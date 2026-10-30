import XCTest
@testable import AppSweepCore

final class UserOwnershipInventoryTests: XCTestCase {
    private let machine = ApplicationIdentity(path: "/Applications/One.app", name: "One", bundleIdentifier: "org.example.one", signed: true, protectedReason: nil)
    func testUserCopyVetoesUniqueSystemOwnerWithoutBeingAWriteTarget() throws {
        let proof = UserOwnershipInventory(entries: [.init(path: machine.path, identifier: machine.bundleIdentifier, unresolved: false), .init(path: "/Users/test/Applications/One.app", identifier: machine.bundleIdentifier, unresolved: false)], issues: [])
        let merged = try proof.combining(machine: .init(applications: [machine], issues: []), applicationsRoot: "/Applications")
        XCTAssertFalse(AppInspector.uniqueOwner(identifier: machine.bundleIdentifier, path: machine.path, inventory: merged.applications))
        XCTAssertEqual(merged.applications.first, machine)
        XCTAssertFalse(try XCTUnwrap(merged.applications.last).signed)
    }
    func testUserEvidenceCannotInventASystemApplication() throws {
        let proof = UserOwnershipInventory(entries: [.init(path: "/Applications/Invented.app", identifier: "org.example.fake", unresolved: false)], issues: [])
        let merged = try proof.combining(machine: .init(applications: [], issues: []), applicationsRoot: "/Applications")
        XCTAssertTrue(merged.applications.isEmpty)
        XCTAssertFalse(merged.issues.isEmpty)
    }
    func testMissingMachineEntryAndUnknownUserScopeCannotBecomeComplete() throws {
        let proof = UserOwnershipInventory(entries: [], issues: ["user index incomplete"])
        let merged = try proof.combining(machine: .init(applications: [machine], issues: []), applicationsRoot: "/Applications")
        XCTAssertTrue(merged.issues.contains("user index incomplete"))
        XCTAssertGreaterThan(merged.issues.count, 1)
    }
    func testIdenticalRootOwnerIsNotDuplicated() throws {
        let proof = UserOwnershipInventory(entries: [.init(path: machine.path, identifier: machine.bundleIdentifier, unresolved: false)], issues: [])
        let merged = try proof.combining(machine: .init(applications: [machine], issues: []), applicationsRoot: "/Applications")
        XCTAssertEqual(merged.applications.count, 1)
        XCTAssertTrue(merged.issues.isEmpty)
    }
    func testMalformedReadHintsAreRejected() {
        for path in ["relative.app", "/Users/test/../other.app", "/Users/test/app\0"] {
            XCTAssertThrowsError(try UserOwnershipInventory(entries: [.init(path: path, identifier: "org.example.one", unresolved: false)], issues: []).validate())
        }
    }
    func testStoreRejectsMissingExpiredAndClockReversedEvidence() throws {
        let store = UserOwnershipInventoryStore()
        XCTAssertThrowsError(try store.current(uptime: 100))
        let first = UserOwnershipInventory(entries: [], issues: ["first"])
        try store.replace(first, uptime: 100)
        XCTAssertEqual(try store.current(uptime: 220), first)
        XCTAssertThrowsError(try store.current(uptime: 220.01))
        XCTAssertThrowsError(try store.current(uptime: 99))
        let second = UserOwnershipInventory(entries: [], issues: ["second"])
        try store.replace(second, uptime: 221)
        XCTAssertEqual(try store.current(uptime: 221), second)
    }
    func testOwnershipEvidenceRoundTripsThroughBoundedAuthenticatedProtocol() throws {
        let proof = UserOwnershipInventory(entries: [.init(path: machine.path, identifier: machine.bundleIdentifier, unresolved: false)], issues: [])
        let request = PrivilegedRequest(protocolVersion: 1, id: UUID(), nonce: Data(repeating: 1, count: 32), sequence: 1, action: .ownership(proof))
        XCTAssertEqual(try PrivilegedFrame.decode(PrivilegedFrame.encode(request)), request)
        let huge = UserOwnershipInventory(entries: (0..<4097).map { _ in proof.entries[0] }, issues: [])
        XCTAssertThrowsError(try PrivilegedFrame.encode(.init(protocolVersion: 1, id: UUID(), nonce: request.nonce, sequence: 2, action: .ownership(huge))))
    }
    func testCompactHelperProofFitsWireWithoutDroppingOwnershipCoverage() throws {
        let paths = (0..<180).map { "/Users/test/Applications/" + String(repeating: "long-name-", count: 15) + String($0) + ".app" }
        let hash = Data(repeating: 3, count: 20)
        let entries = paths.map { UserOwnershipInventory.Entry(path: $0, identifier: "org.example.owner", unresolved: false) }
        let proof = UserOwnershipInventory(entries: entries, issues: [], helperChecks: [.init(label: "org.example.helper", codeHash: hash, inspectedPaths: paths, exclusive: true)])
        let compact = try proof.compacted()
        let request = PrivilegedRequest(protocolVersion: 1, id: UUID(), nonce: Data(repeating: 1, count: 32), sequence: 1, action: .ownership(compact))
        let decoded = try PrivilegedFrame.decode(PrivilegedFrame.encode(request))
        XCTAssertEqual(decoded, request)
        XCTAssertTrue(compact.provesExclusiveHelper(label: "org.example.helper", codeHash: hash, applicationsRoot: "/Applications"))
        let changed = UserOwnershipInventory(entries: Array(entries.dropLast()), issues: [], helperChecks: compact.helperChecks)
        XCTAssertFalse(changed.provesExclusiveHelper(label: "org.example.helper", codeHash: hash, applicationsRoot: "/Applications"))
        XCTAssertFalse(compact.provesExclusiveHelper(label: "org.example.helper", codeHash: Data([9]), applicationsRoot: "/Applications"))
        let rejected = UserOwnershipInventory(entries: entries, issues: [], helperChecks: [.init(label: "org.example.helper", codeHash: hash, inspectedPaths: paths, exclusive: false)])
        XCTAssertFalse(try rejected.compacted().provesExclusiveHelper(label: "org.example.helper", codeHash: hash, applicationsRoot: "/Applications"))
    }

    func testCompactHelperProofRejectsDuplicateOrMalformedCoverage() throws {
        let entry = UserOwnershipInventory.Entry(path: "/Users/test/Applications/One.app", identifier: "org.example.one", unresolved: false)
        let hash = Data([1, 2, 3])
        let duplicate = UserOwnershipInventory(entries: [entry], issues: [], helperChecks: [.init(label: "org.example.helper", codeHash: hash, inspectedPaths: [entry.path, entry.path], exclusive: true)])
        XCTAssertFalse(try duplicate.compacted().provesExclusiveHelper(label: "org.example.helper", codeHash: hash, applicationsRoot: "/Applications"))
        for digest in ["", "not-a-digest", String(repeating: "g", count: 64)] {
            let malformed = UserOwnershipInventory(entries: [entry], issues: [], helperChecks: [.init(label: "org.example.helper", codeHash: hash, inspectedPaths: [], exclusive: true, inspectedPathsDigest: digest)])
            XCTAssertThrowsError(try malformed.validate())
        }
        let ambiguous = UserOwnershipInventory(entries: [entry], issues: [], helperChecks: [.init(label: "org.example.helper", codeHash: hash, inspectedPaths: [entry.path], exclusive: true, inspectedPathsDigest: String(repeating: "0", count: 64))])
        XCTAssertThrowsError(try ambiguous.validate())
    }

    func testSystemInventoryDoesNotCallUserIndexOrOpenUserHome() throws {
        #if os(macOS)
        let fixture = try RecoveryTests.Fixture(); defer { try? fixture.clean() }
        XCTAssertNil(try AppInspector.fixtureMachineApplicationsRoot(home: SystemIdentity.home()))
        let result = try AppInspector.inventorySnapshot(home: fixture.home + "/nonexistent-unreadable-user-home", indexLookup: { _ in
            XCTFail("System inventory must never query the user's index")
            throw SweepError.denied("User index must not run")
        }, machineOnly: true)
        XCTAssertTrue(result.applications.allSatisfy { SafetyPolicy.contains("/Applications", $0.path) })
        #endif
    }

    func testUnknownUserInstallationCannotDisappearFromSharedOwnershipChecks() throws {
        let proof = UserOwnershipInventory(entries: [.init(path: machine.path, identifier: machine.bundleIdentifier, unresolved: false), .init(path: "/Users/test/Applications/unknown.app", identifier: "", unresolved: true)], issues: [])
        XCTAssertFalse(try proof.combining(machine: .init(applications: [machine], issues: []), applicationsRoot: "/Applications").issues.isEmpty)
    }

    func testHelperProofRequiresExactHashAndEveryUserSideInstallation() {
        var proof = UserOwnershipInventory(entries: [.init(path: "/Users/test/Applications/Other.app", identifier: "org.example.other", unresolved: false)], issues: [])
        let hash = Data(repeating: 2, count: 20)
        XCTAssertFalse(proof.provesExclusiveHelper(label: "org.example.helper", codeHash: hash, applicationsRoot: "/Applications"))
        proof.helperChecks = [.init(label: "org.example.helper", codeHash: hash, inspectedPaths: [], exclusive: true)]
        XCTAssertFalse(proof.provesExclusiveHelper(label: "org.example.helper", codeHash: hash, applicationsRoot: "/Applications"))
        proof.helperChecks = [.init(label: "org.example.helper", codeHash: hash, inspectedPaths: [proof.entries[0].path], exclusive: true)]
        XCTAssertTrue(proof.provesExclusiveHelper(label: "org.example.helper", codeHash: hash, applicationsRoot: "/Applications"))
        XCTAssertFalse(proof.provesExclusiveHelper(label: "org.example.helper", codeHash: Data(repeating: 3, count: 20), applicationsRoot: "/Applications"))
    }

}
