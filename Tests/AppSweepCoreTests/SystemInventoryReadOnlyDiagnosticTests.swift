#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class SystemInventoryReadOnlyDiagnosticTests: XCTestCase {
    func testFirefoxLogOwnershipReadOnly() throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_FIREFOX_OWNERSHIP_DIAGNOSTIC"] == "1",
              try SystemIdentity.home() == "/Users/localtest",
              try BoundedProcess.run("/usr/sbin/sysctl", arguments: ["-n", "hw.model"], timeout: 3).hasPrefix("VirtualMac") else { throw XCTSkip("Explicit disposable VM read-only diagnostic") }
        let home = "/Users/localtest", path = home + "/Applications/Firefox.app", identifier = "org.mozilla.firefox"
        do { let app = try AppInspector.verifiedDataOwner(path: path, identifier: identifier, home: home); print("FIREFOX_SIGNATURE", app.signed) }
        catch { print("FIREFOX_SIGNATURE_FAILURE", error.localizedDescription) }
        let inventory = try AppInspector.inventory(home: home, selectedApplication: path)
        for item in inventory where item.bundleIdentifier == identifier || item.bundleIdentifier.isEmpty {
            print("FIREFOX_OWNER", item.path, item.bundleIdentifier, item.signed, item.protectedReason ?? "none")
        }
        print("FIREFOX_UNIQUE", AppInspector.uniqueOwner(identifier: identifier, path: path, inventory: inventory))
    }
    func testRegisteredSystemFixtureOwnership() throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_REAL_SUPPORT_ACCEPTANCE"] == "1",
              try SystemIdentity.home() == "/Users/localtest",
              try BoundedProcess.run("/usr/sbin/sysctl", arguments: ["-n", "hw.model"], timeout: 3).hasPrefix("VirtualMac") else { throw XCTSkip("Explicit disposable VM read-only diagnostic") }
        let home = "/Users/localtest"
        let path = "/Applications/DisposableSystemConsumer-AC2D11AA-7EF2-4522-B78F-EF06650C6080.app"
        let app = try AppInspector.inspect(path)
        print("SYSTEM_DIRECT", app.bundleIdentifier, app.signed, app.protectedReason ?? "none")
        let user = try UserOwnershipInventory.collect(home: home)
        let helpers = try UserOwnershipInventory.collect(home: home, includeHelpers: true)
        let encoder = JSONEncoder()
        print("OWNERSHIP_BYTES", try encoder.encode(user).count, "HELPER_BYTES", try encoder.encode(helpers).count, "CHECKS", helpers.helperChecks?.count ?? 0)
        let machine = try AppInspector.inventorySnapshot(home: home, machineOnly: true)
        let combined = try user.combining(machine: machine, applicationsRoot: "/Applications")
        for item in combined.applications where item.bundleIdentifier == app.bundleIdentifier || item.bundleIdentifier.isEmpty {
            print("SYSTEM_OWNER", item.path, item.bundleIdentifier, item.signed, item.protectedReason ?? "none")
        }
        for issue in combined.issues { print("SYSTEM_INVENTORY_ISSUE", issue) }
        print("SYSTEM_UNIQUE", AppInspector.uniqueOwner(identifier: app.bundleIdentifier, path: path, inventory: combined.applications))
    }
}
#endif
