#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore

/// Root-mode CI only in this disposable VM. No real cache/log/app is selected.
final class PrivilegedNativeAcceptanceTests: XCTestCase {
    private func rootTask() throws -> SafeDirectory {
        guard geteuid() == 0, ProcessInfo.processInfo.environment["APP_SWEEP_PRIVILEGED_ACCEPTANCE"] == "1",
              try BoundedProcess.run("/usr/sbin/sysctl", arguments: ["-n", "hw.model"], timeout: 3).hasPrefix("VirtualMac") else { throw XCTSkip("Explicit disposable VM root acceptance required") }
        let task = try SafeDirectory(path: "/Users/localtest/AppSweepAcceptanceGeneral-20261016")
        guard try task.ownIdentity.owner == 501 else { throw SweepError.denied("Unexpected VM task owner") }
        return try task.privateChild("root-fixtures.noindex")
    }
    func testActualRootOwnedConfigurationLoadAndTamperRefusal() throws {
        let fixtures = try rootTask(), operation = try fixtures.privateChild(UUID().uuidString)
        let basePath = "/Library/Application Support/App Sweep", configPath = RootServiceConfiguration.path
        guard try !SafeFilesystem.presence(basePath) else { throw SweepError.denied("Existing global App Sweep directory retained; root fixture will not overwrite it") }
        let receipt: [String:String] = ["createdFromAbsent":"true", "path":basePath, "purpose":"temporary root-owned config acceptance; remove only verified own tree"]
        try operation.write(JSONSerialization.data(withJSONObject: receipt, options:[.sortedKeys]), name:"ownership.json")
        guard mkdir(basePath, 0o755) == 0 else { throw SweepError.denied("Temporary root base appeared; no overwrite") }
        let createdBase = try SafeDirectory(path:basePath).ownIdentity
        defer {
            do {
                let current = try SafeDirectory(path:basePath).ownIdentity
                guard current.device == createdBase.device, current.inode == createdBase.inode, current.owner == 0 else { throw SweepError.denied("Temporary root base identity changed; retained") }
                try FileManager.default.setAttributes([.posixPermissions:0o755], ofItemAtPath:basePath)
                let snapshot = try SafeFilesystem.snapshot(basePath)
                let known: Set<String> = ["Service", "Service/config.json"]
                guard Set(snapshot.tree.map(\.relative)) == known, snapshot.identity.owner == 0, snapshot.tree.allSatisfy({$0.identity.owner == 0}) else { throw SweepError.denied("Unexpected object in temporary root config tree; retained") }
                let parent = try SafeDirectory(path:"/Library/Application Support")
                guard SafeFilesystem.removeVerified(in:parent,name:"App Sweep",identity:snapshot.identity,contents:snapshot.tree) else { throw SweepError.filesystem("Root fixture cleanup stopped; retained") }
            } catch { XCTFail("Own root-config fixture retained for manual review: " + error.localizedDescription) }
        }
        guard mkdir(basePath + "/Service", 0o755) == 0 else { throw SweepError.denied("Temporary root service directory appeared; no overwrite") }
        let pins = RootServicePins(schemaVersion:1,serviceBuild:"root-acceptance-1",clientCodeHashes:[String(repeating:"a",count:40)],serviceCodeHashes:[String(repeating:"b",count:40)])
        try pins.encode().write(to:URL(fileURLWithPath:configPath),options:.atomic)
        try FileManager.default.setAttributes([.posixPermissions:0o644],ofItemAtPath:configPath)
        let loaded = try RootServiceConfiguration.load()
        XCTAssertEqual(loaded.pins,pins);try loaded.verifyUnchanged()
        try FileManager.default.setAttributes([.posixPermissions:0o777],ofItemAtPath:basePath)
        XCTAssertThrowsError(try RootServiceConfiguration.load())
        try FileManager.default.setAttributes([.posixPermissions:0o755],ofItemAtPath:basePath)
        let changed = RootServicePins(schemaVersion:1,serviceBuild:"root-acceptance-2",clientCodeHashes:pins.clientCodeHashes,serviceCodeHashes:pins.serviceCodeHashes)
        try changed.encode().write(to:URL(fileURLWithPath:configPath),options:.atomic)
        try FileManager.default.setAttributes([.posixPermissions:0o644],ofItemAtPath:configPath)
        XCTAssertThrowsError(try loaded.verifyUnchanged())
        XCTAssertEqual(try RootServiceConfiguration.load().pins,changed)
        print("Actual root config load/unsafe-parent/stale-file checks passed; own temporary root path removed at scope exit; receipt=" + operation.path + "/ownership.json")
    }
    func testRootOwnedObjectsMoveAndRestoreWithoutFollowingEscapeLinks() throws {
        let fixtures = try rootTask(), operation = try fixtures.privateChild(UUID().uuidString)
        let source = try operation.privateChild("source"), vault = try operation.privateChild("recovery")
        try source.write(Data("root-owned disposable fixture".utf8),name:"payload")
        let snapshot = try SafeFilesystem.snapshot(source.path + "/payload")
        XCTAssertEqual(snapshot.identity.owner,0)
        try SafeFilesystem.move(snapshot,into:vault,name:"payload")
        let isolated = try SafeFilesystem.snapshot(vault.path + "/payload")
        XCTAssertTrue(isolated.identity.sameObject(as:snapshot.identity))
        try SafeFilesystem.move(isolated,into:source,name:"payload")
        XCTAssertEqual(try SafeFilesystem.readMetadata(source.path + "/payload"),Data("root-owned disposable fixture".utf8))
        let escaping = source.path + "/escape"
        try FileManager.default.createSymbolicLink(atPath:escaping,withDestinationPath:"/private/var")
        XCTAssertThrowsError(try SafeFilesystem.snapshot(source.path))
        print("Root-owned fixture move/restore and escape refusal passed; only registered task fixture retained: " + operation.path)
    }
}
#endif
