#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore

/// Reproduces the physical /private/tmp namespace used by macOS Installer.
/// It never installs a service and never runs on the host or old Intel Mac.
final class InstallerPhysicalPathTests: XCTestCase {
    func testPhysicalInstallerMetadataPathRemainsReadableWhileCleanupStaysDenied() throws {
        guard getuid() == 501, NSHomeDirectory() == "/Users/localtest",
              ProcessInfo.processInfo.environment["APP_SWEEP_FIXTURES"]?.hasPrefix("/Users/localtest/AppSweepAcceptanceGeneral-20261016/") == true,
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).hasPrefix("VirtualMac") else { throw XCTSkip("Disposable VM physical Installer path only") }
        let task = "/Users/localtest/AppSweepAcceptanceGeneral-20261016"
        let id = UUID().uuidString, path = "/private/tmp/AppSweepAcceptancePath-" + id
        let receipt = try SafeDirectory(path:task).privateChild("installer-path-probes.noindex").privateChild(id)
        guard !FileManager.default.fileExists(atPath:path) else { throw SweepError.denied("Physical path fixture already exists") }
        try receipt.write(JSONSerialization.data(withJSONObject:["createdFromAbsent":true,"path":path,"state":"before mkdir; test only"]),name:"ownership.json")
        guard mkdir(path,0o700) == 0 else { throw SweepError.filesystem("Cannot exclusively create physical path fixture") }
        let identity = try SafeDirectory(path:path).ownIdentity
        try receipt.write(JSONSerialization.data(withJSONObject:["createdFromAbsent":true,"path":path,"device":identity.device,"inode":identity.inode,"owner":identity.owner,"state":"created; retain if teardown fails"]),name:"ownership.json")
        defer {
            do {
                let current = try SafeDirectory(path:path).ownIdentity
                guard current.device == identity.device, current.inode == identity.inode, current.owner == getuid() else { throw SweepError.stale("Retain changed Installer path fixture") }
                try FileManager.default.removeItem(atPath:path)
                try receipt.write(JSONSerialization.data(withJSONObject:["path":path,"device":identity.device,"inode":identity.inode,"state":"verified exact task fixture removed"]),name:"ownership.json")
            } catch { print("Physical Installer fixture retained with receipt: " + receipt.path) }
        }
        let file = path + "/payload", bytes = Data("independent package metadata".utf8)
        try bytes.write(to:URL(fileURLWithPath:file),options:.withoutOverwriting)
        XCTAssertNoThrow(try SafeFilesystem.snapshot(file),"A physical Installer staging path is not a lexical path alias")
        XCTAssertEqual(try SafeFilesystem.readMetadata(file),bytes)
        let policy = SafetyPolicy(home:"/Users/localtest",acceptedPlatform:true)
        XCTAssertNotNil(policy.lexicalDenial(file),"A readable Installer source must never become an ordinary cleanup target")
        for alias in [path + "/./payload",path + "/../" + URL(fileURLWithPath:path).lastPathComponent + "/payload",file + "/",file + "\0",path + "//payload"] {
            XCTAssertThrowsError(try SafeFilesystem.snapshot(alias))
            XCTAssertThrowsError(try SafeFilesystem.readMetadata(alias))
        }
        try FileManager.default.createSymbolicLink(atPath:path + "/alias",withDestinationPath:path)
        XCTAssertThrowsError(try SafeFilesystem.snapshot(path + "/alias/payload"))
        XCTAssertThrowsError(try SafeFilesystem.readMetadata(path + "/alias/payload"))
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:file)),bytes)
        print("Physical Installer path probe receipt: " + receipt.path)
    }
}
#endif
