#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore

final class PreferenceFileInspectorTests: XCTestCase, @unchecked Sendable {
    private struct Fixture {
        let home: String
        let path: String
        let identifier: String
        let identity: FileIdentity
        init(_ data: Data, identifier: String = "org.example.preferencefixture") throws {
            guard getuid() != 0, let base = ProcessInfo.processInfo.environment["APP_SWEEP_FIXTURES"],
                  base.hasPrefix(NSHomeDirectory() + "/AppSweepAcceptance") else { throw XCTSkip("Explicit non-root isolated fixture root required") }
            self.identifier = identifier
            home = base + "/" + UUID().uuidString
            path = home + "/Library/Preferences/" + identifier + ".plist"
            try FileManager.default.createDirectory(atPath:home + "/Library/Preferences",withIntermediateDirectories:true)
            try FileManager.default.setAttributes([.posixPermissions:0o700],ofItemAtPath:home)
            identity = try SafeDirectory(path:home).ownIdentity
            try data.write(to:URL(fileURLWithPath:path),options:.withoutOverwriting)
            try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:path)
        }
        func inspect() throws -> PreferenceFileInspector.Inspection {
            try PreferenceFileInspector.inspect(path:path,home:home,identifier:identifier)
        }
        func clean() throws {
            let current = try SafeDirectory(path:home).ownIdentity
            guard current.device == identity.device, current.inode == identity.inode, current.owner == getuid() else { throw SweepError.denied("Retain changed preference fixture") }
            try FileManager.default.removeItem(atPath:home)
        }
    }
    func testHealthyXMLBinaryAndOpenStepDictionariesStayHealthyAndUnmodified() throws {
        let values: [String:Any] = ["name":"personal setting","enabled":true]
        let samples = try [PropertyListSerialization.data(fromPropertyList:values,format:.xml,options:0),
                           PropertyListSerialization.data(fromPropertyList:values,format:.binary,options:0),
                           Data("{ name = \"personal setting\"; enabled = YES; }".utf8)]
        for bytes in samples {
            let f = try Fixture(bytes); defer { try? f.clean() }
            let before = try SafeFilesystem.snapshot(f.path)
            let listing = try FileManager.default.contentsOfDirectory(atPath:f.home + "/Library/Preferences")
            let result = try f.inspect()
            XCTAssertEqual(result.status,.dictionary)
            XCTAssertEqual(result.snapshot.identity,before.identity)
            XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:f.path)),bytes)
            XCTAssertEqual(try SafeFilesystem.snapshot(f.path).identity,before.identity)
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath:f.home + "/Library/Preferences"),listing)
            try PreferenceFileInspector.verifyUnchanged(result,home:f.home,identifier:f.identifier)
        }
    }
    func testNonDictionaryMalformedAndEmptyAreDistinctWithoutReadingErrorsAsDamage() throws {
        let scalar = try PropertyListSerialization.data(fromPropertyList:["not a dictionary"],format:.binary,options:0)
        let wrong = try Fixture(scalar); defer { try? wrong.clean() }
        XCTAssertEqual(try wrong.inspect().status,.nonDictionary)
        let broken = try Fixture(Data("<?xml version=\"1.0\"?><plist><dict><key>unfinished".utf8)); defer { try? broken.clean() }
        XCTAssertEqual(try broken.inspect().status,.malformed)
        let empty = try Fixture(Data()); defer { try? empty.clean() }
        let result = try empty.inspect()
        XCTAssertEqual(result.status,.malformed)
        XCTAssertEqual(result.digest,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }
    func testFutureBinaryVersionAndOversizedInputAreUnknown() throws {
        let f = try Fixture(Data("bplist99".utf8) + Data(repeating:0,count:64)); defer { try? f.clean() }
        XCTAssertThrowsError(try f.inspect())
        try Data(repeating:32,count:8*1024*1024 + 1).write(to:URL(fileURLWithPath:f.path))
        XCTAssertThrowsError(try f.inspect())
    }
    func testLinksHardLinksAndSharedWritableACLRemainUnconfirmed() throws {
        let f = try Fixture(Data("broken".utf8)); defer { try? f.clean() }
        let original = f.home + "/original"
        try FileManager.default.moveItem(atPath:f.path,toPath:original)
        try FileManager.default.createSymbolicLink(atPath:f.path,withDestinationPath:original)
        XCTAssertThrowsError(try f.inspect())
        try FileManager.default.removeItem(atPath:f.path)
        try FileManager.default.linkItem(atPath:original,toPath:f.path)
        XCTAssertThrowsError(try f.inspect())
        try FileManager.default.removeItem(atPath:f.path)
        try Data("broken".utf8).write(to:URL(fileURLWithPath:f.path))
        _ = try BoundedProcess.run("/bin/chmod",arguments:["+a","everyone allow write",f.path],timeout:3)
        XCTAssertThrowsError(try f.inspect())
        XCTAssertEqual(try String(contentsOfFile:original,encoding:.utf8),"broken")
    }
    func testChangedOrReplacedFileInvalidatesEarlierInspection() throws {
        let f = try Fixture(Data()); defer { try? f.clean() }
        let before = try f.inspect()
        try Data("new setting".utf8).write(to:URL(fileURLWithPath:f.path))
        XCTAssertThrowsError(try PreferenceFileInspector.verifyUnchanged(before,home:f.home,identifier:f.identifier))
        let changed = try f.inspect()
        try FileManager.default.moveItem(atPath:f.path,toPath:f.home + "/previous")
        try Data("new setting".utf8).write(to:URL(fileURLWithPath:f.path))
        XCTAssertThrowsError(try PreferenceFileInspector.verifyUnchanged(changed,home:f.home,identifier:f.identifier))
    }
    func testProtectedDomainsAndPathAliasesCannotBeInspectedAsAppSettings() throws {
        let f = try Fixture(Data()); defer { try? f.clean() }
        for id in ["com.apple.finder","Com.Apple.Finder","org.appsweep.app",".GlobalPreferences","org..example"] {
            let protected = try Fixture(Data(),identifier:id); defer { try? protected.clean() }
            XCTAssertThrowsError(try protected.inspect())
        }
        XCTAssertThrowsError(try PreferenceFileInspector.inspect(path:f.path + "/../org.example.preferencefixture.plist",home:f.home,identifier:f.identifier))
        XCTAssertThrowsError(try PreferenceFileInspector.inspect(path:f.path,home:f.home + "/..",identifier:f.identifier))
        XCTAssertThrowsError(try PreferenceFileInspector.inspect(path:"/Library/Preferences/" + f.identifier + ".plist",home:f.home,identifier:f.identifier))
    }

    func testPermissionDenialAndAncestorWriteAccessCannotBecomeMalformedResults() throws {
        let f = try Fixture(Data()); defer { try? f.clean() }
        try FileManager.default.setAttributes([.posixPermissions:0],ofItemAtPath:f.path)
        XCTAssertThrowsError(try f.inspect(),"An unreadable empty file is unknown, not confirmed malformed")
        try FileManager.default.setAttributes([.posixPermissions:0o600],ofItemAtPath:f.path)
        let result = try f.inspect()
        let parent = f.home + "/Library/Preferences"
        _ = try BoundedProcess.run("/bin/chmod",arguments:["+a","everyone allow write",parent],timeout:3)
        XCTAssertThrowsError(try f.inspect())
        XCTAssertThrowsError(try PreferenceFileInspector.verifyUnchanged(result,home:f.home,identifier:f.identifier))
        _ = try BoundedProcess.run("/bin/chmod",arguments:["-N",parent],timeout:3)
        try PreferenceFileInspector.verifyUnchanged(result,home:f.home,identifier:f.identifier)
    }
}
#endif
