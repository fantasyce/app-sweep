#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore

final class PreferenceDomainServiceTests: XCTestCase, @unchecked Sendable {
    private func plist(_ values: Any, format: PropertyListSerialization.PropertyListFormat = .binary) throws -> Data {
        try PropertyListSerialization.data(fromPropertyList:values,format:format,options:0)
    }
    func testTypedValuesHaveFormatIndependentDigestsAndKeepTypesAndOrder() throws {
        let values: [String:Any] = ["text":"example","bool":true,"int":Int64(7),"real":1.25,"date":Date(timeIntervalSince1970:1_000),"data":Data([1,2,3]),"array":["one","two"],"nested":["value":false]]
        let binary=try PreferenceDomainService.valuesDigest(plist(values)),xml=try PreferenceDomainService.valuesDigest(plist(values,format:.xml))
        XCTAssertEqual(binary,xml);XCTAssertEqual(binary.count,64)
        for (left,right) in [(["v":true] as [String:Any],["v":1]),(["v":1],["v":1.0]),(["v":[1,2]],["v":[2,1]]),(["v":Data([1])],["v":"AQ=="])] {
            XCTAssertNotEqual(try PreferenceDomainService.valuesDigest(plist(left)),try PreferenceDomainService.valuesDigest(plist(right)))
        }
        XCTAssertEqual(try PreferenceDomainService.valuesDigest(Data("{ z = value; a = value; }".utf8)),try PreferenceDomainService.valuesDigest(plist(["a":"value","z":"value"])))
    }
    func testMalformedNonDictionaryDeepAndOversizedValuesAreUnknown() throws {
        for bytes in [Data(),Data("invalid".utf8),try plist(["array"]),Data(repeating:32,count:8*1024*1024+1)] {
            XCTAssertThrowsError(try PreferenceDomainService.valuesDigest(bytes))
        }
        var deep: Any="leaf"
        for _ in 0..<34 { deep=["nested":deep] }
        XCTAssertThrowsError(try PreferenceDomainService.valuesDigest(plist(deep)))
        XCTAssertThrowsError(try PreferenceDomainService.valuesDigest(plist(["many":Array(repeating:0,count:50_001)])))
    }
    func testProtectedOrAmbiguousDomainsAndForeignHomesAreRefusedBeforeServiceAccess() throws {
        let home=try SystemIdentity.home()
        for identifier in ["com.apple.finder","Com.Apple.finder","org.appsweep.app",".GlobalPreferences","NSGlobalDomain","-g","/tmp/preferences","org..example","org.example.","org.example\0bad"] {
            XCTAssertThrowsError(try PreferenceDomainService.inspect(path:home + "/Library/Preferences/" + identifier + ".plist",home:home,identifier:identifier))
        }
        XCTAssertThrowsError(try PreferenceDomainService.inspect(path:home + "/Library/Preferences/org.example.preferencefixture.plist",home:home + "/foreign",identifier:"org.example.preferencefixture"))
    }
    func testNativeServiceClearsActualValuesRestoresAndPreservesNewSettingsOnConflict() throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_PREFERENCE_SERVICE_ACCEPTANCE"] == "AppSweep-General-20261016",
              getuid()==501, geteuid()==501, try SystemIdentity.home()=="/Users/localtest",
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).hasPrefix("VirtualMac") else {
            throw XCTSkip("Explicit disposable VM current-home service acceptance only")
        }
        let f=try NativeDomainFixture()
        try f.set("original-owned-value")
        let original=try PreferenceDomainService.inspect(path:f.path,home:f.home,identifier:f.identifier)
        try PreferenceDomainService.verify(original)
        let backup=f.root.path + "/original.plist"
        try f.root.write(original.bytes,name:"original.plist")
        let empty=try PreferenceDomainService.clear(original)
        XCTAssertEqual(try f.read().status,6,"Fresh native consumer must see no value")
        XCTAssertEqual(empty.valuesDigest,try PreferenceDomainService.valuesDigest(plist([String:String]())))
        XCTAssertThrowsError(try PreferenceDomainService.clear(original),"A consumed original file state must not clear twice")
        try f.set("new-owned-value")
        XCTAssertThrowsError(try PreferenceDomainService.restore(original:original,expectedEmpty:empty,backupPath:backup))
        XCTAssertEqual(try f.read().text.trimmingCharacters(in:.whitespacesAndNewlines),"new-owned-value")
        let changed=try PreferenceDomainService.inspect(path:f.path,home:f.home,identifier:f.identifier)
        let emptyAgain=try PreferenceDomainService.clear(changed)
        try f.root.write(Data("tampered".utf8),name:"original.plist")
        XCTAssertThrowsError(try PreferenceDomainService.restore(original:original,expectedEmpty:emptyAgain,backupPath:backup))
        XCTAssertEqual(try f.read().status,6)
        try f.root.write(original.bytes,name:"original.plist")
        let restored=try PreferenceDomainService.restore(original:original,expectedEmpty:emptyAgain,backupPath:backup)
        XCTAssertEqual(restored.valuesDigest,original.valuesDigest)
        XCTAssertEqual(try f.read().text.trimmingCharacters(in:.whitespacesAndNewlines),"original-owned-value")
        try f.finish()
    }
    func testNativeFractionalDateSurvivesInspectionClearAndRestoreWithoutRounding() throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_PREFERENCE_SERVICE_ACCEPTANCE"] == "AppSweep-General-20261016",
              getuid()==501,try SystemIdentity.home()=="/Users/localtest",try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).hasPrefix("VirtualMac") else { throw XCTSkip("Explicit disposable native preference VM only") }
        let f=try NativeDomainFixture()
        let payload=try plist(["acceptance-consumer":"original-owned-value","acceptance-date":Date(timeIntervalSinceReferenceDate:1234.125)] as [String:Any])
        try f.root.write(payload,name:"date-seed.plist")
        let seed=try BoundedProcess.capture("/usr/bin/defaults",arguments:["import",f.identifier,f.root.path + "/date-seed.plist"],timeout:10,mergeStderr:false)
        XCTAssertEqual(seed.status,0)
        func dateValue() throws -> CapturedProcess { try BoundedProcess.capture(f.executable,arguments:["--read-date",f.identifier],timeout:3,mergeStderr:false) }
        XCTAssertEqual(Double(try dateValue().text.trimmingCharacters(in:.whitespacesAndNewlines)),1234.125)
        let original=try PreferenceDomainService.inspect(path:f.path,home:f.home,identifier:f.identifier)
        try f.root.write(original.bytes,name:"date-original.plist")
        let empty=try PreferenceDomainService.clear(original)
        XCTAssertEqual(try dateValue().status,6)
        _ = try PreferenceDomainService.restore(original:original,expectedEmpty:empty,backupPath:f.root.path + "/date-original.plist")
        XCTAssertEqual(Double(try dateValue().text.trimmingCharacters(in:.whitespacesAndNewlines)),1234.125,"A fractional native Date must not be rounded through XML export")
        try f.finish()
    }
    func testNativeMetadataOnlyChangeKeepsExactValuesButNewContentInvalidatesState() throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_PREFERENCE_SERVICE_ACCEPTANCE"] == "AppSweep-General-20261016",
              getuid()==501,try SystemIdentity.home()=="/Users/localtest",try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).hasPrefix("VirtualMac") else { throw XCTSkip("Explicit disposable native preference VM only") }
        let f=try NativeDomainFixture()
        func seed(_ value: String) throws {
            let result=try BoundedProcess.capture("/usr/bin/defaults",arguments:["write",f.identifier,"acceptance-consumer","-string",value],timeout:10,mergeStderr:false)
            guard result.status==0 else { throw SweepError.incomplete("Owned metadata regression seed failed") }
        }
        try seed("original-owned-value")
        let original=try PreferenceDomainService.inspect(path:f.path,home:f.home,identifier:f.identifier)
        _ = try BoundedProcess.run("/usr/bin/xattr",arguments:["-w","org.example.acceptance-metadata","owned-test",f.path],timeout:3)
        let current=try SafeFilesystem.snapshot(f.path)
        XCTAssertNotEqual(current.identity,original.inspection.snapshot.identity)
        XCTAssertTrue(current.identity.sameObject(as:original.inspection.snapshot.identity))
        try PreferenceDomainService.verify(original)
        try seed("new-owned-value")
        XCTAssertThrowsError(try PreferenceDomainService.verify(original))
        XCTAssertThrowsError(try PreferenceDomainService.clear(original))
        XCTAssertEqual(try f.read().text.trimmingCharacters(in:.whitespacesAndNewlines),"new-owned-value")
        try seed("original-owned-value")
        try f.finish()
    }
    struct NativeDomainFixture {
        let root: SafeDirectory,home: String,identifier: String,path: String,executable: String
        init() throws {
            home=try SystemIdentity.home()
            guard let base=ProcessInfo.processInfo.environment["APP_SWEEP_FIXTURES"],base.hasPrefix(home + "/AppSweepAcceptance"),
                  let sdk=ProcessInfo.processInfo.environment["APP_SWEEP_SDK"],let clang=ProcessInfo.processInfo.environment["APP_SWEEP_CLANG"] else { throw SweepError.denied("Owned native service fixture environment missing") }
            let token=UUID().uuidString;identifier="org.example.nativefixture." + token.lowercased()
            path=home + "/Library/Preferences/" + identifier + ".plist"
            guard try !SafeFilesystem.presence(path) else { throw SweepError.denied("Unique native preference domain already exists") }
            root=try SafeDirectory(path:base).privateChild(token)
            let identity=try root.ownIdentity
            try root.write(JSONSerialization.data(withJSONObject:["root":root.path,"inode":identity.inode,"device":identity.device,"owner":identity.owner,"domain":identifier,"preferencePath":path,"preExisting":false,"state":"intent before native API seed; retain on failure"],options:[.sortedKeys]),name:"ownership.json")
            let app=try root.privateChild("Preference Witness.app"),contents=try app.privateChild("Contents"),code=try contents.privateChild("MacOS")
            executable=code.path + "/witness"
            try contents.write(PropertyListSerialization.data(fromPropertyList:["CFBundleIdentifier":identifier,"CFBundleExecutable":"witness","CFBundlePackageType":"APPL","CFBundleName":"Preference Witness"],format:.xml,options:0),name:"Info.plist")
            let source=try NativeAcceptanceTests.NativeFixture.resource("PreferencesConsumer",extension:"c")
            let built=try BoundedProcess.capture(clang,arguments:["-isysroot",sdk,"-mmacosx-version-min=12.0","-framework","CoreFoundation",source.path,"-o",executable],timeout:30,mergeStderr:true)
            guard built.status==0 else { throw SweepError.incomplete("Owned preference consumer build failed") }
            let signed=try BoundedProcess.capture("/usr/bin/codesign",arguments:["--force","--sign","-",app.path],timeout:10,mergeStderr:true)
            guard signed.status==0 else { throw SweepError.incomplete("Owned preference consumer signing failed") }
            print("NATIVE_PREFERENCE_FIXTURE root=\(root.path) inode=\(identity.inode) domain=\(identifier) createdFromAbsent=true")
        }
        func set(_ value: String) throws {
            let p=try BoundedProcess.capture(executable,arguments:["--set-pref",identifier,value],timeout:10,mergeStderr:true)
            guard p.status==0 else { throw SweepError.incomplete("Owned preference seed failed") }
            // This is fixture preparation, not the product's 10-second write
            // convergence budget. CFPreferences may delay a consumer's flush.
            let started=ProcessInfo.processInfo.systemUptime,deadline=started+30
            while true {
                if let bytes=try? SafeFilesystem.readMetadata(path),let values=(try? PropertyListSerialization.propertyList(from:bytes,format:nil)) as? [String:String],values==["acceptance-consumer":value] { break }
                guard ProcessInfo.processInfo.systemUptime<deadline else { throw SweepError.incomplete("Native preference fixture did not settle before product invocation") }
                Thread.sleep(forTimeInterval:0.1)
            }
            print("NATIVE_PREFERENCE_SEED settledSeconds=\(ProcessInfo.processInfo.systemUptime-started)")
        }
        func read() throws -> CapturedProcess {
            try BoundedProcess.capture(executable,arguments:["--read-pref",identifier],timeout:10,mergeStderr:false)
        }
        func finish() throws {
            let value=try read();guard value.status==0 && value.text.trimmingCharacters(in:.whitespacesAndNewlines)=="original-owned-value" else { throw SweepError.stale("Keep changed native fixture") }
            let clear=try BoundedProcess.capture(executable,arguments:["--clear-pref",identifier],timeout:10,mergeStderr:true)
            guard clear.status==0,try read().status==6 else { throw SweepError.incomplete("Owned native fixture key retained") }
            try root.write(Data("Native service clear/restore verified; own sentinel cleared; private fixture and possible empty domain retained under ownership receipt for exact cleanup.".utf8),name:"completed.txt")
        }
    }
}
#endif
