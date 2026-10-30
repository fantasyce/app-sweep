#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore

final class ApplicationLanguagePreparationTests: XCTestCase, @unchecked Sendable {
    private func fixture(signResources: Bool = true) throws -> NativeAcceptanceTests.NativeFixture {
        let f = try NativeAcceptanceTests.NativeFixture()
        do {
            let path = f.app + "/Contents/Info.plist"
            var info = try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:path)),format:nil) as? [String:Any])
            info["CFBundleDevelopmentRegion"] = "de"
            try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:path))
            for language in ["Base","de","en","en-GB","zh-Hans","zh-Hant","zh_CN","fr","es","zz-unknown"] {
                let directory = f.app + "/Contents/Resources/" + language + ".lproj"
                try FileManager.default.createDirectory(atPath:directory,withIntermediateDirectories:true)
                try Data("\"message\" = \"\(language)\";\n".utf8).write(to:URL(fileURLWithPath:directory + "/Localizable.strings"))
            }
            let nested = f.app + "/Contents/Resources/Examples/fr.lproj"
            try FileManager.default.createDirectory(atPath:nested,withIntermediateDirectories:true)
            try Data("ordinary sample data".utf8).write(to:URL(fileURLWithPath:nested + "/sample.txt"))
            if signResources { try sign(f) }
            return f
        } catch { try? f.clean(); throw error }
    }
    private func sign(_ f: NativeAcceptanceTests.NativeFixture) throws {
        let result = try BoundedProcess.capture("/usr/bin/codesign",arguments:["--force","--sign","-",f.app],timeout:10,mergeStderr:true)
        XCTAssertEqual(result.status,0,result.text)
        guard result.status == 0 else { throw SweepError.incomplete("Owned language fixture signing failed") }
    }
    private func snapshot(_ f: NativeAcceptanceTests.NativeFixture) throws -> FileSnapshot {
        try SafeFilesystem.snapshot(f.app,allowInternalLinks:true,purpose:.application,allowInternalHardLinks:true)
    }
    private func parent(_ f: NativeAcceptanceTests.NativeFixture, name: String) throws -> SafeDirectory {
        let parent = try SafeDirectory(path:f.home).privateChild("language-preparation")
        try parent.write(Data(name.utf8),name:"preparation-intent.txt")
        return parent
    }
    func testPreferredFamiliesBaseDevelopmentAndEnglishRemainWhileOptionalLanguageIsPrepared() throws {
        let f = try fixture(); defer { try? f.clean() }
        let source = try snapshot(f), plan = try ApplicationLanguagePreparation.analyze(source,retaining:["zh-Hans-CN","fr"])
        XCTAssertEqual(Set(plan.omitted.map(\.relative)),["Contents/Resources/es.lproj","Contents/Resources/es.lproj/Localizable.strings"])
        XCTAssertTrue(plan.retained.contains { $0.contains("zz-unknown.lproj") })
        let token = UUID().uuidString, destination = try parent(f,name:token)
        let result = try ApplicationLanguagePreparation.prepare(plan,in:destination,name:token)
        XCTAssertGreaterThan(result.savedBytes,0)
        XCTAssertEqual(result.snapshot.bytes,source.bytes-result.savedBytes)
        XCTAssertEqual(Set(result.snapshot.tree.map(\.relative)),Set(source.tree.map(\.relative)).subtracting(plan.omitted.map(\.relative)))
        let signed = try BoundedProcess.capture("/usr/bin/codesign",arguments:["--verify","--deep","--strict","--all-architectures",result.snapshot.path],timeout:15,mergeStderr:true)
        XCTAssertEqual(signed.status,0,signed.text)
        XCTAssertNoThrow(try SafeFilesystem.verify(source))
        let generated = try BoundedProcess.capture(result.snapshot.path + "/Contents/MacOS/fixture",arguments:["--generate",f.home],timeout:10,mergeStderr:true)
        XCTAssertEqual(generated.status,0,generated.text)
        XCTAssertNoThrow(try SafeFilesystem.verify(source))
    }
    func testEmptyOrUnknownPreferredLanguagesCannotCreateAPlan() throws {
        let f = try fixture(); defer { try? f.clean() }; let source = try snapshot(f)
        for value in [[],[""],["zz-ZZ"],["../en"],["en\0fr"],["en-!"],[String(repeating:"a",count:100)]] {
            XCTAssertThrowsError(try ApplicationLanguagePreparation.analyze(source,retaining:value))
        }
        XCTAssertNoThrow(try SafeFilesystem.verify(source))
    }
    func testNativeCrossCodeFallbacksRetainTheirWholeLanguageFamily() throws {
        let f=try fixture();defer { try? f.clean() }
        let pairs=[("nb-NO","no"),("no","nb"),("nn-NO","no"),("he","iw"),("id","in"),("yi","ji"),("jv","jw")]
        for language in Set(pairs.map(\.1)).union(["no-NO"]) {
            let path=f.app + "/Contents/Resources/" + language + ".lproj"
            try FileManager.default.createDirectory(atPath:path,withIntermediateDirectories:true)
            try Data("\"message\" = \"\(language)\";\n".utf8).write(to:URL(fileURLWithPath:path + "/Localizable.strings"))
        }
        try sign(f);let source=try snapshot(f)
        for (preferred,fallback) in pairs {
            XCTAssertTrue(Bundle.preferredLocalizations(from:["en",fallback,"de"],forPreferences:[preferred,"en"]).contains(fallback),"Native witness for \(preferred)/\(fallback)")
            let plan=try ApplicationLanguagePreparation.analyze(source,retaining:[preferred])
            XCTAssertFalse(plan.omitted.contains { $0.relative.hasPrefix("Contents/Resources/" + fallback + ".lproj") },"Native fallback \(fallback) required by \(preferred)")
            if fallback == "no" {
                XCTAssertFalse(plan.omitted.contains { $0.relative.hasPrefix("Contents/Resources/no-NO.lproj") },"Retain all regions in a native fallback family")
            }
        }
        XCTAssertNoThrow(try SafeFilesystem.verify(source))
    }
    func testExecutableAndLinkedLanguageGroupsAreRetainedAsAWhole() throws {
        let f = try fixture(); defer { try? f.clean() }
        let resource = f.app + "/Contents/Resources"
        XCTAssertEqual(chmod(resource + "/es.lproj/Localizable.strings",0o755),0)
        try FileManager.default.createSymbolicLink(atPath:resource + "/fr.lproj/alias",withDestinationPath:"../en.lproj/Localizable.strings")
        try sign(f)
        let source = try snapshot(f), plan = try ApplicationLanguagePreparation.analyze(source,retaining:["en"])
        XCTAssertFalse(plan.omitted.contains { $0.relative.hasPrefix("Contents/Resources/es.lproj") || $0.relative.hasPrefix("Contents/Resources/fr.lproj") })
        XCTAssertTrue(plan.retained.contains { $0.contains("es.lproj") });XCTAssertTrue(plan.retained.contains { $0.contains("fr.lproj") })
    }
    func testChangedOriginalRejectsPreparationBeforeDestinationCreation() throws {
        let f = try fixture(); defer { try? f.clean() }
        let source = try snapshot(f), plan = try ApplicationLanguagePreparation.analyze(source,retaining:["en"])
        try Data("new original data".utf8).write(to:URL(fileURLWithPath:f.app + "/Contents/Resources/es.lproj/Localizable.strings"))
        let token = UUID().uuidString,destination = try parent(f,name:token)
        XCTAssertThrowsError(try ApplicationLanguagePreparation.prepare(plan,in:destination,name:token))
        XCTAssertThrowsError(try destination.identity(token))
        XCTAssertEqual(try String(contentsOfFile:f.app + "/Contents/Resources/es.lproj/Localizable.strings",encoding:.utf8),"new original data")
    }
    func testInvalidOriginalSignatureCannotAuthorizeAnyOmission() throws {
        let f = try fixture(); defer { try? f.clean() }
        try Data("tampered".utf8).write(to:URL(fileURLWithPath:f.app + "/Contents/Resources/en.lproj/Localizable.strings"))
        XCTAssertThrowsError(try ApplicationLanguagePreparation.analyze(snapshot(f),retaining:["en"]))
    }
    func testAliasedNodesReferencesAndCodeBytesRetainWholeLanguageGroups() throws {
        let f = try fixture(signResources:false); defer { try? f.clean() }
        let resources=f.app + "/Contents/Resources"
        // Construct aliases in a private fixture staging directory before
        // installing it as bundle resources, like the existing copier tests.
        let staged=try SafeDirectory(path:f.home).privateChild("alias-language")
        try staged.write(Data("\"message\" = \"it\";\n".utf8),name:"Localizable.strings")
        let linked=linkat(staged.fd,"Localizable.strings",staged.fd,"shared-language",0)
        XCTAssertEqual(linked,0,"Owned fixture linkat errno=\(errno)")
        guard linked == 0 else { throw SweepError.incomplete("Could not create owned alias fixture") }
        try FileManager.default.moveItem(atPath:staged.path,toPath:resources + "/it.lproj")
        try FileManager.default.createSymbolicLink(atPath:resources + "/Examples/selected-language",withDestinationPath:"../fr.lproj/Localizable.strings")
        try Data([0xcf,0xfa,0xed,0xfe,0,0,0,0]).write(to:URL(fileURLWithPath:resources + "/zh-Hant.lproj/Localizable.strings"))
        try sign(f)
        let source=try snapshot(f),plan=try ApplicationLanguagePreparation.analyze(source,retaining:["en"])
        for group in ["it.lproj","fr.lproj","zh-Hant.lproj"] {
            XCTAssertFalse(plan.omitted.contains { $0.relative.hasPrefix("Contents/Resources/" + group) })
            XCTAssertTrue(plan.retained.contains { $0.contains(group) })
        }
        let token=UUID().uuidString,destination=try parent(f,name:token)
        let result=try ApplicationLanguagePreparation.prepare(plan,in:destination,name:token)
        let copiedLink=try XCTUnwrap(result.snapshot.tree.first { $0.relative == "Contents/Resources/it.lproj/Localizable.strings" })
        XCTAssertEqual(copiedLink.identity.links,2)
        XCTAssertNoThrow(try SafeFilesystem.verify(source))
    }
    func testCaseVariantLinkReferencesRetainTheirLanguageGroup() throws {
        let f=try fixture();defer { try? f.clean() }
        try FileManager.default.createSymbolicLink(atPath:f.app + "/Contents/Resources/Examples/reference",withDestinationPath:"../FR.lproj/Localizable.strings")
        try sign(f)
        let plan=try ApplicationLanguagePreparation.analyze(snapshot(f),retaining:["en"])
        XCTAssertFalse(plan.omitted.contains { $0.relative.hasPrefix("Contents/Resources/fr.lproj") },"Case-insensitive filesystem aliases must not become dangling after preparation")
    }
    func testTypedProofCannotBeAppliedToAnotherSource() throws {
        let a=try fixture();defer { try? a.clean() }
        let b=try fixture();defer { try? b.clean() }
        let plan=try ApplicationLanguagePreparation.analyze(snapshot(a),retaining:["en"])
        let token=UUID().uuidString,destination=try parent(b,name:token)
        XCTAssertThrowsError(try ApplicationTreeCopy.prepare(snapshot(b),in:destination,name:token,languagePlan:plan))
        XCTAssertThrowsError(try destination.identity(token))
    }
    func testRegisteredRealConsumersPrepareWithoutPublishingOrResigning() throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_LANGUAGE_PREPARATION_ACCEPTANCE"] == "AppSweep-General-20261016" else {
            throw XCTSkip("Requires explicitly registered disposable-VM real consumers; preparation only")
        }
        guard getuid() == 501, try SystemIdentity.home() == "/Users/localtest",
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).hasPrefix("VirtualMac") else {
            throw SweepError.denied("Wrong real language preparation environment")
        }
        for (name,identifier,team,hash,inode) in [
            ("IINA","com.colliderli.iina","67CQ77V27R","8778dd7b22d0ae53aaea4cd590b82f9831fad70f",UInt64(1143080)),
            ("Vienna","uk.co.opencommunity.vienna2","KUU2LM7U9K","c41a91c5c346817292b71a946b037e7d4e2cc84e",UInt64(279051))
        ] {
            let path="/Users/localtest/Applications/" + name + ".app"
            let source=try SafeFilesystem.snapshot(path,allowInternalLinks:true,purpose:.application,allowInternalHardLinks:true)
            guard source.identity.owner == 501, source.identity.inode == inode,
                  AppInspector.signedByTeam(path:path,team:team),
                  try ApplicationArchitecturePreparation.signature(path,identifier:identifier,architecture:"arm64") == hash else {
                throw SweepError.denied("Registered consumer identity changed")
            }
            let f=try NativeAcceptanceTests.NativeFixture();defer { try? f.clean() }
            let plan=try ApplicationLanguagePreparation.analyze(source,retaining:["en","zh-Hans-CN"])
            XCTAssertFalse(plan.omitted.contains { $0.relative.hasPrefix("Contents/Resources/Base.lproj") || $0.relative.hasPrefix("Contents/Resources/en.lproj") || $0.relative.hasPrefix("Contents/Resources/zh") })
            let token=UUID().uuidString,destination=try parent(f,name:token)
            let result: ApplicationLanguagePreparation.Result
            do { result=try ApplicationLanguagePreparation.prepare(plan,in:destination,name:token) }
            catch {
                print("LANGUAGE_PREPARATION_FAILURE consumer=\(name) omittedNodes=\(plan.omitted.count) error=\(error)")
                if let current=try? SafeFilesystem.snapshot(path,allowInternalLinks:true,purpose:.application,allowInternalHardLinks:true) {
                    print("LANGUAGE_SOURCE_ROOT_UNCHANGED=\(current.identity == source.identity) TREE_UNCHANGED=\(current.tree == source.tree)")
                    let prior=Dictionary(uniqueKeysWithValues:source.tree.map { ($0.relative,$0.identity) })
                    for entry in current.tree where prior[entry.relative] != entry.identity { print("LANGUAGE_CHANGED_SOURCE_NODE=\(entry.relative)") }
                } else { print("LANGUAGE_SOURCE_RECHECK_UNCONFIRMED") }
                throw error
            }
            XCTAssertGreaterThan(result.savedBytes,0)
            XCTAssertEqual(try ApplicationArchitecturePreparation.signature(result.snapshot.path,identifier:identifier,architecture:"arm64"),hash)
            XCTAssertNoThrow(try SafeFilesystem.verify(source))
            print("LANGUAGE_PREPARATION_ONLY consumer=\(name) omittedNodes=\(plan.omitted.count) savedBytes=\(result.savedBytes) originalInode=\(inode) noPublication=true noConsumerLaunch=true temporaryFixture=\(f.home)")
        }
    }
}
#endif
