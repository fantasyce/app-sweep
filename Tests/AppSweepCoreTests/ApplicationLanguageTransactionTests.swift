#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore

final class ApplicationLanguageTransactionTests: XCTestCase, @unchecked Sendable {
    private func fixture() throws -> NativeAcceptanceTests.NativeFixture {
        let f = try NativeAcceptanceTests.NativeFixture()
        do {
            let infoPath = f.app + "/Contents/Info.plist"
            var info = try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:infoPath)),format:nil) as? [String:Any])
            info["CFBundleDevelopmentRegion"] = "de"
            try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:infoPath))
            for language in ["Base","de","en","zh-Hans","fr"] {
                let directory = f.app + "/Contents/Resources/" + language + ".lproj"
                try FileManager.default.createDirectory(atPath:directory,withIntermediateDirectories:true)
                try Data("\"message\" = \"\(language)\";\n".utf8).write(to:URL(fileURLWithPath:directory + "/Localizable.strings"))
            }
            let signed = try BoundedProcess.capture("/usr/bin/codesign",arguments:["--force","--sign","-",f.app],timeout:10,mergeStderr:true)
            guard signed.status == 0 else { throw SweepError.incomplete(signed.text) }
            return f
        } catch { try? f.clean(); throw error }
    }
    private func snapshot(_ path: String) throws -> FileSnapshot {
        try SafeFilesystem.snapshot(path,allowInternalLinks:true,purpose:.application,allowInternalHardLinks:true)
    }
    private func engine(_ f: NativeAcceptanceTests.NativeFixture, languageEnabled: Bool = true) -> ApplicationOptimizationEngine {
        ApplicationOptimizationEngine(policy:SafetyPolicy(home:f.home,acceptedPlatform:true,validatedRules:languageEnabled ? [ApplicationOptimizationEngine.languageRule] : [ApplicationOptimizationEngine.rule]))
    }
    // A missing language publish/undo path, architecture-only dispatch or
    // dropping a fallback language must fail this actual signed-bundle check.
    func testPublishesOnlyReviewedOptionalLanguagesAndRestoresExactOriginalAfterRestart() async throws {
        let f = try fixture();defer { try? f.clean() }
        let original = try snapshot(f.app), mainBytes = try SafeFilesystem.readMetadata(f.executable)
        let e = engine(f), review = try await e.reviewLanguages(f.app,retaining:["zh-Hans-CN"])
        XCTAssertGreaterThan(review.estimatedReductionBytes,0)
        let batch = try await e.execute(reviewID:review.id)
        XCTAssertEqual(batch.rule,"application-language-transaction-v1");XCTAssertEqual(batch.status,.published)
        XCTAssertFalse(try SafeFilesystem.presence(f.app + "/Contents/Resources/fr.lproj"))
        for kept in ["Base","de","en","zh-Hans"] {
            XCTAssertTrue(try SafeFilesystem.presence(f.app + "/Contents/Resources/" + kept + ".lproj/Localizable.strings"))
        }
        XCTAssertEqual(try SafeFilesystem.readMetadata(f.executable),mainBytes)
        let valid = try BoundedProcess.capture("/usr/bin/codesign",arguments:["--verify","--deep","--strict","--all-architectures",f.app],timeout:15,mergeStderr:true)
        XCTAssertEqual(valid.status,0,valid.text)
        let restored = try await engine(f).undo(batchID:batch.id)
        XCTAssertEqual(restored.status,.restored)
        let after = try snapshot(f.app)
        XCTAssertTrue(after.identity.sameObject(as:original.identity));XCTAssertEqual(after.tree,original.tree)
        XCTAssertEqual(try SafeFilesystem.readMetadata(f.executable),mainBytes)
    }
    func testArchitectureValidationDoesNotAuthorizeLanguageExecutionOrReplay() async throws {
        let f = try fixture();defer { try? f.clean() }
        let original = try snapshot(f.app), disabled = engine(f,languageEnabled:false)
        let review = try await disabled.reviewLanguages(f.app,retaining:["en"])
        do { _ = try await disabled.execute(reviewID:review.id);XCTFail("Architecture rule authorized language omission") } catch { }
        XCTAssertNoThrow(try SafeFilesystem.verify(original))
        let e = engine(f), choice = try await e.reviewLanguages(f.app,retaining:["en"])
        let batch = try await e.execute(reviewID:choice.id)
        do { _ = try await e.execute(reviewID:choice.id);XCTFail("Language review replayed") } catch { }
        _ = try await e.undo(batchID:batch.id)
    }
    func testLanguageReviewCannotPublishChangedSourceAndEmptyPreferencesCannotReview() async throws {
        let f = try fixture();defer { try? f.clean() }
        let e = engine(f)
        do { _ = try await e.reviewLanguages(f.app,retaining:[]);XCTFail("Unknown retention accepted") } catch { }
        let review = try await e.reviewLanguages(f.app,retaining:["en"])
        let path = f.app + "/Contents/Resources/fr.lproj/Localizable.strings"
        try Data("new source resource".utf8).write(to:URL(fileURLWithPath:path))
        let changed = try snapshot(f.app)
        do { _ = try await e.execute(reviewID:review.id);XCTFail("Changed source published") } catch { }
        XCTAssertNoThrow(try SafeFilesystem.verify(changed))
        let history = try await e.history();XCTAssertTrue(history.isEmpty)
    }
}
#endif
