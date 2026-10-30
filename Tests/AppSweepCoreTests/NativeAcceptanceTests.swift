#if os(macOS)
import Foundation
import AppKit
import XCTest
@testable import AppSweepCore

final class NativeAcceptanceTests: XCTestCase, @unchecked Sendable {
    func testCaseVariantReplacementBlocksResidueAfterApplicationWasIsolated() async throws {
        let f = try NativeFixture(); defer { try? f.clean() }; try f.generate()
        let report = try await f.engine.scanApplication(f.app)
        let pref = try XCTUnwrap(report.candidates.first { $0.rule == "cfpreferences-exact-domain-v1" && $0.allowed })
        let isolated = f.home + "/isolated-original.app"
        try FileManager.default.moveItem(atPath:f.app,toPath:isolated)
        let replacement = f.home + "/Applications/Replacement.app"
        try FileManager.default.copyItem(atPath:isolated,toPath:replacement)
        let infoPath=replacement + "/Contents/Info.plist"
        var info = try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:infoPath)),format:nil) as? [String:Any])
        info["CFBundleIdentifier"]="Org.Example.Sweepfixture"
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:infoPath))
        _ = try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",replacement],timeout:10)
        do { try await f.engine.verifyOwner(pref,isolatedApplication:isolated); XCTFail("A differently cased installation still owns the same cache/preference namespace") } catch { }
        XCTAssertTrue(FileManager.default.fileExists(atPath:pref.path))
    }
    struct NativeFixture {
        let home: String
        let app: String
        let executable: String
        let engine: SweepEngine
        static func resource(_ name: String, extension suffix: String) throws -> URL {
            if let sourceRoot = ProcessInfo.processInfo.environment["APP_SWEEP_SOURCE_ROOT"] {
                let url = URL(fileURLWithPath: sourceRoot + "/Tests/AppSweepCoreTests/Fixtures/" + name + "." + suffix)
                guard FileManager.default.fileExists(atPath: url.path) else { throw SweepError.invalid("Owned test resource is missing") }
                return url
            }
            return try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: suffix, subdirectory: "Fixtures"))
        }
        init(additionalRules: Set<String> = []) throws {
            guard let base = ProcessInfo.processInfo.environment["APP_SWEEP_FIXTURES"], base.hasPrefix(FileManager.default.homeDirectoryForCurrentUser.path + "/AppSweepAcceptance"), getuid() != 0 else { throw XCTSkip("Requires explicit isolated fixture root and non-root test user") }
            home = base + "/" + UUID().uuidString
            app = home + "/Applications/Disposable Fixture.app"
            executable = app + "/Contents/MacOS/fixture"
            let fm = FileManager.default
            try fm.createDirectory(atPath: app + "/Contents/MacOS", withIntermediateDirectories: true)
            try fm.createDirectory(atPath: home + "/Library/Application Support", withIntermediateDirectories: true)
            let info: [String:Any] = ["CFBundleIdentifier":"org.example.sweepfixture", "CFBundleExecutable":"fixture", "CFBundlePackageType":"APPL", "CFBundleName":"Disposable Fixture", "CFBundleVersion":"1", "CFBundleShortVersionString":"1.0"]
            try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: URL(fileURLWithPath: app + "/Contents/Info.plist"))
            let source = try Self.resource("Fixture", extension: "m")
            let clang = ProcessInfo.processInfo.environment["APP_SWEEP_CLANG"] ?? "/usr/bin/clang"
            guard let sdk = ProcessInfo.processInfo.environment["APP_SWEEP_SDK"] else { throw XCTSkip("Requires isolated SDK") }
            let compiled = try BoundedProcess.capture(clang, arguments: ["-fobjc-arc", "-isysroot", sdk, "-mmacosx-version-min=12.0", "-framework", "Cocoa", source.path, "-o", executable], timeout: 30, mergeStderr: true)
            guard compiled.status == 0 else { throw SweepError.incomplete("Owned fixture compilation failed: " + compiled.text) }
            let signed = try BoundedProcess.capture("/usr/bin/codesign", arguments: ["--force", "--sign", "-", app], timeout: 10, mergeStderr: true)
            guard signed.status == 0 else { throw SweepError.incomplete("Owned fixture signing failed: " + signed.text) }
            engine = SweepEngine(policy: SafetyPolicy(home: home, acceptedPlatform: true, validatedRules: Set(["signed-application-v1", "cfpreferences-exact-domain-v1", "ips-third-party-30d-v1", XcodeRule.name]).union(additionalRules)), vaultPath: home + "/Library/Application Support/App Sweep/Recovery", fixture: false)
        }
        func generate(timeout: TimeInterval = 10) throws {
            let generated = try BoundedProcess.capture(executable, arguments: ["--generate", home], timeout: timeout, mergeStderr: true)
            guard generated.status == 0 else { throw SweepError.incomplete("Owned fixture generation failed: " + generated.text) }
        }
        func waitUntilUnused(_ path: String) async throws {
            // New native bundles are indexed asynchronously. The product must refuse
            // busy objects; the acceptance driver waits for its own sample to settle.
            var last: Error = SweepError.incomplete("Fixture still occupied")
            for _ in 0..<40 {
                do { try BusyInspector.ensureUnused(SafeFilesystem.snapshot(path, allowInternalLinks: true)); return }
                catch { last = error; try await Task.sleep(nanoseconds: 250_000_000) }
            }
            throw last
        }
        func waitForIsolatedObjects(_ manifest: RecoveryManifest) async throws {
            for entry in manifest.entries where entry.state == .moved {
                try await waitUntilUnused(home + "/Library/Application Support/App Sweep/Recovery/" + manifest.id.uuidString + "/" + manifest.objectsDirectory + "/" + entry.id.uuidString)
            }
        }
        func restoreWhenUnused(_ manifest: RecoveryManifest) async throws -> RecoveryManifest {
            var result = manifest
            for attempt in 0..<8 {
                try await waitForIsolatedObjects(result)
                result = try await engine.restore(batchID: manifest.id)
                if result.status == .restored { return result }
                guard result.entries.compactMap(\.message).contains(where: { $0.contains("文件占用状态未确认") || $0.contains("文件仍被进程使用") }) else { return result }
                // The product has stopped safely. A test driver may wait and
                // explicitly request recovery again after transient indexing.
                print("Owned native fixture recovery deferred for busy/unknown state, attempt \(attempt + 1)")
                for entry in result.entries where entry.state != .restored {
                    let path = home + "/Library/Application Support/App Sweep/Recovery/" + result.id.uuidString + "/" + result.objectsDirectory + "/" + entry.id.uuidString
                    if let diagnostic = try? BoundedProcess.capture("/usr/sbin/lsof", arguments: ["-F0pcn", "+D", path], timeout: 3, mergeStderr: true) { print(diagnostic.text.replacingOccurrences(of: "\0", with: " ")) }
                }
                try await Task.sleep(nanoseconds: 250_000_000)
            }
            return result
        }
        func clean() throws { try FileManager.default.removeItem(atPath: home) }
    }
    func testUnsignedChosenBodyRestoresWithoutClaimingItsUserData() async throws {
        let f = try NativeFixture(additionalRules: ["chosen-application-v1"]); defer { try? f.clean() }
        // ARM requires a signed Mach-O. The application bundle itself has no resource seal
        // and its executable's unrelated identifier cannot authorize application data.
        _ = try BoundedProcess.run("/usr/bin/codesign", arguments: ["--remove-signature", f.app], timeout: 10)
        _ = try BoundedProcess.run("/usr/bin/codesign", arguments: ["--force", "--sign", "-", "--identifier", "org.example.unsigned-executable", f.executable], timeout: 10)
        XCTAssertFalse(try AppInspector.inspect(f.app).signed)
        try f.generate(); try await f.waitUntilUnused(f.app)
        let report = try await f.engine.scanApplication(f.app)
        let body = try XCTUnwrap(report.candidates.first { $0.category == .application })
        let pref = try XCTUnwrap(report.candidates.first { $0.rule == "cfpreferences-exact-domain-v1" })
        XCTAssertTrue(body.allowed, body.retentionReason ?? "")
        XCTAssertFalse(pref.allowed, "A self-declared identifier is not authority over application data")
        let plan = try await f.engine.makePlan(reportID: report.id, selected: [body.id], includeUserData: false)
        let moved = try await f.engine.execute(planID: plan.id)
        XCTAssertEqual(moved.status, .isolated, moved.issue ?? "")
        XCTAssertTrue(FileManager.default.fileExists(atPath: pref.path))
        let restored = try await f.restoreWhenUnused(moved)
        XCTAssertEqual(restored.status, .restored)
        try f.generate()
    }
    func testChosenDuplicateBodyCanMoveWhileSharedPreferencesStay() async throws {
        let f = try NativeFixture(additionalRules: ["chosen-application-v1"]); defer { try? f.clean() }; try f.generate()
        let directory = f.home + "/Applications/Archive"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        let duplicate = directory + "/Second.app"
        try FileManager.default.copyItem(atPath: f.app, toPath: duplicate)
        try await f.waitUntilUnused(f.app)
        let report = try await f.engine.scanApplication(f.app)
        let body = try XCTUnwrap(report.candidates.first { $0.category == .application })
        let pref = try XCTUnwrap(report.candidates.first { $0.rule == "cfpreferences-exact-domain-v1" })
        XCTAssertTrue(body.allowed, body.retentionReason ?? "")
        XCTAssertFalse(pref.allowed)
        let plan = try await f.engine.makePlan(reportID: report.id, selected: [body.id], includeUserData: false)
        let moved = try await f.engine.execute(planID: plan.id)
        XCTAssertEqual(moved.status, .isolated, moved.issue ?? "")
        XCTAssertTrue(FileManager.default.fileExists(atPath: duplicate))
        XCTAssertTrue(FileManager.default.fileExists(atPath: pref.path))
        let restored = try await f.restoreWhenUnused(moved)
        XCTAssertEqual(restored.status, .restored)
        try f.generate()
    }
    func testChosenArchiveDirectoryIsDistinctFromPackageEmbeddedApp() async throws {
        let f = try NativeFixture(additionalRules: ["chosen-application-v1"]); defer { try? f.clean() }
        let archive = f.home + "/Applications/Archive"
        let helpers = f.app + "/Contents/Helpers"
        try FileManager.default.createDirectory(atPath: archive, withIntermediateDirectories: true)
        let copy = archive + "/Archived.app"
        try FileManager.default.copyItem(atPath: f.app, toPath: copy)
        try FileManager.default.createDirectory(atPath: helpers, withIntermediateDirectories: true)
        try FileManager.default.copyItem(atPath: copy, toPath: helpers + "/Embedded.app")
        let ordinary = try await f.engine.scanApplication(copy)
        XCTAssertTrue(try XCTUnwrap(ordinary.candidates.first { $0.category == .application }).allowed)
        let embedded = try await f.engine.scanApplication(helpers + "/Embedded.app")
        XCTAssertFalse(try XCTUnwrap(embedded.candidates.first { $0.category == .application }).allowed, "An embedded component is part of its outer application's body")
    }
    func testChosenBodyRejectsMissingOrEscapingExecutable() async throws {
        for executable in ["missing", "../outside"] {
            let f = try NativeFixture(additionalRules: ["chosen-application-v1"]); defer { try? f.clean() }
            let infoURL = URL(fileURLWithPath: f.app + "/Contents/Info.plist")
            var info = try XCTUnwrap(try PropertyListSerialization.propertyList(from: Data(contentsOf: infoURL), format: nil) as? [String: Any])
            info["CFBundleExecutable"] = executable
            try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: infoURL)
            let report = try await f.engine.scanApplication(f.app)
            XCTAssertFalse(try XCTUnwrap(report.candidates.first { $0.category == .application }).allowed)
        }
    }
    func testUnreadableUnrelatedInventoryRetainsDataWithoutDisablingChosenBody() async throws {
        let f = try NativeFixture(additionalRules: ["chosen-application-v1"]); defer { try? f.clean() }; try f.generate()
        let inaccessible = f.home + "/Applications/Unconfirmed"
        try FileManager.default.createDirectory(atPath: inaccessible, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: inaccessible)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: inaccessible) }
        try await f.waitUntilUnused(f.app)
        let report = try await f.engine.scanApplication(f.app)
        XCTAssertFalse(report.complete)
        let body = try XCTUnwrap(report.candidates.first { $0.category == .application })
        XCTAssertTrue(report.selectableCandidates(includeUserData: true).contains { $0.id == body.id })
        XCTAssertFalse(report.selectableCandidates(includeUserData: true).contains { $0.userData })
        let plan = try await f.engine.makePlan(reportID: report.id, selected: [body.id], includeUserData: false)
        let moved = try await f.engine.execute(planID: plan.id)
        XCTAssertEqual(moved.status, .isolated, moved.issue ?? "")
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.home + "/Library/Preferences/org.example.sweepfixture.plist"))
        let restored = try await f.restoreWhenUnused(moved)
        XCTAssertEqual(restored.status, .restored)
        try f.generate()
    }
    func testUnusedHelperDeclarationDoesNotDisableChosenBody() async throws {
        let f = try NativeFixture(additionalRules: ["chosen-application-v1"]); defer { try? f.clean() }
        try f.generate()
        let label = "org.example.disposable-helper." + UUID().uuidString
        XCTAssertFalse(FileManager.default.fileExists(atPath: "/Library/PrivilegedHelperTools/" + label))
        XCTAssertFalse(FileManager.default.fileExists(atPath: "/Library/LaunchDaemons/" + label + ".plist"))
        let infoURL = URL(fileURLWithPath: f.app + "/Contents/Info.plist")
        var info = try XCTUnwrap(try PropertyListSerialization.propertyList(from: Data(contentsOf: infoURL), format: nil) as? [String: Any])
        info["SMPrivilegedExecutables"] = [label: "identifier \"" + label + "\""]
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: infoURL)
        _ = try BoundedProcess.run("/usr/bin/codesign", arguments: ["--force", "--sign", "-", f.app], timeout: 10)
        try await f.waitUntilUnused(f.app)
        let report = try await f.engine.scanApplication(f.app)
        let body = try XCTUnwrap(report.candidates.first { $0.category == .application })
        XCTAssertTrue(body.allowed, body.retentionReason ?? "")
        let preference = try XCTUnwrap(report.candidates.first { $0.rule == "cfpreferences-exact-domain-v1" })
        XCTAssertTrue(preference.allowed, preference.retentionReason ?? "")
        let plan = try await f.engine.makePlan(reportID: report.id, selected: [body.id, preference.id], includeUserData: true)
        let moved = try await f.engine.execute(planID: plan.id)
        XCTAssertEqual(moved.status, .isolated, moved.issue ?? "")
        let restored = try await f.restoreWhenUnused(moved)
        XCTAssertEqual(restored.status, .restored)
        try f.generate()
    }
    func testRegisteredHelperLabelStopsChosenBodyWithoutTouchingService() async throws {
        for (domain, label) in [("system", "com.apple.logd"), ("gui/" + String(getuid()), "com.apple.Dock.agent")] {
        let f = try NativeFixture(additionalRules: ["chosen-application-v1"]); defer { try? f.clean() }
        let registered = try BoundedProcess.capture("/bin/launchctl", arguments: ["print", domain + "/" + label], timeout: 3, mergeStderr: true)
        XCTAssertEqual(registered.status, 0, "Requires an existing native service; no test service is installed")
        let infoURL = URL(fileURLWithPath: f.app + "/Contents/Info.plist")
        var info = try XCTUnwrap(try PropertyListSerialization.propertyList(from: Data(contentsOf: infoURL), format: nil) as? [String: Any])
        info["SMPrivilegedExecutables"] = [label: "identifier \"" + label + "\""]
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: infoURL)
        _ = try BoundedProcess.run("/usr/bin/codesign", arguments: ["--force", "--sign", "-", f.app], timeout: 10)
        try await f.waitUntilUnused(f.app)
        let report = try await f.engine.scanApplication(f.app)
        let body = try XCTUnwrap(report.candidates.first { $0.category == .application })
        XCTAssertTrue(body.allowed, "Scan may discover the body; execution must separately check registered dependency labels")
        do {
            _ = try await f.engine.makePlan(reportID: report.id, selected: [body.id], includeUserData: false)
            XCTFail("Registered helper must block review before execution")
        } catch { XCTAssertTrue(error.localizedDescription.contains("服务"),error.localizedDescription) }
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.app))
        XCTAssertEqual(try BoundedProcess.capture("/bin/launchctl", arguments: ["print", domain + "/" + label], timeout: 3, mergeStderr: true).status, 0)
        }
    }
    func testUnsignedBodyInterruptionRecoversInFreshEngine() async throws {
        let f = try NativeFixture(additionalRules: ["chosen-application-v1"]); defer { try? f.clean() }
        _ = try BoundedProcess.run("/usr/bin/codesign", arguments: ["--remove-signature", f.app], timeout: 10)
        _ = try BoundedProcess.run("/usr/bin/codesign", arguments: ["--force", "--sign", "-", "--identifier", "org.example.unsigned-executable", f.executable], timeout: 10)
        try f.generate(); try await f.waitUntilUnused(f.app)
        let policy = SafetyPolicy(home: f.home, acceptedPlatform: true, validatedRules: ["chosen-application-v1"])
        let vault = f.home + "/Library/Application Support/App Sweep/Recovery"
        let interrupted = SweepEngine(policy: policy, vaultPath: vault, failurePoint: .interruptAfterMove, fixture: false)
        let report = try await interrupted.scanApplication(f.app)
        let body = try XCTUnwrap(report.selectableCandidates(includeUserData: false).first { $0.category == .application })
        let plan = try await interrupted.makePlan(reportID: report.id, selected: [body.id], includeUserData: false)
        do { _ = try await interrupted.execute(planID: plan.id); XCTFail("Expected the owned interruption point") } catch { }
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.app))
        let recovery = SweepEngine(policy: policy, vaultPath: vault, fixture: false)
        let batches = try await recovery.recoveryBatches()
        let batch = try XCTUnwrap(batches.first)
        XCTAssertTrue(batch.hasUnconfirmedObjects)
        let restored = try await recovery.restore(batchID: batch.id)
        XCTAssertEqual(restored.status, .restored, restored.entries.compactMap(\.message).joined(separator: "; "))
        XCTAssertFalse(try AppInspector.inspect(f.app).signed)
        try f.generate()
    }
    func testSignedAppDefaultRetainsDataAndRestoresExecutable() async throws {
        let f = try NativeFixture(); defer { try? f.clean() }; try f.generate(); try await f.waitUntilUnused(f.app)
        let report = try await f.engine.scanApplication(f.app)
        XCTAssertTrue(report.complete, report.issues.joined(separator: "\n"))
        let app = try XCTUnwrap(report.candidates.first { $0.category == .application })
        let pref = try XCTUnwrap(report.candidates.first { $0.rule == "cfpreferences-exact-domain-v1" })
        XCTAssertTrue(app.allowed); XCTAssertTrue(pref.allowed); XCTAssertFalse(pref.selectedByDefault)
        let plan = try await f.engine.makePlan(reportID: report.id, selected: Set(report.candidates.filter(\.selectedByDefault).map(\.id)), includeUserData: false)
        XCTAssertFalse(plan.items.contains { $0.userData })
        let moved = try await f.engine.execute(planID: plan.id)
        XCTAssertEqual(moved.status, .isolated, moved.issue ?? "")
        XCTAssertTrue(FileManager.default.fileExists(atPath: pref.path))
        try await f.waitForIsolatedObjects(moved)
        let restored = try await f.restoreWhenUnused(moved)
        XCTAssertEqual(restored.status, .restored, restored.entries.compactMap(\.message).joined(separator: "\n"))
        try f.generate()
    }
    func testExplicitUserDataChoiceIncludesAllEligibleData() async throws {
        let f = try NativeFixture(); defer { try? f.clean() }; try f.generate(); try await f.waitUntilUnused(f.app)
        let report = try await f.engine.scanApplication(f.app)
        let selected = Set(report.candidates.filter(\.allowed).map(\.id))
        let plan = try await f.engine.makePlan(reportID: report.id, selected: selected, includeUserData: true)
        XCTAssertEqual(Set(plan.items.filter(\.userData).map(\.id)), Set(report.candidates.filter { $0.allowed && $0.userData }.map(\.id)))
        let moved = try await f.engine.execute(planID: plan.id)
        XCTAssertEqual(moved.status, .isolated, moved.issue ?? "")
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.home + "/Library/Preferences/org.example.sweepfixture.plist"))
        try await f.waitForIsolatedObjects(moved)
        let restored = try await f.restoreWhenUnused(moved)
        XCTAssertEqual(restored.status, .restored, restored.entries.compactMap(\.message).joined(separator: "\n"))
        try f.generate()
    }
    func testNestedSignedCopyRetainsSharedPreferences() async throws {
        let f = try NativeFixture(); defer { try? f.clean() }; try f.generate()
        let directory = f.home + "/Applications/Archive"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        try FileManager.default.copyItem(atPath: f.app, toPath: directory + "/Second.app")
        let report = try await f.engine.scanApplication(f.app)
        let pref = try XCTUnwrap(report.candidates.first { $0.rule == "cfpreferences-exact-domain-v1" })
        XCTAssertFalse(pref.allowed)
        XCTAssertNotNil(pref.retentionReason)
        XCTAssertTrue(FileManager.default.fileExists(atPath: pref.path))
    }
    func testRunningAppStopsEntireBatchWithoutTerminatingIt() async throws {
        let f = try NativeFixture(), process = Process()
        defer { if !process.isRunning { try? f.clean() } }
        try f.generate()
        let report = try await f.engine.scanApplication(f.app)
        let plan = try await f.engine.makePlan(reportID: report.id, selected: Set(report.candidates.filter(\.selectedByDefault).map(\.id)), includeUserData: false)
        process.executableURL = URL(fileURLWithPath: f.executable); process.arguments = ["--wait", f.home]
        let stopped = expectation(description: "Owned running-app fixture exited")
        process.terminationHandler = { _ in stopped.fulfill() }
        try process.run()
        var bodyError: Error?
        do {
            for _ in 0..<100 where !FileManager.default.fileExists(atPath:f.home + "/wait-ready") { try await Task.sleep(nanoseconds:50_000_000) }
            guard FileManager.default.fileExists(atPath:f.home + "/wait-ready"),process.isRunning else { throw SweepError.incomplete("Disposable application failed to reach its running barrier") }
            do { _ = try await f.engine.execute(planID: plan.id); XCTFail("Running application was moved") } catch { }
            XCTAssertTrue(process.isRunning)
            XCTAssertTrue(FileManager.default.fileExists(atPath: f.app))
        } catch { bodyError = error }
        try Data().write(to:URL(fileURLWithPath:f.home + "/release-wait"))
        await fulfillment(of:[stopped],timeout:10)
        guard !process.isRunning else { throw SweepError.incomplete("Owned running-app fixture did not exit; retained at " + f.home) }
        XCTAssertEqual(process.terminationStatus,0)
        if let bodyError { throw bodyError }
    }
    func testRunningBundleIdentityBlocksChecksWithoutAnApplicationPath() async throws {
        let f = try NativeFixture(), process = Process()
        defer { if !process.isRunning { try? f.clean() } }
        process.executableURL = URL(fileURLWithPath: f.executable); process.arguments = ["--wait", f.home]
        let stopped = expectation(description: "Owned bundle-identity fixture exited")
        process.terminationHandler = { _ in stopped.fulfill() }
        try process.run()
        var bodyError: Error?
        do {
            let identifier = "org.example.sweepfixture"
            var registered = false
            for _ in 0..<100 {
                registered = NSRunningApplication.runningApplications(withBundleIdentifier: identifier).contains { $0.processIdentifier == process.processIdentifier }
                if registered && FileManager.default.fileExists(atPath: f.home + "/wait-ready") { break }
                try await Task.sleep(nanoseconds: 50_000_000)
            }
            guard registered, process.isRunning else { throw SweepError.incomplete("Owned GUI process did not register its bundle identity; no behavioral result") }
            XCTAssertThrowsError(try ActivityInspector.ensureStopped(bundleID: identifier, applicationPath: nil), "Recovery has no installed body path while data is restored")
            XCTAssertThrowsError(try ActivityInspector.ensureStopped(bundleID: "org.example.unrelated", applicationPath: nil, additionalIdentifiers: [identifier]), "A component identity must also block")
            XCTAssertThrowsError(try ActivityInspector.ensureStopped(bundleID: identifier.uppercased(), applicationPath: nil), "Case variants share the same protected data namespace")
            XCTAssertTrue(process.isRunning, "The inspector must never terminate a running application")
        } catch { bodyError = error }
        try Data().write(to:URL(fileURLWithPath:f.home + "/release-wait"))
        await fulfillment(of:[stopped],timeout:10)
        guard !process.isRunning else { throw SweepError.incomplete("Owned bundle-identity fixture did not exit; retained at " + f.home) }
        XCTAssertEqual(process.terminationStatus,0)
        if let bodyError { throw bodyError }
    }
    func testOccupiedApplicationBodyIsRetainedDuringScan() async throws {
        let f = try NativeFixture(additionalRules: [ChosenApplicationRule.name]); defer { try? f.clean() }
        let reader = try FileHandle(forReadingFrom: URL(fileURLWithPath: f.executable))
        defer { try? reader.close() }
        let occupied = try await f.engine.scanApplication(f.app)
        let body = try XCTUnwrap(occupied.candidates.first { $0.category == .application })
        XCTAssertFalse(body.allowed, "A known open extension or file must be explained before presenting an executable plan")
        XCTAssertTrue(body.retentionReason?.contains("仍被进程使用") == true)
        try reader.close()
        let idle = try await f.engine.scanApplication(f.app)
        XCTAssertTrue(try XCTUnwrap(idle.candidates.first { $0.category == .application }).allowed)
    }
    func testOpenFileStopsTheWholePlanBeforeAnyMove() async throws {
        let f = try NativeFixture(); defer { try? f.clean() }; try f.generate()
        let report = try await f.engine.scanApplication(f.app)
        let plan = try await f.engine.makePlan(reportID: report.id, selected: Set(report.candidates.filter(\.allowed).map(\.id)), includeUserData: true)
        let preference = URL(fileURLWithPath: f.home + "/Library/Preferences/org.example.sweepfixture.plist")
        let handle = try FileHandle(forReadingFrom: preference); defer { try? handle.close() }
        do { _ = try await f.engine.execute(planID: plan.id); XCTFail("Occupied file was moved") } catch { }
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.app))
        XCTAssertTrue(FileManager.default.fileExists(atPath: preference.path))
    }
    func testLaterOccupiedPurgeObjectIsPreservedAfterEarlierObjectWasPurged() async throws {
        let f = try NativeFixture(); defer { try? f.clean() }; try f.generate(); try await f.waitUntilUnused(f.app)
        let engine = SweepEngine(policy: SafetyPolicy(home: f.home, acceptedPlatform: true, validatedRules: ["signed-application-v1", "cfpreferences-exact-domain-v1"]), vaultPath: f.home + "/Library/Application Support/App Sweep/Recovery", failurePoint: .occupySecondPurge, fixture: false)
        let report = try await engine.scanApplication(f.app)
        let plan = try await engine.makePlan(reportID: report.id, selected: Set(report.candidates.filter(\.allowed).map(\.id)), includeUserData: true)
        XCTAssertEqual(plan.items.count, 2)
        let moved = try await engine.execute(planID: plan.id)
        XCTAssertEqual(moved.status, .isolated, moved.issue ?? "")
        try await f.waitForIsolatedObjects(moved)
        let result = try await engine.purge(batchID: moved.id, confirmation: "永久清空 " + moved.id.uuidString)
        XCTAssertEqual(result.status, .needsAttention)
        XCTAssertEqual(result.entries.first?.state, .purged)
        XCTAssertEqual(result.entries.last?.state, .moved)
        let preference = try XCTUnwrap(result.entries.last)
        XCTAssertTrue(FileManager.default.fileExists(atPath: f.home + "/Library/Application Support/App Sweep/Recovery/" + result.id.uuidString + "/" + result.objectsDirectory + "/" + preference.id.uuidString))
    }
    func testRestorePreservesPermissionsGroupAndExtendedAttributes() async throws {
        let f = try NativeFixture(); defer { try? f.clean() }; try f.generate()
        let preference = f.home + "/Library/Preferences/org.example.sweepfixture.plist"
        try FileManager.default.setAttributes([.posixPermissions:0o640], ofItemAtPath: preference)
        _ = try BoundedProcess.run("/usr/bin/xattr", arguments: ["-w", "org.appsweep.acceptance", "fixture-metadata", preference], timeout: 3)
        let before = try FileManager.default.attributesOfItem(atPath: preference)
        try await f.waitUntilUnused(f.app)
        let report = try await f.engine.scanApplication(f.app)
        let plan = try await f.engine.makePlan(reportID: report.id, selected: Set(report.candidates.filter(\.allowed).map(\.id)), includeUserData: true)
        let moved = try await f.engine.execute(planID: plan.id)
        XCTAssertEqual(moved.status, .isolated, moved.issue ?? "")
        try await f.waitForIsolatedObjects(moved)
        let restored = try await f.restoreWhenUnused(moved)
        XCTAssertEqual(restored.status, .restored, restored.entries.compactMap(\.message).joined(separator: "\n"))
        let after = try FileManager.default.attributesOfItem(atPath: preference)
        for key in [FileAttributeKey.posixPermissions, .ownerAccountID, .groupOwnerAccountID] {
            XCTAssertEqual(before[key] as? NSNumber, after[key] as? NSNumber)
        }
        let metadata = try BoundedProcess.run("/usr/bin/xattr", arguments: ["-p", "org.appsweep.acceptance", preference], timeout: 3)
        XCTAssertEqual(metadata.trimmingCharacters(in: .whitespacesAndNewlines), "fixture-metadata")
    }

    func testOldStructuredCrashIsIsolatedAndRestoredWhileMismatchedReportIsRetained() async throws {
        let f = try NativeFixture(); defer { try? f.clean() }; try f.generate()
        let directory = f.home + "/Library/Logs/DiagnosticReports"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        let header = try JSONSerialization.data(withJSONObject: ["bug_type":"309", "bundleID":"org.example.sweepfixture"])
        for (name, path) in [("matching.ips", f.executable), ("mismatched.ips", "/Applications/Another.app/Contents/MacOS/fixture")] {
            let body = try JSONSerialization.data(withJSONObject: ["bundleInfo":["CFBundleIdentifier":"org.example.sweepfixture"], "procPath":path])
            let destination = directory + "/" + name
            try (header + Data([10]) + body).write(to: URL(fileURLWithPath: destination))
            try FileManager.default.setAttributes([.modificationDate:Date().addingTimeInterval(-31 * 86400)], ofItemAtPath: destination)
        }
        let report = try await f.engine.scanJunk()
        XCTAssertTrue(report.complete, report.issues.joined(separator: "\n"))
        let log = try XCTUnwrap(report.candidates.first { $0.path == directory + "/matching.ips" })
        XCTAssertTrue(log.allowed)
        XCTAssertFalse(try XCTUnwrap(report.candidates.first { $0.path == directory + "/mismatched.ips" }).allowed)
        let plan = try await f.engine.makePlan(reportID: report.id, selected: [log.id], includeUserData: false)
        let moved = try await f.engine.execute(planID: plan.id)
        XCTAssertEqual(moved.status, .isolated, moved.issue ?? "")
        XCTAssertFalse(FileManager.default.fileExists(atPath: log.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: directory + "/mismatched.ips"))
        let restored = try await f.restoreWhenUnused(moved)
        XCTAssertEqual(restored.status, .restored, restored.entries.compactMap(\.message).joined(separator: "\n"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: log.path))
    }

    func testXcodeIntermediateFilesRegenerateAndRestoreWithoutTouchingProductsOrSources() async throws {
        print("Native Xcode acceptance: creating owned fixture")
        let f = try NativeFixture(); defer { try? f.clean() }
        let fm = FileManager.default
        let project = f.home + "/Fixture.xcodeproj"
        let derived = f.home + "/Library/Developer/Xcode/DerivedData/Fixture-acceptance"
        try fm.createDirectory(atPath: project, withIntermediateDirectories: true)
        let projectResource = try NativeFixture.resource("BuildFixture", extension: "pbxproj")
        let sourceResource = try NativeFixture.resource("BuildFixture", extension: "c")
        try fm.copyItem(atPath: projectResource.path, toPath: project + "/project.pbxproj")
        try fm.copyItem(atPath: sourceResource.path, toPath: f.home + "/main.c")
        let developer = try XCTUnwrap(ProcessInfo.processInfo.environment["DEVELOPER_DIR"])
        let arguments = ["-project", project, "-scheme", "Fixture", "-derivedDataPath", derived, "-configuration", "Debug", "CODE_SIGNING_ALLOWED=NO", "build"]
        print("Native Xcode acceptance: initial build")
        let first = try BoundedProcess.capture(developer + "/usr/bin/xcodebuild", arguments: arguments, timeout: 30, mergeStderr: true)
        guard first.status == 0 else { throw SweepError.incomplete("Owned build fixture failed: " + String(first.text.prefix(12000))) }
        XCTAssertTrue(first.text.contains("BUILD SUCCEEDED"))
        let source = try Data(contentsOf: URL(fileURLWithPath: f.home + "/main.c"))
        let product = derived + "/Build/Products/Debug/Fixture"
        let before = try Data(contentsOf: URL(fileURLWithPath: product))
        print("Native Xcode acceptance: scan and isolate")
        let report = try await f.engine.scanJunk()
        let item = try XCTUnwrap(report.candidates.first { $0.rule == XcodeRule.name })
        XCTAssertTrue(item.allowed, item.retentionReason ?? "")
        try await f.waitUntilUnused(item.path)
        let plan = try await f.engine.makePlan(reportID: report.id, selected: [item.id], includeUserData: false)
        let moved = try await f.engine.execute(planID: plan.id)
        XCTAssertEqual(moved.status, .isolated, moved.issue ?? "")
        XCTAssertFalse(fm.fileExists(atPath: item.path))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: product)), before)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.home + "/main.c")), source)
        try await f.waitForIsolatedObjects(moved)
        print("Native Xcode acceptance: restore intermediate files")
        let restored = try await f.restoreWhenUnused(moved)
        XCTAssertEqual(restored.status, .restored, restored.entries.compactMap(\.message).joined(separator: "\n"))
        let nextReport = try await f.engine.scanJunk()
        let nextItem = try XCTUnwrap(nextReport.candidates.first { $0.rule == XcodeRule.name })
        let nextPlan = try await f.engine.makePlan(reportID: nextReport.id, selected: [nextItem.id], includeUserData: false)
        print("Native Xcode acceptance: isolate again")
        let nextMoved = try await f.engine.execute(planID: nextPlan.id)
        XCTAssertEqual(nextMoved.status, .isolated, nextMoved.issue ?? "")
        print("Native Xcode acceptance: regenerate")
        let rebuilt = try BoundedProcess.capture(developer + "/usr/bin/xcodebuild", arguments: arguments, timeout: 30, mergeStderr: true)
        guard rebuilt.status == 0 else { throw SweepError.incomplete("Owned rebuild fixture failed: " + String(rebuilt.text.prefix(12000))) }
        XCTAssertTrue(rebuilt.text.contains("BUILD SUCCEEDED"))
        XCTAssertTrue(fm.fileExists(atPath: item.path))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: f.home + "/main.c")), source)
        // Regenerated output is an explicit restore conflict; it must not be overwritten.
        let conflict = try await f.engine.restore(batchID: nextMoved.id)
        XCTAssertEqual(conflict.status, .needsAttention)
    }

}
#endif
