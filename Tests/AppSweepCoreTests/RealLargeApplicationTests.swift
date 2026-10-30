#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class RealLargeApplicationTests: XCTestCase, @unchecked Sendable {
    private func context() throws -> (home: String, task: String, source: String) {
        let model = try BoundedProcess.run("/usr/sbin/sysctl", arguments: ["-n", "hw.model"], timeout: 3).trimmingCharacters(in: .whitespacesAndNewlines)
        let home = try SystemIdentity.home()
        #if arch(arm64)
        guard model.hasPrefix("VirtualMac"), home == "/Users/localtest" else { throw XCTSkip("Registered disposable VM only") }
        let task = home + "/AppSweepAcceptanceGeneral-20261016"
        return (home, task, task + "/developer/Xcode.app")
        #elseif arch(x86_64)
        guard model == "MacBookPro14,3", home == "/Users/acceptance",
              try BoundedProcess.run("/usr/sbin/sysctl", arguments: ["-n", "kern.osversion"], timeout: 3).trimmingCharacters(in: .whitespacesAndNewlines) == "22H730" else { throw XCTSkip("Registered Intel acceptance machine only") }
        return (home, home + "/AppSweepGeneral-20261016", "/Applications/Xcode.app")
        #else
        throw XCTSkip("No registered real-large environment")
        #endif
    }
    private func restoreWhenIdle(_ engine: SweepEngine, id: UUID) async throws -> RecoveryManifest {
        for attempt in 0..<12 {
            let result = try await engine.restore(batchID: id)
            if result.status == .restored { return result }
            let messages = result.entries.compactMap(\.message)
            guard messages.contains(where: { $0.contains("文件仍被进程使用") || $0.contains("文件占用状态未确认") }) else { return result }
            print("Owned SDK recovery deferred for an observed or unconfirmed open descriptor, attempt \(attempt + 1); no process or guard changed")
            try await Task.sleep(nanoseconds: 5_000_000_000)
        }
        throw SweepError.incomplete("Owned SDK clone remains in recovery after bounded normal retries; retain batch " + id.uuidString)
    }
    func testRestorePreviouslyRetainedTaskOwnedCloneThroughNormalRecovery() async throws {
        guard let text = ProcessInfo.processInfo.environment["APP_SWEEP_LARGE_RECOVERY_BATCH"], let id = UUID(uuidString: text) else { throw XCTSkip("Explicit registered recovery batch required") }
        let (home, task, source) = try context()
        let rules = NativeAcceptance.rules(for: PlatformStamp.current).union([SelectedApplicationRule.name, ChosenApplicationRule.largeName])
        let engine = SweepEngine(policy: SafetyPolicy(home: home, acceptedPlatform: true, validatedRules: rules), vaultPath: home + "/Library/Application Support/App Sweep/Recovery", fixture: false)
        let batches = try await engine.recoveryBatches()
        let batch = try XCTUnwrap(batches.first { $0.id == id })
        guard batch.entries.count == 1, let entry = batch.entries.first,
              entry.original.rule == SelectedApplicationRule.name, entry.original.bundleIdentifier == "com.apple.dt.Xcode",
              entry.original.path.hasPrefix(task + "/real-large.noindex/Xcode-"), entry.original.path.hasSuffix(".app"),
              let fingerprint = entry.treeFingerprint else { throw SweepError.denied("Not the registered owned SDK clone") }
        let name = URL(fileURLWithPath: entry.original.path).deletingPathExtension().lastPathComponent
        guard let token = UUID(uuidString: String(name.dropFirst("Xcode-".count))) else { throw SweepError.denied("Invalid owned clone token") }
        let receipt = try JSONSerialization.jsonObject(with: SafeFilesystem.readMetadata(task + "/real-large.noindex/" + token.uuidString + ".json")) as? [String: Any]
        guard receipt?["source"] as? String == source, receipt?["clone"] as? String == entry.original.path,
              receipt?["createdFromAbsent"] as? Bool == true else { throw SweepError.denied("Owned clone receipt does not match") }
        let result = try await restoreWhenIdle(engine, id: id)
        guard result.status == .restored else { throw SweepError.incomplete(result.entries.compactMap(\.message).joined(separator: "; ")) }
        let after = try SafeFilesystem.snapshot(entry.original.path, allowInternalLinks: true, purpose: .application)
        guard let original = entry.original.identity, after.identity.sameObject(as: original),
              try fingerprint.matches(after.tree),
              AppInspector.signatureMatches(path: entry.original.path, identifier: "com.apple.dt.Xcode"),
              AppInspector.signatureMatches(path: source, identifier: "com.apple.dt.Xcode") else { throw SweepError.stale("Recovered clone differs; retain it") }
        XCTAssertEqual(try BoundedProcess.capture(source + "/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang", arguments: ["--version"], timeout: 10, mergeStderr: true).status, 0)
        try FileManager.default.removeItem(atPath: entry.original.path)
        print("Previously retained owned clone restored through normal API; exact identity/fingerprint and both official signatures confirmed; only the verified disposable clone removed.")
    }
    func testTaskOwnedXcodeCloneRestoresWithoutTouchingTheToolchain() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_REAL_LARGE_ACCEPTANCE"] == "1" else { throw XCTSkip("Explicit registered real-large acceptance required") }
        let (home, task, source) = try context(), identifier = "com.apple.dt.Xcode"
        guard AppInspector.signatureMatches(path: source, identifier: identifier) else { throw SweepError.incomplete("Private SDK signature was not confirmed before cloning") }
        let original = try SafeDirectory(path: source).ownIdentity
        let parent = try SafeDirectory(path: task).privateChild("real-large.noindex")
        guard parent.availableBytes > 2 * 1024 * 1024 * 1024 else { throw SweepError.denied("Less than2GiB available; do not create the large acceptance clone") }
        let token = UUID().uuidString, clone = parent.path + "/Xcode-" + token + ".app"
        guard try !SafeFilesystem.presence(clone) else { throw SweepError.invalid("Clone destination already exists") }
        let receipt = try JSONSerialization.data(withJSONObject: ["source": source, "clone": clone, "createdFromAbsent": true, "purpose": "owned actual large software round-trip"], options: [.sortedKeys])
        try parent.write(receipt, name: token + ".json")
        var cleanupAllowed = true
        defer {
            if cleanupAllowed { try? FileManager.default.removeItem(atPath: clone) }
            else { print("Retained owned clone or recovery batch for normal recovery: " + clone) }
        }
        print("Real large acceptance: cloning registered private SDK with APFS copy-on-write")
        // Acceptance setup may need longer than the product's30s subprocess cap
        // on the registered older Mac. This exact, test-owned cp process has a
        // separate300s bound; no product timeout or execution guard is changed.
        let copy = Process(), output = Pipe()
        copy.executableURL = URL(fileURLWithPath: "/bin/cp"); copy.arguments = ["-cR", source, clone]
        copy.standardOutput = output; copy.standardError = output
        cleanupAllowed = false
        try copy.run()
        defer { if copy.isRunning { copy.terminate() } }
        print("Owned acceptance clone process \(copy.processIdentifier), bounded to300s")
        let deadline = ProcessInfo.processInfo.systemUptime + 300
        while copy.isRunning && ProcessInfo.processInfo.systemUptime < deadline { try await Task.sleep(nanoseconds: 100_000_000) }
        if copy.isRunning {
            copy.terminate()
            for _ in 0..<50 where copy.isRunning { try await Task.sleep(nanoseconds: 100_000_000) }
        }
        guard !copy.isRunning else { throw SweepError.incomplete("Owned clone process has not exited; retain its destination") }
        // The bounded loop above has already observed termination.
        cleanupAllowed = true
        guard copy.terminationStatus == 0 else { throw SweepError.incomplete("Owned SDK clone failed: " + String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)) }
        guard AppInspector.signatureMatches(path: clone, identifier: identifier) else { throw SweepError.incomplete("Clone signature not confirmed") }
        let before = try SafeFilesystem.snapshot(clone, allowInternalLinks: true, purpose: .application)
        guard before.tree.count > 20_000 else { throw SweepError.incomplete("SDK clone does not exercise the large recovery path") }
        let rules = NativeAcceptance.rules(for: PlatformStamp.current).union([SelectedApplicationRule.name, ChosenApplicationRule.largeName])
        let engine = SweepEngine(policy: SafetyPolicy(home: home, acceptedPlatform: true, validatedRules: rules), vaultPath: home + "/Library/Application Support/App Sweep/Recovery", fixture: false)
        print("Real large acceptance: scanning \(before.tree.count) complete bundle entries")
        let report = try await engine.scanApplication(clone)
        let body = try XCTUnwrap(report.selectableCandidates(includeUserData: false).first { $0.category == .application && $0.path == clone }, report.candidates.compactMap(\.retentionReason).joined(separator: "; "))
        XCTAssertEqual(body.rule, SelectedApplicationRule.name)
        let plan = try await engine.makePlan(reportID: report.id, selected: [body.id], includeUserData: false)
        cleanupAllowed = false
        print("Real large acceptance: isolating only the owned clone")
        let moved = try await engine.execute(planID: plan.id)
        guard moved.status == .isolated else { throw SweepError.incomplete(moved.issue ?? "Clone isolation incomplete") }
        XCTAssertLessThan(try JSONEncoder().encode(moved).count, 64 * 1024)
        print("Real large acceptance: restoring through a fresh engine")
        let recovery = SweepEngine(policy: SafetyPolicy(home: home, acceptedPlatform: true, validatedRules: rules), vaultPath: home + "/Library/Application Support/App Sweep/Recovery", fixture: false)
        let restored = try await restoreWhenIdle(recovery, id: moved.id)
        guard restored.status == .restored else { throw SweepError.incomplete("Retained SDK clone recovery batch " + moved.id.uuidString + ": " + restored.entries.compactMap(\.message).joined(separator: "; ")) }
        let after = try SafeFilesystem.snapshot(clone, allowInternalLinks: true, purpose: .application)
        guard after.identity.sameObject(as: before.identity), after.tree == before.tree,
              AppInspector.signatureMatches(path: clone, identifier: identifier),
              try SafeDirectory(path: source).ownIdentity.sameObject(as: original),
              AppInspector.signatureMatches(path: source, identifier: identifier) else { throw SweepError.stale("SDK clone or original changed; retain evidence") }
        let clang = try BoundedProcess.capture(source + "/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang", arguments: ["--version"], timeout: 10, mergeStderr: true)
        guard clang.status == 0 else { throw SweepError.incomplete("Original toolchain did not respond after clone recovery") }
        cleanupAllowed = true
        print("Real large acceptance: \(before.tree.count) entries restored with exact identities and official signatures; original toolchain preserved. Removing only its verified disposable clone.")
    }
}
#endif
