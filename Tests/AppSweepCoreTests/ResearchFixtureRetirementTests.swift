#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

/// Task-owned research copies only. No product rule or arbitrary-path endpoint.
/// Originals are retired only after a separately extracted archive is verified.
final class ResearchFixtureRetirementTests: XCTestCase, @unchecked Sendable {
    private struct Receipt: Codable {
        let source: String
        let originalIdentity: FileIdentity
        let originalTree: TreeFingerprint
        var stage: String
        var archiveDigest: String?
        var verifiedFiles: Int?
    }
    func testRetireVerifiedObsoleteTaskApplicationCopiesIntoPrivateArchives() async throws {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_RETIRE_RESEARCH_APPS"] == "1",
              try BoundedProcess.run("/usr/sbin/sysctl", arguments: ["-n", "hw.model"], timeout: 3).hasPrefix("VirtualMac") else { throw XCTSkip("Explicit disposable VM task fixture retirement") }
        let home = try SystemIdentity.home(), task = home + "/AppSweepAcceptanceGeneral-20261016"
        let fixture = try String(contentsOfFile: task + "/ui-fixture-home.txt", encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        guard fixture.hasPrefix(task + "/fixtures/"), UUID(uuidString: URL(fileURLWithPath: fixture).lastPathComponent) != nil else { throw SweepError.invalid("Owned fixture marker invalid") }
        let retireHungFixture = ProcessInfo.processInfo.environment["APP_SWEEP_RETIRE_HUNG_FIXTURE"] == "1"
        let fixtureID = ProcessInfo.processInfo.environment["APP_SWEEP_RETIRE_FIXTURE_UUID"] ?? "C102EA48-B680-45ED-BAFB-E4244CBA241F"
        guard UUID(uuidString:fixtureID)?.uuidString == fixtureID,
              let expectedInode = UInt64(ProcessInfo.processInfo.environment["APP_SWEEP_RETIRE_FIXTURE_INODE"] ?? "2127522") else { throw SweepError.invalid("Exact task fixture identity receipt is invalid") }
        let hungHome = task + "/fixtures.noindex/" + fixtureID
        if retireHungFixture {
            let identity = try SafeDirectory(path:hungHome).ownIdentity
            guard identity.owner == getuid(), identity.inode == expectedInode,
                  try SafeFilesystem.presence(hungHome + "/wait-ready"),
                  try SafeFilesystem.presence(hungHome + "/release-wait") else { throw SweepError.stale("Sampled hung fixture identity or lifecycle evidence changed") }
        }
        let sources: [(String, String, String?)] = retireHungFixture ? [
            (hungHome + "/Applications/Disposable Fixture.app", "org.example.sweepfixture", "1.0")
        ] : [
            (task + "/consumers/firefox-current-158/Firefox.app", "org.mozilla.firefox", "158.0"),
            (task + "/consumers/vienna-current-3.10.8/Vienna.app", "uk.co.opencommunity.vienna2", "3.10.8 :0294d207:"),
            (fixture + "/Applications/Firefox.app", "org.mozilla.firefox", nil)
        ]
        let store = try SafeDirectory(path: task).privateChild("retired-research.noindex")
        for (path, identifier, version) in sources {
            guard try SafeFilesystem.presence(path) else { print("Previously retired task path remains absent: " + path); continue }
            let snapshot = try SafeFilesystem.snapshot(path, allowInternalLinks: true, purpose: .application)
            guard snapshot.identity.owner == getuid(), snapshot.tree.allSatisfy({ $0.identity.owner == getuid() }) else { throw SweepError.denied("Research copy has unexpected owner") }
            let info = try AppInspector.metadata(path, component: false).0
            guard info["CFBundleIdentifier"] as? String == identifier else { throw SweepError.denied("Research copy ID changed") }
            if let version {
                guard info["CFBundleShortVersionString"] as? String == version, AppInspector.signatureMatches(path: path, identifier: identifier) else { throw SweepError.denied("Official research version/signature changed") }
            } else {
                guard snapshot.bytes < 4096, Set(snapshot.tree.map(\.relative)) == ["Contents", "Contents/Info.plist"], info["CFBundleExecutable"] == nil else { throw SweepError.denied("Old metadata-only mock changed") }
            }
            try BusyInspector.ensureUnused(snapshot)
            let operation = try store.privateChild(UUID().uuidString)
            let archive = operation.path + "/bundle.zip", extracted = try operation.privateChild("verified-extraction.noindex")
            var receipt = Receipt(source: path, originalIdentity: snapshot.identity, originalTree: try TreeFingerprint.capture(snapshot.tree), stage: "prepared")
            func persist() throws { try operation.write(JSONEncoder().encode(receipt), name: "receipt.json") }
            try persist()
            guard try !SafeFilesystem.presence(archive) else { throw SweepError.denied("Archive already exists") }
            _ = try BoundedProcess.run("/usr/bin/ditto", arguments: ["-c", "-k", "--sequesterRsrc", "--keepParent", path, archive], timeout: 30)
            receipt.archiveDigest = try VerifiedFileStream.digest(SafeFilesystem.snapshot(archive)); receipt.stage = "archived"; try persist()
            _ = try BoundedProcess.run("/usr/bin/ditto", arguments: ["-x", "-k", archive, extracted.path], timeout: 30)
            let restoredPath = extracted.path + "/" + URL(fileURLWithPath: path).lastPathComponent
            let restored = try SafeFilesystem.snapshot(restoredPath, allowInternalLinks: true, purpose: .application)
            guard snapshot.tree.map(\.relative) == restored.tree.map(\.relative) else { throw SweepError.stale("Archive extraction contents differ") }
            var verified = 0
            for (original, copy) in zip(snapshot.tree, restored.tree) {
                guard original.identity.mode == copy.identity.mode, original.identity.owner == copy.identity.owner else { throw SweepError.stale("Archived metadata changed") }
                let originalPath = path + "/" + original.relative, copyPath = restoredPath + "/" + copy.relative
                if original.identity.mode & 0o170000 == 0o100000 {
                    guard try VerifiedFileStream.digest(SafeFilesystem.snapshot(originalPath)) == VerifiedFileStream.digest(SafeFilesystem.snapshot(copyPath)) else { throw SweepError.stale("Archived bytes differ") }
                    verified += 1
                } else if original.identity.isLink {
                    guard try FileManager.default.destinationOfSymbolicLink(atPath: originalPath) == FileManager.default.destinationOfSymbolicLink(atPath: copyPath) else { throw SweepError.stale("Archived link target changed") }
                }
            }
            if version != nil { guard AppInspector.signatureMatches(path: restoredPath, identifier: identifier) else { throw SweepError.denied("Extracted official signature invalid") } }
            receipt.verifiedFiles = verified; receipt.stage = "extraction-verified"; try persist()
            try SafeFilesystem.verify(snapshot); try BusyInspector.ensureUnused(snapshot)
            let parent = try SafeDirectory(path: URL(fileURLWithPath: path).deletingLastPathComponent().path)
            guard try SafeFilesystem.ancestors(of: parent.path) == snapshot.ancestors,
                  SafeFilesystem.removeVerified(in: parent, name: URL(fileURLWithPath: path).lastPathComponent, identity: snapshot.identity, contents: snapshot.tree) else { throw SweepError.filesystem("Task copy retirement stopped; verified archive retained") }
            guard try !SafeFilesystem.presence(path) else { throw SweepError.stale("Retired research path still exists") }
            receipt.stage = "retired-original-archive-and-verified-extraction-retained"; try persist()
            print("Retired task-only research source: " + path + "; receipt=" + operation.path + "/receipt.json; files=" + String(verified))
        }
        print("Official current applications and all test profiles/cache/recovery data retained; no registrations, indexes or services changed")
    }
}
#endif
