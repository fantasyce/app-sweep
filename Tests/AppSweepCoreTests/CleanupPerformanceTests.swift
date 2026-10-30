#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

private final class PerformanceProgress: @unchecked Sendable {
    private let lock = NSLock()
    private var first: TimeInterval?
    func record(_ value: ScanProgress) {
        guard value.completedReports.values.contains(where: { !$0.candidates.isEmpty }) else { return }
        lock.lock(); defer { lock.unlock() }
        if first == nil { first = ProcessInfo.processInfo.systemUptime }
    }
    var firstCompleted: TimeInterval? { lock.lock(); defer { lock.unlock() }; return first }
}

final class CleanupPerformanceTests: XCTestCase {
    func testTwentyApplicationsAndTwentyThousandFilesHaveBoundedVisibleResults() throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        let fm = FileManager.default
        for index in 0..<20 {
            let app = f.home + "/Applications/Performance-\(index).app"
            try fm.copyItem(atPath: f.app, toPath: app)
            let id = "org.example.performance.p\(index)"
            let info = app + "/Contents/Info.plist"
            var data = try XCTUnwrap(try PropertyListSerialization.propertyList(from: Data(contentsOf: URL(fileURLWithPath: info)), format: nil) as? [String: Any])
            data["CFBundleIdentifier"] = id
            try PropertyListSerialization.data(fromPropertyList: data, format: .xml, options: 0).write(to: URL(fileURLWithPath: info))
            _ = try BoundedProcess.run("/usr/bin/codesign", arguments: ["--force", "--sign", "-", app], timeout: 10)
            let payload = f.home + "/Library/Caches/" + id + "/payload"
            try fm.createDirectory(atPath: payload, withIntermediateDirectories: true)
            for leaf in 0..<1000 {
                try Data("independent cache \(index)/\(leaf)".utf8).write(to: URL(fileURLWithPath: payload + "/\(leaf).bin"))
            }
        }
        // Remove only the fixture's original template, leaving exactly 20 apps.
        try fm.removeItem(atPath: f.app)
        let progress = PerformanceProgress(), start = ProcessInfo.processInfo.systemUptime
        let output = try Scanner(policy: SafetyPolicy(home: f.home, acceptedPlatform: true, validatedRules: [CacheDomainRule.name, UserCacheNamespaceRule.name])).junk(indexLookup: { _ in [] }, progress: { progress.record($0) })
        let elapsed = ProcessInfo.processInfo.systemUptime - start
        let first = try XCTUnwrap(progress.firstCompleted) - start
        let payloads = output.report.candidates.filter { $0.path.hasSuffix("/payload") }
        XCTAssertEqual(payloads.count, 20, output.report.unconfirmedIssues.joined(separator: "; "))
        XCTAssertTrue(payloads.allSatisfy { $0.identity != nil && $0.bytes > 0 }, "Samples must be inspected, not merely retained as hints")
        XCTAssertLessThanOrEqual(first, 5)
        XCTAssertLessThanOrEqual(elapsed, 120)
        XCTAssertTrue(output.report.complete, output.report.unconfirmedIssues.joined(separator: "; "))
        print("PERFORMANCE apps=20 files=20000 firstScopeSeconds=\(first) totalSeconds=\(elapsed)")
    }
}
#endif
