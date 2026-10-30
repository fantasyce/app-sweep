import AppKit
import SwiftUI
import Darwin
@testable import AppSweepCore

#if !DEBUG
#error("Disposable UI state probe must never ship")
#endif

@main
struct OptimizationUIStateProbe {
    @MainActor
    static func main() async throws {
        guard getuid() == 501, CommandLine.arguments.count == 2,
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:5).hasPrefix("VirtualMac") else { throw SweepError.denied("Disposable VM UI probe only") }
        let home = CommandLine.arguments[1]
        let homeURL = URL(fileURLWithPath:home)
        guard home == homeURL.standardizedFileURL.path,
              homeURL.deletingLastPathComponent().path == "/Users/localtest/AppSweepAcceptanceGeneral-20261016/ui-optimization.noindex/fixtures",
              UUID(uuidString:homeURL.lastPathComponent) != nil else { throw SweepError.denied("Registered UI fixture home required") }
        let root = try SafeDirectory(path:home)
        guard try root.ownIdentity.owner == 501 else { throw SweepError.denied("Wrong fixture owner") }
        let app = home + "/Applications/Optimization UI Fixture.app"
        let original = try SafeFilesystem.snapshot(app,allowInternalLinks:true,purpose:.application,allowInternalHardLinks:true)
        func require(_ value: Bool,_ message: String) throws { if !value { throw SweepError.incomplete(message) } }
        @MainActor func model(_ rules: Set<String>) throws -> SweepStore {
            let policy = SafetyPolicy(home:home,acceptedPlatform:true,validatedRules:rules)
            let engine = SweepEngine(policy:policy,vaultPath:home + "/Library/Application Support/App Sweep/Recovery",fixture:false)
            let cleanup = try CleanupCoordinator.fixture(engine:engine,systemFactory:{ throw SweepError.denied("No system service in this UI fixture") })
            return SweepStore(engine:engine,coordinator:cleanup,optimization:try .fixture(policy:policy))
        }
        @MainActor func wait(_ store: SweepStore) async throws {
            let deadline = ProcessInfo.processInfo.systemUptime + 45
            while store.busy {
                guard ProcessInfo.processInfo.systemUptime < deadline else { throw SweepError.incomplete("UI fixture operation timed out") }
                try await Task.sleep(nanoseconds:20_000_000)
            }
        }
        let readOnly = try model([])
        readOnly.selectedApp = app;readOnly.openOptimization()
        readOnly.reviewOptimization(kind:.languages,retainingLanguages:[]);try await wait(readOnly)
        print("UI_READONLY_REVIEW_DIAGNOSTIC: hasReview=\(readOnly.optimizationReview != nil) error=\(readOnly.error) message=\(readOnly.message)")
        try require(readOnly.optimizationReview != nil && readOnly.optimizationReview?.executionAvailable == false,"Read-only review not shown accurately: " + readOnly.message)
        readOnly.executeOptimization();try await wait(readOnly)
        try SafeFilesystem.verify(original)
        readOnly.closeOptimization()

        let store = try model([ApplicationOptimizationEngine.rule,ApplicationOptimizationEngine.languageRule])
        store.workspace = .uninstall;store.selectedApp = app;store.openOptimization()
        let old = try XCTFreeUnwrap(store.optimizationSelection?.id)
        store.reviewOptimization(kind:.languages,retainingLanguages:[])
        store.closeOptimization()
        store.openOptimization()
        let current = try XCTFreeUnwrap(store.optimizationSelection?.id)
        try require(current != old,"Reopened sheet reused cancelled session")
        store.optimizationSheetDisappeared(old)
        try require(store.optimizationSelection?.id == current,"Old sheet disappearance cancelled new session")
        store.reviewOptimization(kind:.languages,retainingLanguages:[]);try await wait(store)
        try require(store.optimizationReview?.executionAvailable == true,"New review lost after cancellation retirement")
        store.invalidateOptimizationReview()
        store.executeOptimization();try await wait(store)
        try SafeFilesystem.verify(original)
        store.reviewOptimization(kind:.languages,retainingLanguages:[]);try await wait(store)
        store.executeOptimization()
        try require(store.busy && !store.canCancel,"Mutation exposed cancellation")
        store.closeOptimization();store.switchWorkspace(.recovery)
        try require(store.optimizationSelection?.id == current && store.workspace == .uninstall,"Active mutation dismissed or switched workspace")
        try await wait(store)
        let published = try XCTFreeUnwrap(store.optimizationResult)
        try require(published.status == .published && store.message.contains("原包保留") && !store.message.contains("已释放"),"Publication result confused retained original with released space")
        let note = home + "/user-note.txt", latest = Data("new user content after UI optimization".utf8)
        try latest.write(to:URL(fileURLWithPath:note))
        store.closeOptimization();store.switchWorkspace(.recovery);try await wait(store)
        try require(store.optimizationHistory.contains(where:{ $0.id == published.id && $0.canRestore }),"Published batch absent from ordinary Recovery")
        store.restoreOptimization(published.id);try await wait(store)
        try require(store.optimizationResult?.status == .restored,"Ordinary Recovery did not restore")
        let restored = try SafeFilesystem.snapshot(app,allowInternalLinks:true,purpose:.application,allowInternalHardLinks:true)
        try require(restored.identity.sameObject(as:original.identity) && restored.tree == original.tree,"Original identity/tree lost")
        try require(try Data(contentsOf:URL(fileURLWithPath:note)) == latest,"Latest user content lost")
        store.selectedApp = app;store.openOptimization()
        store.reviewOptimization(kind:.languages,retainingLanguages:[]);try await wait(store)
        let changedPath = app + "/Contents/Resources/fr.lproj/Localizable.strings"
        try Data("stale source fixture changed before confirmation".utf8).write(to:URL(fileURLWithPath:changedPath))
        let changed = try SafeFilesystem.snapshot(app,allowInternalLinks:true,purpose:.application,allowInternalHardLinks:true)
        store.executeOptimization();try await wait(store)
        try require(store.error && store.optimizationReview == nil,"Failed execution retained executable stale UI plan")
        try SafeFilesystem.verify(changed)
        store.closeOptimization();store.switchWorkspace(.recovery);try await wait(store)
        try require(!store.optimizationHistory.isEmpty,"Failure left no Recovery exit")
        print("UI_OPTIMIZATION_STATE_PROBE_PASSED: readonly, cancellation/session retirement, kind invalidation, critical dismissal, publish, Recovery, latest data, stale-source failure")
    }
    private static func XCTFreeUnwrap<T>(_ value: T?) throws -> T {
        guard let value else { throw SweepError.incomplete("Expected UI fixture value is absent") };return value
    }
}
