// Independent acceptance driver, compiled only with the debug core inside a disposable VM.
// It is never included in the product executables or used on the primary host.
import Foundation
import Darwin
@testable import AppSweepCore

@main
struct InterruptionHarness {
    static func main() async throws {
        guard getuid() != 0,
              try BoundedProcess.run("/usr/sbin/sysctl", arguments: ["-n", "hw.model"], timeout: 3).hasPrefix("VirtualMac"),
              CommandLine.arguments.count == 3,
              let id = UUID(uuidString: CommandLine.arguments[2]), id.uuidString == CommandLine.arguments[2] else { fatalError("Disposable VM and explicit fixture UUID required") }
        let base = try SystemIdentity.home() + "/AppSweepAcceptance/fixtures/samples.noindex"
        _ = try SafeDirectory(path: base)
        let home = base + "/" + id.uuidString
        let source = home + "/Library/Caches/org.example.fixture"
        let mode = CommandLine.arguments[1]
        let payload = Data("owned recoverable interruption fixture".utf8)
        if mode == "prepare" {
            guard try !SafeFilesystem.presence(home) else { fatalError("Fixture must be new") }
            try FileManager.default.createDirectory(atPath: source, withIntermediateDirectories: true)
            try payload.write(to: URL(fileURLWithPath: source + "/data"))
            let snapshot = try SafeFilesystem.snapshot(source)
            let candidate = Candidate(id: UUID(), path: source, category: .cache, bundleIdentifier: "org.example.fixture", evidence: [.init(kind: .validatedRule, detail: "Disposable interruption fixture", verified: true)], rule: "fixture-v1", identity: snapshot.identity, bytes: snapshot.bytes, retentionReason: nil)
            let engine = SweepEngine(policy: SafetyPolicy(home: home, acceptedPlatform: true), vaultPath: home + "/vault", failurePoint: .interruptAfterMove)
            let report = await engine.adoptFixture([candidate], snapshots: [candidate.id:snapshot])
            let plan = try await engine.makePlan(reportID: report.id, selected: [candidate.id], includeUserData: false)
            do { _ = try await engine.execute(planID: plan.id); fatalError("Interruption not injected") }
            catch { }
            let batches = try await engine.recoveryBatches()
            guard batches.count == 1, batches[0].status == .inProgress, batches[0].entries.first?.state == .prepared,
                  try !SafeFilesystem.presence(source) else { fatalError("Durable pending move was not established") }
            let ready: [String:Any] = ["fixture":id.uuidString, "batch":batches[0].id.uuidString, "pid":ProcessInfo.processInfo.processIdentifier, "status":"durable prepared move; awaiting owned process termination"]
            try JSONSerialization.data(withJSONObject: ready, options: [.sortedKeys]).write(to: URL(fileURLWithPath: home + "/ready.json"))
            while true { try await Task.sleep(nanoseconds: 1_000_000_000) }
        } else if mode == "verify" {
            let engine = SweepEngine(policy: SafetyPolicy(home: home, acceptedPlatform: true), vaultPath: home + "/vault")
            let batches = try await engine.recoveryBatches()
            guard batches.count == 1, batches[0].status == .inProgress, batches[0].entries.first?.state == .prepared,
                  try !SafeFilesystem.presence(source) else { fatalError("Restart must retain pending intent without resuming") }
            let restored = try await engine.restore(batchID: batches[0].id)
            guard restored.status == .restored,
                  try Data(contentsOf: URL(fileURLWithPath: source + "/data")) == payload else { fatalError("Recovery failed") }
            print("PASS: pending journal survives termination; no automatic continuation; exact payload restored for " + id.uuidString)
        } else { fatalError("Unknown harness mode") }
    }
}
