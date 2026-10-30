#if os(macOS)
import Foundation
import Darwin
import XCTest
import CFSafety
@testable import AppSweepCore

/// Explicit, staged disposable-VM acceptance. UI and consumer observations are
/// separate from actor results; no default test starts or modifies real apps.
final class RealApplicationOptimizationTests: XCTestCase, @unchecked Sendable {
    private struct Context {
        let name: String, identifier: String, team: String, hash: String
        let originalInode: UInt64
        var app: String { "/Users/localtest/Applications/" + name + ".app" }
        var profileRoots: [String] {
            if name == "Firefox" {
                return ["/Users/localtest/AppSweepAcceptanceGeneral-20261016/official-optimization.noindex/firefox/profile",
                        "/Users/localtest/Library/Application Support/Firefox",
                        "/Users/localtest/Library/Preferences/org.mozilla.firefox.plist"]
            }
            let support = name == "IINA" ? identifier : "Vienna"
            return ["/Users/localtest/Library/Application Support/" + support,
                    "/Users/localtest/Library/Preferences/" + identifier + ".plist"]
        }
    }
    private struct Receipt: Codable {
        let schemaVersion: Int
        let application: String
        let original: ApplicationOptimizationRecord.Object
        let batch: ApplicationOptimizationRecord
        let profileBeforePublish: [String:String]
        let publishProfileVerified: Bool?
        var status: String
    }
    private func context() throws -> (Context,String,SafeDirectory) {
        guard let authorization = ProcessInfo.processInfo.environment["APP_SWEEP_REAL_OPTIMIZATION_ACCEPTANCE"] else {
            throw XCTSkip("Explicit staged official consumer acceptance in disposable VM only")
        }
        guard authorization == "AppSweep-General-20261016", getuid() == 501,
              try SystemIdentity.home() == "/Users/localtest",
              PlatformStamp.current == PlatformStamp(major:27,minor:0,patch:1,build:"26A434",architecture:"arm64"),
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).hasPrefix("VirtualMac") else {
            throw SweepError.denied("Wrong explicitly requested real-consumer acceptance scope")
        }
        let value: Context
        switch ProcessInfo.processInfo.environment["APP_SWEEP_OPTIMIZATION_CONSUMER"] {
        case "IINA", "IINA-repeat", "IINA-stable", "IINA-renderer", "IINA-renderer-verified": value = Context(name:"IINA",identifier:"com.colliderli.iina",team:"67CQ77V27R",hash:"8778dd7b22d0ae53aaea4cd590b82f9831fad70f",originalInode:1143080)
        case "Vienna": value = Context(name:"Vienna",identifier:"uk.co.opencommunity.vienna2",team:"KUU2LM7U9K",hash:"c41a91c5c346817292b71a946b037e7d4e2cc84e",originalInode:279051)
        case "Firefox": value = Context(name:"Firefox",identifier:"org.mozilla.firefox",team:"43AQ936H96",hash:"ed526c2a600dd9c380d4070d81443645834a63c0",originalInode:290231)
        case "Firefox158": value = Context(name:"Firefox",identifier:"org.mozilla.firefox",team:"43AQ936H96",hash:"d16810dfc759aae5b6ae30a493e2908fe56b2c0f",originalInode:7697962)
        default: throw SweepError.denied("Consumer is not a registered disposable-VM input")
        }
        guard let phase = ProcessInfo.processInfo.environment["APP_SWEEP_OPTIMIZATION_PHASE"], ["publish","restore","reconcile","diagnostic-restore"].contains(phase) else { throw SweepError.invalid("Unknown real-consumer transaction phase") }
        let task = try SafeDirectory(path:"/Users/localtest/AppSweepAcceptanceGeneral-20261016")
        let requested = ProcessInfo.processInfo.environment["APP_SWEEP_OPTIMIZATION_CONSUMER"]
        let caseName = ["IINA-repeat":"iina-repeat","IINA-stable":"iina-stable","IINA-renderer":"iina-renderer","IINA-renderer-verified":"iina-renderer-verified","Firefox158":"firefox158"][requested ?? ""] ?? value.name.lowercased()
        let root = try task.existingPrivateChild("official-optimization.noindex")
        if let previousCase = ["iina-repeat":"iina","iina-stable":"iina-repeat","iina-renderer":"iina-stable","iina-renderer-verified":"iina-renderer"][caseName] {
            let previous = try root.existingPrivateChild(previousCase)
            let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
            let receipt = try decoder.decode(Receipt.self,from:SafeFilesystem.readMetadata(previous.path + "/transaction.json"))
            let priorStateOK = receipt.status.hasPrefix("restored;") ||
                (caseName == "iina-renderer-verified" && receipt.status.hasPrefix("stopped;") && receipt.batch.status == .stopped && receipt.batch.prepared == nil)
            guard priorStateOK, receipt.original.identity.inode == value.originalInode else { throw SweepError.denied("Prior operation must be explicitly restored before independent repeat diagnosis") }
            if phase == "publish", try !receipt.original.matches(snapshot(value.app)) {
                throw SweepError.denied("Original must still match before independent repeat publication")
            }
        }
        let directory = try root.existingPrivateChild(caseName)
        guard AppInspector.signedByTeam(path:value.app,team:value.team),
              try ApplicationArchitecturePreparation.signature(value.app,identifier:value.identifier,architecture:"arm64") == value.hash else { throw SweepError.denied("Registered official application identity changed") }
        return (value,phase,directory)
    }
    private func snapshot(_ path: String) throws -> FileSnapshot {
        try SafeFilesystem.snapshot(path,allowInternalLinks:true,purpose:.application,allowInternalHardLinks:true)
    }
    private func profiles(_ roots: [String]) throws -> [String:String] {
        var values: [String:String] = [:]
        for root in roots {
            guard try SafeFilesystem.presence(root) else { values[root+"#presence"] = "missing"; continue }
            let tree = try SafeFilesystem.snapshot(root,allowInternalLinks:true,allowInternalHardLinks:true)
            values[root+"#presence"] = tree.identity.isDirectory ? "directory" : "file"
            let files = tree.identity.isDirectory ? tree.tree.filter { $0.identity.mode & 0o170000 == 0o100000 }.map { root + "/" + $0.relative } : [root]
            for file in files {
                let source = try SafeFilesystem.fileSnapshot(file,in:tree)
                guard source.identity.size <= 128*1024*1024 else { throw SweepError.incomplete("Registered profile fingerprint exceeds acceptance bound") }
                values[file] = try VerifiedFileStream.digest(source)
            }
            try SafeFilesystem.verify(tree)
        }
        return values
    }
    private func observation(_ consumer: Context, phase: String, directory: SafeDirectory) throws {
        let bytes = try SafeFilesystem.readMetadata(directory.path + "/" + phase + "-observation.json",maximumBytes:128*1024)
        let value = try XCTUnwrap(try JSONSerialization.jsonObject(with:bytes)as?[String:Any])
        guard (value["runningProcesses"]as?[String]) == [], value["sourceSwapOrCleanupPerformed"]as?Bool == false,
              let ui = value["UIObservation"]as?String, !ui.isEmpty else { throw SweepError.incomplete("Consumer UI/function or normal shutdown observation is missing") }
        if URL(fileURLWithPath:directory.path).lastPathComponent.hasPrefix("iina-renderer") {
            guard value["functionalAccepted"]as?Bool == true,
                  value["renderingOption"]as?String == "--mpv-gpu-dumb-mode=yes" else {
                throw SweepError.incomplete("Actual visible software-renderer control is missing; decoder-only evidence is insufficient")
            }
        }
        if consumer.name == "IINA" {
            let lines = try XCTUnwrap(value["decoderExcerpts"]as?[String])
            guard lines.contains(where:{$0.contains("Selected decoder: png")}), lines.contains(where:{$0.contains("VO: [libmpv] 64x64 rgba")}),
                  value["mediaSHA256"]as?String == "e0238c96929d9991fe05ffdbe43137f8feae6da4df32f3a6882e488b0f70f8f9" else { throw SweepError.incomplete("Actual independent IINA decoding/output evidence is missing") }
        } else if consumer.name == "Firefox" {
            guard value["functionalAccepted"]as?Bool == true,
                  value["articleRequested"]as?Bool == true,
                  value["expectedArticleObserved"]as?Bool == true,
                  value["phase"]as?String == phase,
                  value["URL"]as?String == "http://127.0.0.1:18747/articles/" + phase else {
                throw SweepError.incomplete("Actual Firefox local article body and ordinary use evidence is missing")
            }
        } else {
            guard value["feedRequested"]as?Bool == true, value["expectedArticleObserved"]as?Bool == true,
                  value["phase"]as?String == phase else { throw SweepError.incomplete("Actual Vienna fetch/article evidence is missing") }
        }
    }
    func testRegisteredConsumerTransactionPhase() async throws {
        let (consumer,phase,directory) = try context()
        try ActivityInspector.ensureStopped(bundleID:consumer.identifier,applicationPath:consumer.app)
        let rules: Set<String> = [ApplicationOptimizationEngine.rule,LocalizedResourceReader.name]
        let engine = ApplicationOptimizationEngine(policy:SafetyPolicy(home:"/Users/localtest",acceptedPlatform:true,validatedRules:rules))
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601; encoder.outputFormatting = [.sortedKeys,.withoutEscapingSlashes]
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        if phase == "reconcile" {
            try observation(consumer,phase:"baseline",directory:directory)
            let prior: Receipt?
            if try SafeFilesystem.presence(directory.path + "/transaction.json") {
                prior = try decoder.decode(Receipt.self,from:SafeFilesystem.readMetadata(directory.path + "/transaction.json"))
            } else { prior = nil }
            let original = try decoder.decode(ApplicationOptimizationRecord.Object.self,from:SafeFilesystem.readMetadata(directory.path + "/original-before-publish.json"))
            let candidates = try await engine.history().filter { $0.applicationPath == consumer.app && $0.identifier == consumer.identifier && $0.nativeCodeHash == consumer.hash && $0.original.identity.inode == consumer.originalInode && $0.original.tree == original.tree && $0.status.unfinished }
            guard candidates.count == 1, let pending = candidates.first else { throw SweepError.incomplete("Interrupted real publication is not uniquely identified") }
            let checked = try await engine.reconcile(batchID:pending.id)
            guard [.published,.restored,.stopped].contains(checked.status) else { throw SweepError.incomplete("Real publication/restoration remains unconfirmed; originals retained: " + checked.id.uuidString) }
            if let prior { guard prior.application == consumer.app, prior.batch.id == checked.id else { throw SweepError.denied("Existing receipt identifies another operation") } }
            if checked.status == .restored || checked.status == .stopped { XCTAssertTrue(try original.matches(snapshot(consumer.app))) }
            // The first interrupted caller did not persist pre-operation profile
            // digests. Do not manufacture that missing comparison after the fact.
            let receipt = Receipt(schemaVersion:1,application:consumer.app,original:original,batch:checked,profileBeforePublish:prior?.profileBeforePublish ?? [:],publishProfileVerified:prior?.publishProfileVerified ?? false,status:checked.status.rawValue + "; explicitly reconciled without moving objects; initial profile comparison unavailable")
            try directory.write(encoder.encode(receipt),name:"transaction.json")
            print("REAL_OPTIMIZATION_RECONCILED=" + checked.id.uuidString + "; no repeat swap; original/installed pair verified; original profile-before evidence unavailable")
            return
        }
        if phase == "publish" {
            try observation(consumer,phase:"baseline",directory:directory)
            guard try !SafeFilesystem.presence(directory.path + "/transaction.json") else { throw SweepError.denied("A consumer transaction already exists; inspect/recover, never silently replay") }
            let original = try snapshot(consumer.app)
            guard original.identity.inode == consumer.originalInode, original.identity.owner == 501 else { throw SweepError.stale("Original official source was replaced") }
            let before = try profiles(consumer.profileRoots)
            let object = try ApplicationOptimizationRecord.Object(original)
            try directory.write(encoder.encode(object),name:"original-before-publish.json")
            try directory.write(encoder.encode(before),name:"profile-before-publish.json")
            let reviewed = try await engine.review(consumer.app)
            let published = try await engine.execute(reviewID:reviewed.id)
            print("REAL_OPTIMIZATION_BATCH=" + published.id.uuidString)
            guard published.status == .published else { throw SweepError.incomplete("Real consumer publication did not complete") }
            let receipt = Receipt(schemaVersion:1,application:consumer.app,original:object,batch:published,profileBeforePublish:before,publishProfileVerified:false,status:"published; actual optimized use still required")
            try directory.write(encoder.encode(receipt),name:"transaction.json")
            guard try profiles(consumer.profileRoots) == before else { throw SweepError.stale("Body optimization changed the stopped application's persistent data") }
            let verifiedReceipt = Receipt(schemaVersion:1,application:consumer.app,original:object,batch:published,profileBeforePublish:before,publishProfileVerified:true,status:receipt.status)
            try directory.write(encoder.encode(verifiedReceipt),name:"transaction.json")
            let installed = try snapshot(consumer.app)
            XCTAssertNotEqual(installed.identity.inode,original.identity.inode)
            XCTAssertLessThan(installed.bytes,original.bytes)
            XCTAssertEqual(try ApplicationArchitecturePreparation.signature(consumer.app,identifier:consumer.identifier,architecture:"arm64"),consumer.hash)
            print("Official consumer published: " + consumer.name + "; original retained; logical reduction " + String(original.bytes-installed.bytes) + "; released bytes0; functional use not yet accepted")
        } else {
            if phase == "diagnostic-restore" {
                guard directory.path.hasSuffix("/iina-repeat") else { throw SweepError.denied("Recovery-only phase is restricted to the registered diagnostic batch") }
            } else { try observation(consumer,phase:"optimized",directory:directory) }
            var receipt = try decoder.decode(Receipt.self,from:SafeFilesystem.readMetadata(directory.path + "/transaction.json"))
            guard receipt.schemaVersion == 1, receipt.application == consumer.app, receipt.batch.applicationPath == consumer.app,
                  receipt.batch.identifier == consumer.identifier, receipt.batch.nativeCodeHash == consumer.hash,
                  receipt.original.identity.inode == consumer.originalInode, receipt.status.hasPrefix("published;") else { throw SweepError.denied("Consumer receipt does not match the registered batch") }
            let before = try profiles(consumer.profileRoots)
            try directory.write(encoder.encode(before),name:"profile-before-restore.json")
            let restored = try await engine.undo(batchID:receipt.batch.id)
            guard restored.status == .restored else { throw SweepError.incomplete("Real consumer restoration did not complete") }
            let original = try snapshot(consumer.app)
            XCTAssertTrue(try receipt.original.matches(original))
            XCTAssertEqual(try profiles(consumer.profileRoots),before,"Undo must preserve newer profile data generated by normal optimized use")
            XCTAssertEqual(try ApplicationArchitecturePreparation.signature(consumer.app,identifier:consumer.identifier,architecture:"arm64"),consumer.hash)
            receipt.status = "restored; actual restored use still required"
            try directory.write(encoder.encode(receipt),name:"transaction.json")
            print("Official consumer original restored: " + consumer.name + "; original inode/content tree/signature checked; latest profile data retained; functional use still required")
        }
    }
}
#endif
