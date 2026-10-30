#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore

/// Staged ordinary-user consumer acceptance only. Absent opt-in is a skip;
/// an incorrect explicit request fails, and never becomes a production rule.
final class ApplicationLanguageConsumerAcceptanceTests: XCTestCase, @unchecked Sendable {
    private struct Consumer {
        let name: String, identifier: String, team: String, nativeHash: String, directory: String
        let originalInode: UInt64
        var app: String { "/Users/localtest/Applications/" + name + ".app" }
        var profileRoots: [String] {
            var roots = ["/Users/localtest/Library/Application Support/" + identifier,
                         "/Users/localtest/Library/Preferences/" + identifier + ".plist"]
            if name == "CotEditor" {
                roots += ["/Users/localtest/Library/Application Support/CotEditor",
                          "/Users/localtest/Library/Containers/com.coteditor.CotEditor/Data/Library/Preferences/com.coteditor.CotEditor.plist",
                          "/Users/localtest/Library/Containers/com.coteditor.CotEditor/Data/Library/Application Support/CotEditor",
                          "/Users/localtest/AppSweepAcceptanceGeneral-20261016/official-optimization.noindex/coteditor712-language-20261020/consumer-document.txt"]
            }
            return roots
        }
    }
    private struct Trial: Codable {
        let original: ApplicationOptimizationRecord.Object
        var batch: ApplicationOptimizationRecord
        let profilesBeforePublish: [String:String]
        var state: String
    }
    private func snapshot(_ path: String) throws -> FileSnapshot {
        try SafeFilesystem.snapshot(path,allowInternalLinks:true,purpose:.application,allowInternalHardLinks:true)
    }
    private func profiles(_ consumer: Consumer) throws -> [String:String] {
        var values: [String:String] = [:]
        for root in consumer.profileRoots {
            guard try SafeFilesystem.presence(root) else { values[root + "#presence"] = "absent";continue }
            let tree = try snapshot(root)
            values[root + "#presence"] = tree.identity.isDirectory ? "directory" : "file"
            let files = tree.identity.isDirectory ? tree.tree.filter { $0.identity.mode & 0o170000 == 0o100000 }.map { root + "/" + $0.relative } : [root]
            for file in files {
                let item = try SafeFilesystem.fileSnapshot(file,in:tree)
                guard item.identity.size <= 128*1024*1024 else { throw SweepError.incomplete("Registered profile exceeds fingerprint bound") }
                values[file] = try VerifiedFileStream.digest(item)
            }
            try SafeFilesystem.verify(tree)
        }
        return values
    }
    private func observation(_ consumer: Consumer, phase: String, directory: SafeDirectory) throws {
        let decoded = try JSONSerialization.jsonObject(with:directory.read(phase + "-observation.json"))
        let value = try XCTUnwrap(decoded as? [String:Any])
        guard value["functionalAccepted"] as? Bool == true, value["normalExitObserved"] as? Bool == true,
              ["menuQuit","NSRunningApplication.terminate"].contains(value["terminationMethod"] as? String ?? ""),
              value["forceTerminationUsed"] as? Bool == false,
              value["runningProcesses"] as? [String] == [], value["nativeHash"] as? String == consumer.nativeHash,
              value["sourceSwapOrCleanupPerformed"] as? Bool == false else { throw SweepError.incomplete("Actual source, consumer function and normal shutdown evidence missing") }
        if consumer.name == "IINA" {
            guard value["renderingOption"] as? String == "--mpv-gpu-dumb-mode=yes",
                  value["factoryDefaultRenderingAccepted"] as? Bool == false,
                  value["mediaSHA256"] as? String == "e0238c96929d9991fe05ffdbe43137f8feae6da4df32f3a6882e488b0f70f8f9",
                  let lines = value["decoderExcerpts"] as? [String],
                  lines.contains(where:{ $0.contains("Selected decoder: png") }),
                  lines.contains(where:{ $0.contains("VO: [libmpv] 64x64 rgba") }) else { throw SweepError.incomplete("Actual same-renderer control and decoding proof missing") }
        } else if consumer.name == "CotEditor" {
            guard value["actualDocumentReadAndSaved"] as? Bool == true,
                  value["documentSHA256"] as? String != nil else { throw SweepError.incomplete("Actual native text editing/save evidence missing") }
        }
    }
    func testInspectAndStopRegisteredUnpublishedPreparation() async throws {
        guard let request = ProcessInfo.processInfo.environment["APP_SWEEP_LANGUAGE_PREPARATION_INSPECTION"] else {
            throw XCTSkip("Explicit registered failed preparation inspection only")
        }
        guard request == "AppSweep-General-20261016:DEA598D6-F5A2-48A1-A835-CFE4B223AD0E", getuid() == 501,
              try SystemIdentity.home() == "/Users/localtest",
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:5).hasPrefix("VirtualMac") else { throw SweepError.denied("Wrong explicit preparation inspection") }
        let engine = ApplicationOptimizationEngine(policy:SafetyPolicy(home:"/Users/localtest",acceptedPlatform:true,validatedRules:[ApplicationOptimizationEngine.languageRule,LocalizedResourceReader.name]))
        let id = try XCTUnwrap(UUID(uuidString:"DEA598D6-F5A2-48A1-A835-CFE4B223AD0E"))
        let history = try await engine.history()
        let record = try XCTUnwrap(history.first { $0.id == id })
        guard record.status == .preparing, record.prepared == nil, record.rule == ApplicationOptimizationEngine.languageRule,
              record.applicationPath == "/Users/localtest/Applications/IINA.app", record.original.identity.inode == 1143080 else { throw SweepError.denied("Registered unpublished failure changed") }
        let installed = try snapshot(record.applicationPath)
        let partialPath = "/Users/localtest/Library/Application Support/App Sweep/Optimization.noindex/" + id.uuidString + "/" + id.uuidString
        let partial = try snapshot(partialPath)
        guard partial.identity.inode == 10206540, try record.original.matches(installed) else { throw SweepError.stale("Original or registered partial changed") }
        let partialObject = try ApplicationOptimizationRecord.Object(partial)
        print("LANGUAGE_UNPUBLISHED_ROOT_DIAGNOSTIC: originalMatches=true; partialRootMetadataMatches=" + String(partialObject.rootMetadata == record.original.rootMetadata) + "; partialBytes=" + String(partial.bytes))
        let stopped = try await engine.reconcile(batchID:id)
        XCTAssertEqual(stopped.status,.stopped)
        XCTAssertTrue(try record.original.matches(snapshot(record.applicationPath)))
        XCTAssertTrue(try partialObject.matches(snapshot(partialPath)))
        print("LANGUAGE_UNPUBLISHED_PREPARATION_STOPPED_WITHOUT_APP_MOVE_OR_DELETION=" + id.uuidString)
    }
    func testRegisteredLanguageConsumerPhase() async throws {
        guard let request = ProcessInfo.processInfo.environment["APP_SWEEP_LANGUAGE_TRANSACTION_ACCEPTANCE"] else {
            throw XCTSkip("Explicit staged registered native language consumer only")
        }
        let parts = request.split(separator:":").map(String.init)
        guard parts.count == 3, parts[0] == "AppSweep-General-20261016", ["publish","restore"].contains(parts[2]),
              getuid() == 501, try SystemIdentity.home() == "/Users/localtest",
              PlatformStamp.current == .init(major:27,minor:0,patch:1,build:"26A434",architecture:"arm64"),
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:5).hasPrefix("VirtualMac") else { throw SweepError.denied("Wrong explicit language consumer scope") }
        let consumer: Consumer
        switch parts[1] {
        case "IINA":consumer = .init(name:"IINA",identifier:"com.colliderli.iina",team:"67CQ77V27R",nativeHash:"8778dd7b22d0ae53aaea4cd590b82f9831fad70f",directory:"iina-language-20261020",originalInode:1143080)
        case "CotEditor":consumer = .init(name:"CotEditor",identifier:"com.coteditor.CotEditor",team:"HT3Z3A72WZ",nativeHash:"1aa1bc260c6326e9aae8c11f85498d6f17eab51c",directory:"coteditor712-language-20261020",originalInode:10203270)
        default:throw SweepError.denied("Unregistered language consumer")
        }
        let publishing = parts[2] == "publish"
        let directory = try SafeDirectory(path:"/Users/localtest/AppSweepAcceptanceGeneral-20261016/official-optimization.noindex").existingPrivateChild(consumer.directory)
        try observation(consumer,phase:publishing ? "baseline" : "optimized",directory:directory)
        guard AppInspector.signedByTeam(path:consumer.app,team:consumer.team),
              try ApplicationArchitecturePreparation.signature(consumer.app,identifier:consumer.identifier,architecture:"arm64") == consumer.nativeHash else { throw SweepError.stale("Registered official consumer signature changed") }
        try ActivityInspector.ensureStopped(bundleID:consumer.identifier,applicationPath:consumer.app)
        let engine = ApplicationOptimizationEngine(policy:SafetyPolicy(home:"/Users/localtest",acceptedPlatform:true,validatedRules:[ApplicationOptimizationEngine.languageRule,LocalizedResourceReader.name]))
        let encoder = JSONEncoder();encoder.dateEncodingStrategy = .iso8601;encoder.outputFormatting = [.sortedKeys]
        let decoder = JSONDecoder();decoder.dateDecodingStrategy = .iso8601
        if publishing {
            guard try !SafeFilesystem.presence(directory.path + "/trial.json") else { throw SweepError.denied("No replay of registered real publication") }
            let source = try snapshot(consumer.app)
            guard source.identity.inode == consumer.originalInode else { throw SweepError.stale("Original consumer replaced") }
            let original = try ApplicationOptimizationRecord.Object(source), before = try profiles(consumer)
            if try SafeFilesystem.presence(directory.path + "/original-before-publish.json") {
                let prior = try decoder.decode(ApplicationOptimizationRecord.Object.self,from:directory.read("original-before-publish.json"))
                let priorProfiles = try decoder.decode([String:String].self,from:directory.read("profiles-before-publish.json"))
                guard try prior.matches(source), priorProfiles == before else { throw SweepError.stale("Pre-publication original or profile changed; preserve previous evidence") }
            } else {
                guard try !SafeFilesystem.presence(directory.path + "/profiles-before-publish.json") else { throw SweepError.incomplete("Pre-publication evidence is incomplete") }
                try directory.write(encoder.encode(original),name:"original-before-publish.json")
                try directory.write(encoder.encode(before),name:"profiles-before-publish.json")
            }
            let review = try await engine.reviewLanguages(consumer.app,retaining:["en","zh-Hans-CN"])
            let batch = try await engine.execute(reviewID:review.id)
            let trial = Trial(original:original,batch:batch,profilesBeforePublish:before,state:"published; actual language consumer function pending")
            try directory.write(encoder.encode(trial),name:"trial.json")
            XCTAssertEqual(batch.status,.published);XCTAssertEqual(batch.rule,"application-language-transaction-v1")
            XCTAssertEqual(try profiles(consumer),before)
            XCTAssertLessThan(try snapshot(consumer.app).bytes,source.bytes)
            print("LANGUAGE_CONSUMER_PUBLISHED=" + consumer.name + ":" + batch.id.uuidString + "; actual use pending; original retained")
        } else {
            var trial = try decoder.decode(Trial.self,from:directory.read("trial.json"))
            guard trial.state.hasPrefix("published;"), trial.batch.applicationPath == consumer.app,
                  trial.batch.rule == ApplicationOptimizationEngine.languageRule, trial.batch.nativeCodeHash == consumer.nativeHash,
                  trial.original.identity.inode == consumer.originalInode else { throw SweepError.denied("Registered trial batch changed") }
            let before = try profiles(consumer)
            trial.batch = try await engine.undo(batchID:trial.batch.id);trial.state = "restored; actual language consumer function pending"
            try directory.write(encoder.encode(trial),name:"trial.json")
            XCTAssertEqual(trial.batch.status,.restored);XCTAssertTrue(try trial.original.matches(snapshot(consumer.app)))
            XCTAssertEqual(try profiles(consumer),before)
            print("LANGUAGE_CONSUMER_RESTORED=" + consumer.name + ":" + trial.batch.id.uuidString + "; latest profile preserved; actual use pending")
        }
    }
}
#endif
