#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore

/// Staged acceptance of the existing, registered disposable-VM Vienna input.
/// Product execution uses ordinary ownership/activity checks, not fixture mode.
final class RealPreferenceWorkflowTests: XCTestCase, @unchecked Sendable {
    private let home="/Users/localtest"
    private let identifier="uk.co.opencommunity.vienna2"
    private var app: String { home + "/Applications/Vienna.app" }
    private var preference: String { home + "/Library/Preferences/" + identifier + ".plist" }
    private struct Receipt: Codable {
        let application: String
        let original: FileIdentity
        let valuesDigest: String
        let retainedFiles: [String:String]
        var batchID: UUID?
        var status: String
    }
    private func context() throws -> (String,SafeDirectory) {
        guard ProcessInfo.processInfo.environment["APP_SWEEP_REAL_PREFERENCE_ACCEPTANCE"] == "AppSweep-General-20261016" else {
            throw XCTSkip("Explicit registered disposable-VM real preference workflow only")
        }
        guard getuid()==501,geteuid()==501,try SystemIdentity.home()==home,
              PlatformStamp.current == PlatformStamp(major:27,minor:0,patch:1,build:"26A434",architecture:"arm64"),
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).hasPrefix("VirtualMac"),
              let phase=ProcessInfo.processInfo.environment["APP_SWEEP_REAL_PREFERENCE_PHASE"],
              ["clear","restore","after-consumer","diagnose"].contains(phase) else { throw SweepError.denied("Wrong real preference acceptance scope") }
        let stage=try SafeDirectory(path:home + "/AppSweepAcceptanceGeneral-20261016/chromium-cache.noindex")
        return (phase,try stage.privateChild("real-vienna-preference-20261019"))
    }
    private func engine(_ directory: SafeDirectory) -> SweepEngine {
        SweepEngine(policy:SafetyPolicy(home:home,acceptedPlatform:true,validatedRules:[ChosenApplicationRule.name,ChosenApplicationRule.largeName,SelectedApplicationRule.name,PreferenceDomainService.rule]),vaultPath:directory.path + "/Recovery",fixture:false)
    }
    private func checkedApp() throws -> FileSnapshot {
        let snapshot=try SafeFilesystem.snapshot(app,allowInternalLinks:true,purpose:.application)
        guard snapshot.identity.inode==279051,snapshot.identity.device==16777228,snapshot.identity.owner==501,
              AppInspector.signatureMatches(path:app,identifier:identifier),AppInspector.signedByTeam(path:app,team:"KUU2LM7U9K") else { throw SweepError.denied("Registered Vienna identity changed") }
        try ActivityInspector.ensureStopped(bundleID:identifier,applicationPath:app)
        try BusyInspector.ensureUnused(snapshot)
        return snapshot
    }
    private func retainedFiles() throws -> [String:String] {
        var result: [String:String]=[:]
        for path in [home + "/Library/Application Support/Vienna",home + "/Library/Caches/" + identifier,home + "/Library/Logs/Vienna"] {
            guard try SafeFilesystem.presence(path) else { result[path + "#presence"]="missing";continue }
            let snapshot=try SafeFilesystem.snapshot(path,allowInternalLinks:true,allowInternalHardLinks:true)
            result[path + "#presence"]=snapshot.identity.isDirectory ? "directory" : "file"
            for file in snapshot.identity.isDirectory ? snapshot.tree.filter({ $0.identity.mode & 0o170000 == 0o100000 }).map({ path + "/" + $0.relative }) : [path] {
                let item=try SafeFilesystem.fileSnapshot(file,in:snapshot)
                guard item.identity.size<=128*1024*1024 else { throw SweepError.incomplete("Registered retained-data check exceeds bound") }
                result[file]=try VerifiedFileStream.digest(item)
            }
            try SafeFilesystem.verify(snapshot)
        }
        return result
    }
    private func write(_ receipt: Receipt, directory: SafeDirectory) throws {
        let encoder=JSONEncoder();encoder.outputFormatting=[.sortedKeys,.withoutEscapingSlashes]
        try directory.write(encoder.encode(receipt),name:"transaction.json")
    }
    func testRegisteredViennaPreferenceTransactionPhase() async throws {
        let (phase,directory)=try context(),e=engine(directory)
        if phase == "diagnose" {
            let locations=try ApplicationRegistry.systemLocations(identifier).map(\.absoluteString)
            let inventory=try AppInspector.inventory(home:home,ownershipIdentifier:identifier)
            let conflicts=inventory.filter { $0.bundleIdentifier.isEmpty || $0.bundleIdentifier.lowercased()==identifier.lowercased() }.map { ["path":$0.path,"identifier":$0.bundleIdentifier,"reason":$0.protectedReason ?? ""] }
            let bytes=try JSONSerialization.data(withJSONObject:["purpose":"read-only registered quarantine ownership diagnosis","registryURLs":locations,"conflicts":conflicts],options:[.sortedKeys])
            try directory.write(bytes,name:"registry-diagnosis.json")
            print("REAL_PREFERENCE_READONLY_DIAGNOSIS=" + String(decoding:bytes,as:UTF8.self))
            return
        }
        if phase == "clear" {
            guard try !SafeFilesystem.presence(directory.path + "/transaction.json") else { throw SweepError.denied("Registered transaction already exists; recover rather than replay") }
            let original=try checkedApp()
            let values=try PreferenceDomainService.inspect(path:preference,home:home,identifier:identifier)
            let dictionary=try XCTUnwrap(try PropertyListSerialization.propertyList(from:values.bytes,format:nil) as? [String:Any])
            XCTAssertFalse(dictionary.isEmpty)
            var receipt=Receipt(application:app,original:original.identity,valuesDigest:values.valuesDigest,retainedFiles:try retainedFiles(),batchID:nil,status:"intent before registered app/settings transaction")
            try directory.write(values.bytes,name:"original-settings.plist")
            try write(receipt,directory:directory)
            let report=try await e.scanApplication(app)
            let body=try XCTUnwrap(report.candidates.first { $0.path==app && $0.category == .application })
            let settings=try XCTUnwrap(report.candidates.first { $0.path==preference && $0.rule==PreferenceDomainService.rule })
            XCTAssertFalse(settings.selectedByDefault)
            guard settings.allowed,settings.executionAllowed else { throw SweepError.incomplete("Registered native settings not executable") }
            let plan=try await e.makePlan(reportID:report.id,selected:[body.id,settings.id],includeUserData:true)
            XCTAssertEqual(plan.items.count,2,"Unselected feeds, support data, cache and logs must not enter this plan")
            let batch=try await e.execute(planID:plan.id)
            receipt.batchID=batch.id;receipt.status=batch.status.rawValue;try write(receipt,directory:directory)
            XCTAssertEqual(batch.status,.isolated,batch.issue ?? batch.entries.compactMap(\.message).joined(separator:";"))
            guard batch.status == .isolated else { return }
            XCTAssertFalse(try SafeFilesystem.presence(app))
            let empty=try PreferenceDomainService.inspect(path:preference,home:home,identifier:identifier)
            XCTAssertEqual(empty.valuesDigest,try PreferenceDomainService.valuesDigest(PropertyListSerialization.data(fromPropertyList:[String:String](),format:.binary,options:0)))
            XCTAssertEqual(try retainedFiles(),receipt.retainedFiles)
            print("REAL_PREFERENCE_CLEAR actualNativeValuesEmpty=true unselectedDataUnchanged=true batch=\(batch.id)")
            return
        }
        var receipt=try JSONDecoder().decode(Receipt.self,from:directory.read("transaction.json"))
        guard receipt.application==app,receipt.original.inode==279051,let batchID=receipt.batchID else { throw SweepError.denied("Registered workflow receipt missing or changed") }
        if phase == "restore" {
            guard [RecoveryManifest.Status.isolated.rawValue,RecoveryManifest.Status.needsAttention.rawValue].contains(receipt.status) else { throw SweepError.denied("Registered transaction not ready for explicit restore") }
            let batch=try await e.restore(batchID:batchID)
            receipt.status=batch.status.rawValue;try write(receipt,directory:directory)
            XCTAssertEqual(batch.status,.restored,batch.issue ?? batch.entries.compactMap(\.message).joined(separator:";"))
            guard batch.status == .restored else { return }
            XCTAssertTrue(receipt.original.sameObject(as:try checkedApp().identity))
            let values=try PreferenceDomainService.inspect(path:preference,home:home,identifier:identifier)
            XCTAssertEqual(values.valuesDigest,receipt.valuesDigest,"Fresh native reader must see original typed values, including fractional dates")
            XCTAssertEqual(try retainedFiles(),receipt.retainedFiles)
            print("REAL_PREFERENCE_RESTORE actualValuesMatch=true originalAppIdentity=true unselectedDataUnchanged=true freshEngine=true batch=\(batchID)")
        } else {
            guard receipt.status==RecoveryManifest.Status.restored.rawValue else { throw SweepError.denied("Registered transaction not restored") }
            _ = try checkedApp()
            // Opening the actual consumer may legitimately change timestamps,
            // window state and feeds. The separately captured GUI observation
            // verifies its setting and baseline article, not byte equality here.
            let observation=try XCTUnwrap(try JSONSerialization.jsonObject(with:directory.read("consumer-observation.json")) as? [String:Any])
            guard observation["startupRefreshDisabled"] as? Bool == true,
                  observation["baselineArticleVisible"] as? Bool == true,
                  observation["normalQuit"] as? Bool == true else { throw SweepError.incomplete("Actual reopened Vienna GUI evidence missing") }
            receipt.status="restored; actual consumer setting and baseline article verified after normal reopen/quit"
            try write(receipt,directory:directory)
            print("REAL_PREFERENCE_CONSUMER verified=true normalQuit=true batch=\(batchID)")
        }
    }
}
#endif
