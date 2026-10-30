#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore

final class SystemServiceSessionTests: XCTestCase, @unchecked Sendable {
    private func fixture() throws -> (NativeAcceptanceTests.NativeFixture,SystemCleanupScope,String) {
        let f = try NativeAcceptanceTests.NativeFixture(), library = f.home + "/MachineLibrary"
        let support = f.home + "/Library/Application Support/App Sweep"
        try FileManager.default.createDirectory(atPath: support + "/backups", withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: support)
        let identifier="org.example.systemsession." + UUID().uuidString.lowercased(),metadata=f.app + "/Contents/Info.plist"
        var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:metadata)),format:nil)as? [String:Any])
        info["CFBundleIdentifier"]=identifier
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:metadata))
        _=try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",f.app],timeout:10)
        let root = library + "/Caches/" + identifier
        try FileManager.default.createDirectory(atPath:root,withIntermediateDirectories:true)
        let path = root + "/payload"
        try Data("owned service fixture".utf8).write(to:URL(fileURLWithPath:path))
        return (f,try SystemCleanupScope.fixture(libraryRoot:library,applicationsRoot:f.home + "/Applications",userHome:f.home,requesterUID:getuid()),path)
    }
    private var peer: AuthenticatedLocalPeer { .init(uid:getuid(),pid:getpid(),auditToken:Data(repeating:9,count:32)) }
    private let nonce = Data(repeating:8,count:32)
    private func request(_ action: PrivilegedAction,_ sequence: UInt64) -> PrivilegedRequest {
        .init(protocolVersion:1,id:UUID(),nonce:nonce,sequence:sequence,action:action)
    }
    func testUnreadableIgnorePolicyReturnsUnconfirmedScanAndKeepsStatusAvailable() async throws {
        let (f, scope, path) = try fixture(); defer { try? f.clean() }
        let settings = f.home + "/Library/Application Support/App Sweep/Settings.noindex"
        try FileManager.default.createDirectory(atPath: settings, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try Data("invalid policy".utf8).write(to: URL(fileURLWithPath: settings + "/cleanup-ignores.json"))
        let service = try SystemServiceSession.fixture(scope: scope, peer: peer, nonce: nonce)
        guard case .scan(let report) = try await service.acceptFixture(request(.scan(category: .caches), 1), peer: peer) else { return XCTFail("Expected an explicit incomplete scan") }
        XCTAssertFalse(report.complete)
        XCTAssertTrue(report.candidates.isEmpty)
        XCTAssertFalse(report.issues.isEmpty)
        guard case .status = try await service.acceptFixture(request(.status, 2), peer: peer) else { return XCTFail("Read-only scan error must not discard the connection") }
        do { _ = try await service.acceptFixture(request(.review(scanID: report.id, candidateIDs: [UUID()]), 3), peer: peer); XCTFail("Failed scan must not authorize a plan") } catch { }
        XCTAssertTrue(FileManager.default.fileExists(atPath: path))
    }
    func testServiceUsesTheActualEnginePlanAndFreshSessionRestoresItsBatch() async throws {
        let (f,scope,path) = try fixture(); defer { try? f.clean() }
        let service = try SystemServiceSession.fixture(scope:scope,peer:peer,nonce:nonce)
        guard case .status(let status) = try await service.acceptFixture(request(.status,1),peer:peer) else { return XCTFail("Expected service status") }
        XCTAssertTrue(status.executionEnabled)
        guard case .scan(let report) = try await service.acceptFixture(request(.scan(category:.caches),2),peer:peer) else { return XCTFail("Expected service-owned scan") }
        let items = report.selectableCandidates(includeUserData:false)
        XCTAssertEqual(items.map(\.path),[path],report.unconfirmedIssues.joined(separator:"; "))
        guard case .plan(let plan) = try await service.acceptFixture(request(.review(scanID:report.id,candidateIDs:items.map(\.id)),3),peer:peer) else { return XCTFail("Expected reviewed engine plan") }
        XCTAssertEqual(plan.reportID,report.id); XCTAssertEqual(plan.items,items)
        guard case .batch(let batch) = try await service.acceptFixture(request(.execute(planID:plan.id),4),peer:peer) else { return XCTFail("Expected transaction result") }
        XCTAssertEqual(batch.status,.isolated,batch.issue ?? "")
        XCTAssertFalse(FileManager.default.fileExists(atPath:path))
        do { _ = try await service.acceptFixture(request(.execute(planID:plan.id),5),peer:peer); XCTFail("Service plan must be one-use") } catch { }
        let fresh = try SystemServiceSession.fixture(scope:scope,peer:peer,nonce:nonce)
        do { _ = try await fresh.acceptFixture(request(.execute(planID:plan.id),1),peer:peer); XCTFail("A new connection cannot inherit an old executable plan") } catch { }
        guard case .batches(let batches) = try await fresh.acceptFixture(request(.batches,2),peer:peer) else { return XCTFail("Expected scoped recovery list") }
        XCTAssertEqual(batches.items.map(\.id),[batch.id])
        guard case .batch(let detail) = try await fresh.acceptFixture(request(.batch(batchID:batch.id),3),peer:peer) else { return XCTFail("Expected selected batch detail") }
        XCTAssertEqual(detail.id,batch.id); XCTAssertEqual(detail.entries.map(\.id),batch.entries.map(\.id))
        guard case .batches(let end) = try await fresh.acceptFixture(request(.nextBatches(after:batch.id),4),peer:peer) else { return XCTFail("Expected final page") }
        XCTAssertTrue(end.items.isEmpty); XCTAssertNil(end.nextCursor)
        guard case .batch(let restored) = try await fresh.acceptFixture(request(.restore(batchID:batch.id),5),peer:peer) else { return XCTFail("Expected normal recovery") }
        XCTAssertEqual(restored.status,.restored)
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:path)),Data("owned service fixture".utf8))
    }
    func testCredentialChangesReplayAndUnknownSelectionCannotMoveAnySource() async throws {
        let (f,scope,path) = try fixture(); defer { try? f.clean() }
        let service = try SystemServiceSession.fixture(scope:scope,peer:peer,nonce:nonce)
        let first = request(.scan(category:.caches),1)
        let changed = AuthenticatedLocalPeer(uid:peer.uid,pid:peer.pid,auditToken:Data(repeating:7,count:32))
        do { _ = try await service.acceptFixture(first,peer:changed); XCTFail("Changed kernel identity must not use the connection") } catch { }
        guard case .scan(let report) = try await service.acceptFixture(first,peer:peer) else { return XCTFail("Valid identity should still scan") }
        do { _ = try await service.acceptFixture(first,peer:peer); XCTFail("Replay must fail") } catch { }
        do { _ = try await service.acceptFixture(request(.review(scanID:report.id,candidateIDs:[UUID()]),2),peer:peer); XCTFail("Unknown candidates must fail") } catch { }
        do { _ = try await service.acceptFixture(request(.execute(planID:UUID()),3),peer:peer); XCTFail("Unknown plans must fail") } catch { }
        XCTAssertEqual(try Data(contentsOf:URL(fileURLWithPath:path)),Data("owned service fixture".utf8))
        guard case .batches(let batches) = try await service.acceptFixture(request(.batches,4),peer:peer) else { return XCTFail("Expected no transactions") }
        XCTAssertTrue(batches.items.isEmpty)
        do { _ = try await service.accept(request(.status,5)); XCTFail("A fixture must not impersonate an authenticated socket") } catch { }
    }
}
#endif
