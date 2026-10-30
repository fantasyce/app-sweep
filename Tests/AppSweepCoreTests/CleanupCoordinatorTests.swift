#if os(macOS)
import Foundation
import Darwin
import XCTest
@testable import AppSweepCore
@testable import AppSweepApp

/// Ordinary-user socket transport and actual on-disk engines. No production
/// endpoint, root authority or real user data is injected by this fixture.
actor CoordinatorServiceFixture {
    let scope: SystemCleanupScope
    private var servers: [Task<Void,Never>] = []
    private var counter: UInt8 = 1
    let unexpectedCacheResult: Bool
    let closeOnLogScan: Bool
    private(set) var scannedCategories: [SystemCleanupCategory] = []
    func recordScan(_ category:SystemCleanupCategory) { scannedCategories.append(category) }
    init(scope: SystemCleanupScope,unexpectedCacheResult: Bool = false,closeOnLogScan:Bool=false) { self.scope = scope; self.unexpectedCacheResult = unexpectedCacheResult;self.closeOnLogScan=closeOnLogScan }
    func connect() async throws -> SystemServiceClient {
        let peer = AuthenticatedLocalPeer(uid:getuid(),pid:getpid(),auditToken:Data(repeating:4,count:32))
        let nonce = Data(repeating:counter,count:32); counter &+= 1
        let session = try SystemServiceSession.fixture(scope:scope,peer:peer,nonce:nonce)
        var sockets: [Int32] = [-1,-1]
        guard socketpair(AF_UNIX,SOCK_STREAM,0,&sockets) == 0 else { throw SweepError.filesystem("Coordinator socketpair") }
        let serverSocket = sockets[0], clientSocket = sockets[1], unexpected = unexpectedCacheResult
        servers.append(Task.detached {
            defer { close(serverSocket) }
            do {
                try LocalControlChannel.write(SystemServiceReply.hello(nonce:nonce),socket:serverSocket)
                for _ in 0..<32 {
                    let request = try PrivilegedFrame.decode(await LocalControlChannel.readWhenReady(socket:serverSocket,deadline:ProcessInfo.processInfo.systemUptime + 60))
                    if case .scan(let category) = request.action {
                        await self.recordScan(category)
                        if category == .logs, await self.closeOnLogScan { break }
                    }
                    var result = try await session.acceptFixture(request,peer:peer)
                    if unexpected, case .execute = request.action, case .batch(var batch) = result,
                       batch.entries.first?.original.category == .cache {
                        // Fault at the reply boundary. Actual private recovery
                        // data remains intact and must be inspected/restored.
                        batch.status = .purged; result = .batch(batch)
                    }
                    let reply = try SystemServiceReply.prepare(result,for:request)
                    for index in 0..<reply.partCount { try LocalControlChannel.write(reply.frame(at:index),socket:serverSocket) }
                }
            } catch { /* Closing on failure is the real protocol's indeterminate-result case. */ }
        })
        return try await SystemServiceClient.fixture(socket:clientSocket)
    }
    func finish() async { for server in servers { await server.value } }
}

private actor CoordinatorConnectionGate {
    private var continuation: CheckedContinuation<Void,Never>?
    private var released = false
    private(set) var entered = false
    func wait() async {
        entered = true
        if released { return }
        await withCheckedContinuation { continuation = $0 }
    }
    func release() { released = true; continuation?.resume(); continuation = nil }
}

final class CleanupCoordinatorTests: XCTestCase, @unchecked Sendable {
    func testLaterBrokenTransportRevokesEarlierSystemSelectionsButKeepsUserFindings() async throws {
        let p = try prepared(closeOnLogScan:true); defer { try? p.fixture.clean() }
        do {
            let overview = try await p.coordinator.scanJunk()
            XCTAssertTrue(overview.selectableCandidates(includeUserData:false).contains{$0.path == p.userCache})
            XCTAssertFalse(overview.selectableCandidates(includeUserData:false).contains{$0.path == p.systemCache},"A report on a closed authenticated connection must not look actionable")
            let cache = try XCTUnwrap(overview.candidates.first{$0.path == p.systemCache})
            XCTAssertFalse(cache.allowedActions.contains(.reviewPlan))
            XCTAssertTrue(FileManager.default.fileExists(atPath:p.systemCache))
            await finish(p)
        } catch { await finish(p); throw error }
    }
    func testInsufficientReadBudgetPreservesTheAuthenticatedConnection() async throws {
        let p = try prepared(); defer { try? p.fixture.clean() }
        do {
            let overview = try await p.coordinator.scanJunk(maximumDuration:16)
            let categories = await p.hub.scannedCategories
            XCTAssertTrue(categories.isEmpty,"Do not start a native system scan with too little time for its bounded ownership inventory; that can revoke earlier reports on the same connection")
            XCTAssertTrue(overview.sections.filter{$0.source != .user}.allSatisfy{$0.report == nil && $0.issue != nil})
            await finish(p)
        } catch { await finish(p); throw error }
    }
    private struct Prepared {
        let fixture: NativeAcceptanceTests.NativeFixture
        let hub: CoordinatorServiceFixture
        let coordinator: CleanupCoordinator
        let userCache: String
        let systemCache: String
        let systemLog: String
    }
    private func prepared(unexpectedCacheResult: Bool = false,closeOnLogScan:Bool=false) throws -> Prepared {
        let f = try NativeAcceptanceTests.NativeFixture(additionalRules:[CacheDomainRule.name])
        let identifier="org.example.coordinator." + UUID().uuidString.lowercased()
        let metadata=f.app + "/Contents/Info.plist"
        var info=try XCTUnwrap(try PropertyListSerialization.propertyList(from:Data(contentsOf:URL(fileURLWithPath:metadata)),format:nil)as? [String:Any])
        info["CFBundleIdentifier"]=identifier
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:metadata))
        _=try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",f.app],timeout:10)
        let library = f.home + "/MachineLibrary"
        let user = f.home + "/Library/Caches/\(identifier)/payload"
        let cache = library + "/Caches/\(identifier)/payload"
        let log = library + "/Logs/\(identifier)/old.log"
        for (path,bytes) in [(user,"user cache"),(cache,"system cache"),(log,"old system log")] {
            try FileManager.default.createDirectory(atPath:URL(fileURLWithPath:path).deletingLastPathComponent().path,withIntermediateDirectories:true)
            try Data(bytes.utf8).write(to:URL(fileURLWithPath:path))
        }
        try FileManager.default.setAttributes([.modificationDate:Date().addingTimeInterval(-45*86400)],ofItemAtPath:log)
        let scope = try SystemCleanupScope.fixture(libraryRoot:library,applicationsRoot:f.home + "/Applications",userHome:f.home,requesterUID:getuid())
        let hub = CoordinatorServiceFixture(scope:scope,unexpectedCacheResult:unexpectedCacheResult,closeOnLogScan:closeOnLogScan)
        let coordinator = try CleanupCoordinator.fixture(engine:f.engine,systemFactory:{ try await hub.connect() })
        return Prepared(fixture:f,hub:hub,coordinator:coordinator,userCache:user,systemCache:cache,systemLog:log)
    }
    private func finish(_ p: Prepared) async {
        await p.coordinator.close(); await p.hub.finish()
    }
    @MainActor
    private func waitForStore(_ store: SweepStore) async throws {
        let deadline = ProcessInfo.processInfo.systemUptime + 120
        while store.busy && ProcessInfo.processInfo.systemUptime < deadline { try await Task.sleep(for:.milliseconds(50)) }
        XCTAssertFalse(store.busy,"UI operation must finish within a bounded interval")
    }
    @MainActor
    func testUIUninstallInvalidatesOnlyMovedBundleRowsAndRefreshesAfterUndo() async throws {
        let f = try NativeAcceptanceTests.NativeFixture(); defer { try? f.clean() }
        // This test checks bundle rows, not residue discovery. Existing native
        // consumers with the shared fixture ID are independent installations.
        let identifier="org.example.uiuninstall."+UUID().uuidString.lowercased(),metadata=f.app+"/Contents/Info.plist"
        var info=try AppInspector.metadata(f.app,component:false).0;info["CFBundleIdentifier"]=identifier
        try PropertyListSerialization.data(fromPropertyList:info,format:.xml,options:0).write(to:URL(fileURLWithPath:metadata))
        _=try BoundedProcess.run("/usr/bin/codesign",arguments:["--force","--sign","-",f.app],timeout:10)
        try await f.waitUntilUnused(f.app)
        let coordinator = try CleanupCoordinator.fixture(engine:f.engine,systemFactory:{ throw SweepError.denied("Fixture system unavailable") })
        do {
            let store = SweepStore(engine:f.engine,coordinator:coordinator)
            let helper = f.app + "/Contents/Helpers/Embedded.app"
            let neighbour = f.app + " Copy.app"
            let otherInstall = f.home + "/Applications/Second.app"
            let rows = [f.app,helper,neighbour,otherInstall,otherInstall + "/Contents/Helpers/Embedded.app"]
            store.apps = rows.map { ApplicationIdentity(path:$0,name:"Fixture",bundleIdentifier:identifier,signed:true,protectedReason:nil) }
            store.workspace = .uninstall; store.selectedApp = f.app
            store.scan(); try await waitForStore(store)
            XCTAssertTrue(store.canReview,store.message+"; "+(store.report?.candidates.compactMap(\.retentionReason).joined(separator:"; ") ?? "no report"))
            store.review(); try await waitForStore(store)
            XCTAssertNotNil(store.plan,store.message)
            store.execute(); try await waitForStore(store)
            let batches = try await f.engine.recoveryBatches()
            let batch = try XCTUnwrap(batches.first { $0.status == .isolated })
            XCTAssertFalse(FileManager.default.fileExists(atPath:f.app))
            XCTAssertEqual(store.apps.map(\.path),[neighbour,otherInstall,otherInstall + "/Contents/Helpers/Embedded.app"],"Only the moved bundle and its contained display rows may disappear; a name prefix or matching bundle ID is insufficient")
            XCTAssertNil(store.selectedApp)
            try await f.waitForIsolatedObjects(batch)
            store.switchWorkspace(.recovery); try await waitForStore(store)
            store.selectRecovery("user/" + batch.id.uuidString); try await waitForStore(store)
            store.restore(); try await waitForStore(store)
            XCTAssertEqual(store.currentBatch?.status,.restored,store.message)
            XCTAssertTrue(store.apps.isEmpty,"A restored application must invalidate the old catalog so re-entering uninstall performs fresh discovery")
            XCTAssertTrue(FileManager.default.fileExists(atPath:f.app))
            await coordinator.close()
        } catch { await coordinator.close(); throw error }
    }
    @MainActor
    func testUICleanupKeepsRemainingScanAcrossRecoveryAndAllowsNextBatch() async throws {
        let p = try prepared(); defer { try? p.fixture.clean() }
        do {
            let store = SweepStore(engine:p.fixture.engine,coordinator:p.coordinator)
            store.scan(); try await waitForStore(store)
            let initial = try XCTUnwrap(store.overview)
            let user = try XCTUnwrap(initial.candidates.first { $0.path == p.userCache && $0.allowed })
            let system = try XCTUnwrap(initial.candidates.first { $0.path == p.systemCache && $0.allowed })
            store.clearSelection(); store.select(user,enabled:true)
            store.review(); try await waitForStore(store)
            store.execute(); try await waitForStore(store)
            XCTAssertEqual(store.workspace,.junk)
            let remaining = try XCTUnwrap(store.overview,"Successful cleanup must preserve the other scan results")
            XCTAssertEqual(remaining.id,initial.id)
            XCTAssertFalse(remaining.candidates.contains { $0.id == user.id })
            XCTAssertTrue(remaining.candidates.contains { $0.id == system.id })
            XCTAssertTrue(store.selected.isEmpty)
            store.switchWorkspace(.recovery); try await waitForStore(store)
            store.switchWorkspace(.junk); try await waitForStore(store)
            XCTAssertEqual(store.overview?.id,initial.id,"Read-only recovery navigation must not discard the scan")
            store.select(system,enabled:true); store.review(); try await waitForStore(store)
            XCTAssertEqual(store.combinedReview?.items.map(\.id),[system.id],store.message)
            store.execute(); try await waitForStore(store)
            XCTAssertEqual(store.workspace,.junk)
            XCTAssertFalse(store.overview?.candidates.contains { $0.id == system.id } ?? true)
            await finish(p)
        } catch { await finish(p); throw error }
    }

    @MainActor
    func testPreflightRejectionPreservesScanAndSelectionWithoutRecoveryBatch() async throws {
        let p=try prepared();defer{try? p.fixture.clean()}
        do {
            let store=SweepStore(engine:p.fixture.engine,coordinator:p.coordinator)
            store.scan();try await waitForStore(store)
            let initial=try XCTUnwrap(store.overview)
            let item=try XCTUnwrap(initial.candidates.first{$0.path==p.userCache && $0.allowed})
            store.clearSelection();store.select(item,enabled:true)
            store.review();try await waitForStore(store)
            XCTAssertNotNil(store.combinedReview,store.message)
            try Data("changed after review".utf8).write(to:URL(fileURLWithPath:p.userCache))
            store.execute();try await waitForStore(store)
            XCTAssertTrue(store.error)
            XCTAssertEqual(store.overview?.id,initial.id,"No file was changed by the operation")
            XCTAssertEqual(store.selected,[item.id])
            XCTAssertNil(store.combinedReview,"A rejected plan cannot be executed twice")
            XCTAssertEqual(try String(contentsOfFile:p.userCache,encoding:.utf8),"changed after review")
            let batches=try await p.fixture.engine.recoveryBatches();XCTAssertTrue(batches.isEmpty)
            await finish(p)
        } catch { await finish(p);throw error }
    }

    @MainActor
    func testUIRecentExecutionRemainsReachableBeyondFirstRecoveryPage() async throws {
        let p = try prepared(); defer { try? p.fixture.clean() }
        do {
            // Older records deliberately sort before the new random batch ID.
            // Finding the last operation must not require paging through them.
            let support = try SafeDirectory(path:p.fixture.home + "/Library/Application Support")
            let vault = try support.privateChild("App Sweep").privateChild("Recovery")
            let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
            for number in 1...16 {
                let id = try XCTUnwrap(UUID(uuidString:String(format:"00000000-0000-0000-0000-%012d",number)))
                let record = RecoveryManifest(schemaVersion:3,id:id,createdAt:Date(timeIntervalSince1970:1),status:.restored,entries:[],issue:nil)
                try vault.privateChild(id.uuidString).write(encoder.encode(record),name:"manifest.json")
            }
            let store = SweepStore(engine:p.fixture.engine,coordinator:p.coordinator)
            store.scan(); try await waitForStore(store)
            store.review(); try await waitForStore(store)
            store.execute(); try await waitForStore(store)
            XCTAssertEqual(store.recentRecovery.count,3)
            let batches = try await p.fixture.engine.recoveryBatches()
            let recent = try XCTUnwrap(batches.first { $0.status == .isolated })
            let key = "user/" + recent.id.uuidString
            store.switchWorkspace(.recovery); try await waitForStore(store)
            XCTAssertNotNil(store.recoveryRows.first { $0.id == key },"The just-executed batch must remain directly reachable beyond page one")
            store.selectRecovery(key); try await waitForStore(store)
            XCTAssertEqual(store.currentBatch?.id,recent.id)
            store.restore(); try await waitForStore(store)
            XCTAssertEqual(store.currentBatch?.status,.restored)
            XCTAssertEqual(store.recoveryRows.first { $0.id == key }?.summary.status,.restored,"Refreshing the recent entry must read the current record, not the execution result")
            XCTAssertEqual(try String(contentsOfFile:p.userCache,encoding:.utf8),"user cache")
            // System batches are separate namespaces and remain independently reversible.
            for row in store.recoveryRows.filter({ $0.origin == .system && $0.summary.status == .isolated }) {
                store.selectRecovery(row.id); try await waitForStore(store)
                store.restore(); try await waitForStore(store)
            }
            await finish(p)
        } catch { await finish(p); throw error }
    }
    @MainActor
    func testUIRecentRecordFailureCannotReuseItsStaleRowOrAuthority() async throws {
        let p = try prepared(); defer { try? p.fixture.clean() }
        do {
            let store = SweepStore(engine:p.fixture.engine,coordinator:p.coordinator)
            store.scan(); try await waitForStore(store)
            store.review(); try await waitForStore(store)
            store.execute(); try await waitForStore(store)
            let records = try await p.fixture.engine.recoveryBatches()
            let batch = try XCTUnwrap(records.first { $0.status == .isolated })
            let key = "user/" + batch.id.uuidString
            let path = p.fixture.home + "/Library/Application Support/App Sweep/Recovery/" + batch.id.uuidString + "/manifest.json"
            let held = p.fixture.home + "/held-recovery-manifest.json"
            try FileManager.default.moveItem(atPath:path,toPath:held)
            store.loadRecovery(); try await waitForStore(store)
            XCTAssertNil(store.recoveryRows.first { $0.id == key })
            XCTAssertTrue(store.recoveryIssues.contains { $0.contains("本次操作未确认") })
            XCTAssertTrue(store.recoveryExecutionOrigins.contains(.user),"One damaged batch must not revoke the platform capability for every other user batch; the stale row itself remains unavailable")
            XCTAssertTrue(store.recoveryExecutionOrigins.contains(.system),"Another authenticated origin must remain available")
            store.selectRecovery(key); try await waitForStore(store)
            XCTAssertNil(store.currentBatch); XCTAssertFalse(store.recoveryExecutionAvailable)
            try FileManager.default.moveItem(atPath:held,toPath:path)
            store.loadRecovery(); try await waitForStore(store)
            XCTAssertNotNil(store.recoveryRows.first { $0.id == key })
            store.selectRecovery(key); try await waitForStore(store)
            store.restore(); try await waitForStore(store)
            XCTAssertEqual(store.currentBatch?.status,.restored)
            await finish(p)
        } catch { await finish(p); throw error }
    }
    @MainActor
    func testUIRecentHistoryStaysBoundedWithoutHidingOlderPagedHistory() async throws {
        let p = try prepared(); defer { try? p.fixture.clean() }
        let partial = try CleanupCoordinator.fixture(engine:p.fixture.engine,systemFactory:{ throw SweepError.denied("Fixture system unavailable") })
        do {
            let store = SweepStore(engine:p.fixture.engine,coordinator:partial)
            var firstExecutedBatch: UUID?
            for number in 0..<9 {
                if number > 0 { try Data("generation \(number)".utf8).write(to:URL(fileURLWithPath:p.userCache)) }
                store.scan(); try await waitForStore(store)
                store.review(); try await waitForStore(store)
                store.execute(); try await waitForStore(store)
                XCTAssertFalse(FileManager.default.fileExists(atPath:p.userCache),store.message)
                if number == 0 {
                    let firstRecords = try await p.fixture.engine.recoveryBatches()
                    XCTAssertEqual(firstRecords.count,1)
                    firstExecutedBatch = try XCTUnwrap(firstRecords.first?.id)
                }
            }
            let batches = try await p.fixture.engine.recoveryBatches()
            XCTAssertEqual(batches.count,9)
            XCTAssertEqual(store.recentRecovery.count,8)
            // Persisted ISO8601 timestamps have second precision. Several
            // operations can share a timestamp; date-sorted history cannot
            // identify the first operation in this test.
            let oldest = try XCTUnwrap(firstExecutedBatch)
            XCTAssertFalse(store.recentRecovery.contains { $0.batchID == oldest })
            store.switchWorkspace(.recovery); try await waitForStore(store)
            XCTAssertEqual(Set(store.recoveryRows.filter { $0.origin == .user }.map { $0.summary.id }),Set(batches.map(\.id)),"Trimming the recent display must not trim durable history")
            await partial.close(); await finish(p)
        } catch { await partial.close(); await finish(p); throw error }
    }
    @MainActor
    func testUIJunkWorkflowUsesAllSourcesAndOriginBoundRecovery() async throws {
        let p = try prepared(); defer { try? p.fixture.clean() }
        do {
            let store = SweepStore(engine:p.fixture.engine,coordinator:p.coordinator)
            store.scan(); try await waitForStore(store)
            XCTAssertNil(store.report,"Junk flow must use the combined overview, not a user-only report")
            XCTAssertEqual(store.overview?.sections.count,3)
            XCTAssertEqual(store.selected.count,3,store.message)
            XCTAssertTrue(store.canReview,store.message)
            store.review(); try await waitForStore(store)
            XCTAssertEqual(store.combinedReview?.items.count,3,store.message)
            store.execute(); try await waitForStore(store)
            for path in [p.userCache,p.systemCache,p.systemLog] { XCTAssertFalse(FileManager.default.fileExists(atPath:path),store.message) }
            XCTAssertEqual(store.workspace,.junk)
            XCTAssertNotNil(store.completionNotice)
            store.switchWorkspace(.recovery); try await waitForStore(store)
            XCTAssertEqual(store.recoveryRows.count,3,store.message)
            XCTAssertEqual(Set(store.recoveryRows.map(\.origin)),[.user,.system])
            let rows = store.recoveryRows
            for row in rows {
                store.selectRecovery(row.id); try await waitForStore(store)
                XCTAssertEqual(store.currentBatch?.id,row.summary.id)
                XCTAssertEqual(store.currentBatch?.schemaVersion,row.origin == .user ? RecoveryManifest.currentSchemaVersion : RecoveryManifest.systemSchemaVersion)
                store.restore(); try await waitForStore(store)
                XCTAssertFalse(store.error,store.message)
            }
            for (path,bytes) in [(p.userCache,"user cache"),(p.systemCache,"system cache"),(p.systemLog,"old system log")] {
                XCTAssertEqual(try String(contentsOfFile:path,encoding:.utf8),bytes)
            }
            await finish(p)
        } catch { await finish(p); throw error }
    }
    @MainActor
    func testUIPartialScopeKeepsUserCheckboxAndRecoveryExplicit() async throws {
        let p = try prepared(); defer { try? p.fixture.clean() }
        let support = p.fixture.home + "/Library/Application Support/App Sweep"
        try FileManager.default.createDirectory(atPath: support + "/backups", withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: support)
        let partial = try CleanupCoordinator.fixture(engine:p.fixture.engine,systemFactory:{ throw SweepError.denied("Fixture system unavailable") })
        do {
            let store = SweepStore(engine:p.fixture.engine,coordinator:partial)
            store.scan(); try await waitForStore(store)
            XCTAssertFalse(try XCTUnwrap(store.overview).complete)
            XCTAssertTrue(store.error)
            let candidate = try XCTUnwrap(store.overview?.selectableCandidates(includeUserData:false).first)
            store.select(candidate,enabled:false); XCTAssertFalse(store.canReview)
            store.select(candidate,enabled:true); XCTAssertTrue(store.canReview)
            store.review(); try await waitForStore(store)
            XCTAssertFalse(try XCTUnwrap(store.combinedReview).retainedIssues.isEmpty)
            store.execute(); try await waitForStore(store)
            XCTAssertFalse(FileManager.default.fileExists(atPath:p.userCache))
            XCTAssertFalse(try XCTUnwrap(store.overview).complete,"Unconfirmed scopes stay visible in the retained scan")
            XCTAssertTrue(store.completionNotice?.contains("移入恢复区") == true)
            store.switchWorkspace(.recovery); try await waitForStore(store)
            XCTAssertFalse(store.recoveryIssues.isEmpty)
            XCTAssertFalse(store.recoveryExecutionOrigins.contains(.system))
            XCTAssertTrue(store.recoveryExecutionOrigins.contains(.user))
            let row = try XCTUnwrap(store.recoveryRows.first)
            store.selectRecovery(row.id); try await waitForStore(store)
            store.restore(); try await waitForStore(store)
            XCTAssertEqual(try String(contentsOfFile:p.userCache,encoding:.utf8),"user cache")
            await partial.close(); await finish(p)
        } catch { await partial.close(); await finish(p); throw error }
    }
    @MainActor
    func testUICancelThenRescanWaitsForRetiringCoordinatorOperation() async throws {
        let p = try prepared(); defer { try? p.fixture.clean() }
        do {
            let store = SweepStore(engine:p.fixture.engine,coordinator:p.coordinator)
            store.scan(); store.cancel(); store.scan()
            try await waitForStore(store)
            XCTAssertEqual(store.overview?.sections.count,3,store.message)
            XCTAssertTrue(store.canReview,store.message)
            store.review(); try await waitForStore(store)
            let oldReview = try XCTUnwrap(store.combinedReview)
            store.switchWorkspace(.uninstall)
            try await waitForStore(store)
            XCTAssertNil(store.combinedReview)
            XCTAssertNotNil(store.overview,"Navigation keeps the scan but discards the reviewed execution request")
            do { _ = try await p.coordinator.execute(reviewID:oldReview.id); XCTFail("Switching workspace must invalidate the executor review too") } catch { }
            for path in [p.userCache,p.systemCache,p.systemLog] { XCTAssertTrue(FileManager.default.fileExists(atPath:path)) }
            await finish(p)
        } catch { await finish(p); throw error }
    }
    func testPersonalArchivesRemainOutsideDefaultGarbageDiscovery() async throws {
        let f = try DeletedUserArchiveTests.Fixture(); defer { try? f.clean() }
        let path = try f.image("appsweeparchive" + UUID().uuidString.replacingOccurrences(of: "-", with: ""))
        let bytes = try Data(contentsOf: URL(fileURLWithPath: path))
        let user = SweepEngine(policy: SafetyPolicy(home: f.home, acceptedPlatform: true), vaultPath: f.home + "/UserRecovery", fixture: false)
        let hub = CoordinatorServiceFixture(scope: f.scope)
        let coordinator = try CleanupCoordinator.fixture(engine: user, systemFactory: { try await hub.connect() })
        do {
            let overview = try await coordinator.scanJunk()
            XCTAssertFalse(overview.candidates.contains { $0.path == path })
            let categories = await hub.scannedCategories
            XCTAssertEqual(categories, [.caches, .logs])
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), bytes)
            await coordinator.close(); await hub.finish()
        } catch { await coordinator.close(); await hub.finish(); throw error }
    }
    func testThreeSourcesExecuteOnlyReviewedSelectionAndRestoreThroughTheirOwnEngines() async throws {
        let p = try prepared(); defer { try? p.fixture.clean() }
        do {
            let overview = try await p.coordinator.scanJunk()
            XCTAssertEqual(overview.sections.map(\.source),[.user,.systemCaches,.systemLogs])
            XCTAssertTrue(overview.complete,overview.unconfirmedIssues.joined(separator:"; "))
            let candidates = overview.selectableCandidates(includeUserData:false)
            XCTAssertEqual(Set(candidates.map(\.path)),[p.userCache,p.systemCache,p.systemLog])
            let selected = Set(candidates.map(\.id))
            do { _ = try await p.coordinator.review(overviewID:UUID(),selected:selected,includeUserData:false); XCTFail("Unknown overview cannot grant authority") } catch { }
            let review = try await p.coordinator.review(overviewID:overview.id,selected:selected,includeUserData:false)
            XCTAssertEqual(Set(review.items.map(\.path)),[p.userCache,p.systemCache,p.systemLog])
            let result = try await p.coordinator.execute(reviewID:review.id)
            XCTAssertEqual(result.status,.isolated)
            XCTAssertEqual(result.batches.map(\.source),[.user,.systemCaches,.systemLogs])
            XCTAssertTrue(result.uncertainSources.isEmpty)
            for path in [p.userCache,p.systemCache,p.systemLog] { XCTAssertFalse(FileManager.default.fileExists(atPath:path)) }
            do { _ = try await p.coordinator.execute(reviewID:review.id); XCTFail("A reviewed group must be consumed once") } catch { }
            for record in result.batches.reversed() {
                let restored = try await p.coordinator.restore(source:record.source,batchID:record.manifest.id)
                XCTAssertEqual(restored.status,.restored)
            }
            XCTAssertEqual(try String(contentsOfFile:p.userCache,encoding:.utf8),"user cache")
            XCTAssertEqual(try String(contentsOfFile:p.systemCache,encoding:.utf8),"system cache")
            XCTAssertEqual(try String(contentsOfFile:p.systemLog,encoding:.utf8),"old system log")
            await finish(p)
        } catch { await finish(p); throw error }
    }
    func testUnavailableSystemComponentKeepsUserSelectionAndReportsTheMissingScope() async throws {
        let p = try prepared(); defer { try? p.fixture.clean() }
        let coordinator = try CleanupCoordinator.fixture(engine:p.fixture.engine,systemFactory:{ throw SweepError.denied("Fixture component unavailable") })
        do {
            let overview = try await coordinator.scanJunk()
            XCTAssertFalse(overview.complete)
            XCTAssertFalse(overview.unconfirmedIssues.isEmpty)
            XCTAssertEqual(overview.selectableCandidates(includeUserData:false).map(\.path),[p.userCache])
            let review = try await coordinator.review(overviewID:overview.id,selected:Set(overview.selectableCandidates(includeUserData:false).map(\.id)),includeUserData:false)
            let result = try await coordinator.execute(reviewID:review.id)
            XCTAssertEqual(result.status,.isolated)
            XCTAssertEqual(result.batches.map(\.source),[.user])
            XCTAssertFalse(result.retainedIssues.isEmpty,"A selected user batch must not turn an unavailable system scan into complete success")
            let restored = try await coordinator.restore(source:.user,batchID:try XCTUnwrap(result.batches.first).manifest.id)
            XCTAssertEqual(restored.status,.restored)
            XCTAssertEqual(try String(contentsOfFile:p.systemCache,encoding:.utf8),"system cache")
            await coordinator.close(); await finish(p)
        } catch { await coordinator.close(); await finish(p); throw error }
    }
    func testOriginBoundHistoryDetailsRestoreAndPurgeUseTheirOwnNamespaces() async throws {
        let p = try prepared(); defer { try? p.fixture.clean() }
        do {
            let overview = try await p.coordinator.scanJunk()
            let review = try await p.coordinator.review(overviewID:overview.id,selected:Set(overview.selectableCandidates(includeUserData:false).map(\.id)),includeUserData:false)
            _ = try await p.coordinator.execute(reviewID:review.id)
            let history = try await p.coordinator.historyPage()
            XCTAssertTrue(history.issues.isEmpty,history.issues.joined(separator:"; "))
            XCTAssertEqual(history.rows.filter { $0.origin == .user }.count,1)
            XCTAssertEqual(history.rows.filter { $0.origin == .system }.count,2)
            XCTAssertEqual(Set(history.rows.map(\.id)).count,3)
            for row in history.rows {
                let detail = try await p.coordinator.recoveryDetail(origin:row.origin,batchID:row.summary.id)
                XCTAssertEqual(detail.id,row.summary.id)
                XCTAssertEqual(detail.schemaVersion,row.origin == .user ? RecoveryManifest.currentSchemaVersion : RecoveryManifest.systemSchemaVersion)
                do { _ = try await p.coordinator.purgeRecovery(origin:row.origin,batchID:row.summary.id,confirmation:"yes"); XCTFail("Every origin requires explicit exact purge confirmation") } catch { }
                let restored = try await p.coordinator.restoreRecovery(origin:row.origin,batchID:row.summary.id)
                XCTAssertEqual(restored.status,.restored)
                if restored.canPurge {
                    let purged = try await p.coordinator.purgeRecovery(origin:row.origin,batchID:row.summary.id,confirmation:"永久清空 " + row.summary.id.uuidString)
                    XCTAssertEqual(purged.status,.purged)
                }
            }
            for (path,bytes) in [(p.userCache,"user cache"),(p.systemCache,"system cache"),(p.systemLog,"old system log")] {
                XCTAssertEqual(try String(contentsOfFile:path,encoding:.utf8),bytes)
            }
            await finish(p)
        } catch { await finish(p); throw error }
    }
    func testSystemHistoryPaginationDoesNotRepeatUserRowsOrCollideWithUserBatchIDs() async throws {
        let p = try prepared(); defer { try? p.fixture.clean() }
        do {
            let overview = try await p.coordinator.scanJunk()
            let review = try await p.coordinator.review(overviewID:overview.id,selected:Set(overview.selectableCandidates(includeUserData:false).map(\.id)),includeUserData:false)
            let result = try await p.coordinator.execute(reviewID:review.id)
            XCTAssertEqual(result.batches.count, 3, "Pagination setup must contain all three actual transactions: " + overview.candidates.compactMap(\.retentionReason).joined(separator: "; ") + overview.unconfirmedIssues.joined(separator: "; ") + (result.issue ?? ""))
            let userID = try XCTUnwrap(result.batches.first { $0.source == .user }).manifest.id
            let vault = try p.hub.scope.openVault(create:false)
            let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
            for id in [userID] + (0..<17).map({ _ in UUID() }) {
                var manifest = RecoveryManifest(schemaVersion:4,id:id,createdAt:Date(),status:.restored,entries:[],issue:nil)
                manifest.requestingUserID = getuid()
                try vault.privateChild(id.uuidString).write(encoder.encode(manifest),name:"manifest.json")
            }
            let first = try await p.coordinator.historyPage()
            XCTAssertEqual(first.rows.filter { $0.origin == .user }.count,1)
            XCTAssertEqual(first.rows.filter { $0.origin == .system }.count,16)
            let next = try XCTUnwrap(first.nextSystemCursor)
            let second = try await p.coordinator.historyPage(afterSystem:next)
            XCTAssertTrue(second.rows.allSatisfy { $0.origin == .system })
            XCTAssertEqual(second.rows.count,4)
            XCTAssertNil(second.nextSystemCursor)
            let all = first.rows + second.rows
            XCTAssertEqual(all.count,21)
            XCTAssertEqual(Set(all.map(\.id)).count,21,"The same UUID in two authorised namespaces must remain two distinct rows")
            let collisions = all.filter { $0.summary.id == userID }
            XCTAssertEqual(collisions.count,2)
            for row in collisions {
                let detail = try await p.coordinator.recoveryDetail(origin:row.origin,batchID:userID)
                XCTAssertEqual(detail.entries.count,row.origin == .user ? 1 : 0,"Never guess a recovery origin by UUID")
            }
            // Restore actual source bytes before retiring the test fixtures.
            for record in result.batches { _ = try await p.coordinator.restore(source:record.source,batchID:record.manifest.id) }
            await finish(p)
        } catch { await finish(p); throw error }
    }
    func testOpeningHistoryInvalidatesLiveReviewWithoutMutatingSources() async throws {
        let p = try prepared(); defer { try? p.fixture.clean() }
        do {
            let overview = try await p.coordinator.scanJunk()
            let review = try await p.coordinator.review(overviewID:overview.id,selected:Set(overview.selectableCandidates(includeUserData:false).map(\.id)),includeUserData:false)
            _ = try await p.coordinator.historyPage()
            do { _ = try await p.coordinator.execute(reviewID:review.id); XCTFail("History navigation must invalidate old execution authority") } catch { }
            for path in [p.userCache,p.systemCache,p.systemLog] { XCTAssertTrue(FileManager.default.fileExists(atPath:path)) }
            await finish(p)
        } catch { await finish(p); throw error }
    }
    func testNewScanInvalidatesThePreviousReviewBeforeAnySourceMutation() async throws {
        let p = try prepared(); defer { try? p.fixture.clean() }
        do {
            let first = try await p.coordinator.scanJunk()
            let review = try await p.coordinator.review(overviewID:first.id,selected:Set(first.selectableCandidates(includeUserData:false).map(\.id)),includeUserData:false)
            _ = try await p.coordinator.scanJunk()
            do { _ = try await p.coordinator.execute(reviewID:review.id); XCTFail("A new scan must invalidate the previous review") } catch { }
            for path in [p.userCache,p.systemCache,p.systemLog] { XCTAssertTrue(FileManager.default.fileExists(atPath:path)) }
            await finish(p)
        } catch { await finish(p); throw error }
    }
    func testCloseDuringConnectionRejectsLateResultsAndOverlappingScans() async throws {
        let p = try prepared(); defer { try? p.fixture.clean() }
        let gate = CoordinatorConnectionGate()
        let coordinator = try CleanupCoordinator.fixture(engine:p.fixture.engine,systemFactory:{ await gate.wait(); return try await p.hub.connect() })
        let scan = Task { try await coordinator.scanJunk() }
        do {
            // This precondition includes the real installation inventory.
            // Give older native hardware the same bounded setup allowance as
            // waitForStore; the tested pending-connection behavior is unchanged.
            let setupDeadline = ProcessInfo.processInfo.systemUptime + 120
            while !(await gate.entered) && ProcessInfo.processInfo.systemUptime < setupDeadline {
                try await Task.sleep(nanoseconds:100_000_000)
            }
            guard await gate.entered else { throw SweepError.incomplete("Native user scan did not reach the controlled connection within120seconds") }
            do { _ = try await coordinator.scanJunk(); XCTFail("Overlapping scans must refuse while the first connection is pending") } catch { }
            await coordinator.close(); await gate.release()
            do { _ = try await scan.value; XCTFail("Late scan results cannot survive close") } catch is CancellationError { }
            for path in [p.userCache,p.systemCache,p.systemLog] { XCTAssertTrue(FileManager.default.fileExists(atPath:path)) }
            await coordinator.close(); await finish(p)
        } catch {
            await coordinator.close(); await gate.release(); _ = try? await scan.value
            await coordinator.close(); await finish(p); throw error
        }
    }
    func testUnexpectedExecuteTerminalStateDoesNotCountAsRestoration() async throws {
        let p = try prepared(unexpectedCacheResult:true); defer { try? p.fixture.clean() }
        do {
            let overview = try await p.coordinator.scanJunk()
            let review = try await p.coordinator.review(overviewID:overview.id,selected:Set(overview.selectableCandidates(includeUserData:false).map(\.id)),includeUserData:false)
            let result = try await p.coordinator.execute(reviewID:review.id)
            XCTAssertEqual(result.status,.rolledBack)
            XCTAssertTrue(result.batches.allSatisfy { $0.manifest.status == .restored },"A purged reply is not proof of restoration")
            XCTAssertTrue(FileManager.default.fileExists(atPath:p.systemCache),"Rollback must restore the actual existing recovery data")
            if FileManager.default.fileExists(atPath:p.systemCache) { XCTAssertEqual(try String(contentsOfFile:p.systemCache,encoding:.utf8),"system cache") }
            XCTAssertEqual(try String(contentsOfFile:p.userCache,encoding:.utf8),"user cache")
            XCTAssertEqual(try String(contentsOfFile:p.systemLog,encoding:.utf8),"old system log")
            await finish(p)
        } catch { await finish(p); throw error }
    }
    func testCoordinationJournalLinkRefusesExecutionBeforeAnyFileMove() async throws {
        let p = try prepared(); defer { try? p.fixture.clean() }
        do {
            let overview = try await p.coordinator.scanJunk()
            let review = try await p.coordinator.review(overviewID:overview.id,selected:Set(overview.selectableCandidates(includeUserData:false).map(\.id)),includeUserData:false)
            let support = try SafeDirectory(path:p.fixture.home + "/Library/Application Support").privateChild("App Sweep")
            let outside = p.fixture.home + "/untouched-coordination-target"
            try FileManager.default.createDirectory(atPath:outside,withIntermediateDirectories:false)
            try FileManager.default.createSymbolicLink(atPath:support.path + "/Coordination.noindex",withDestinationPath:outside)
            do { _ = try await p.coordinator.execute(reviewID:review.id); XCTFail("A journal alias must refuse before any source operation") } catch { }
            for path in [p.userCache,p.systemCache,p.systemLog] { XCTAssertTrue(FileManager.default.fileExists(atPath:path)) }
            XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath:outside).isEmpty)
            // Remove this fixture's exact alias so its normal bounded teardown
            // can inspect the remaining tree; the destination is never followed.
            try FileManager.default.removeItem(atPath:support.path + "/Coordination.noindex")
            await finish(p)
        } catch { await finish(p); throw error }
    }
    func testLaterIndeterminateFailureStopsAndRestoresEveryKnownCompletedBatch() async throws {
        let p = try prepared(); defer { try? p.fixture.clean() }
        do {
            let overview = try await p.coordinator.scanJunk()
            let review = try await p.coordinator.review(overviewID:overview.id,selected:Set(overview.selectableCandidates(includeUserData:false).map(\.id)),includeUserData:false)
            try Data("changed before execution".utf8).write(to:URL(fileURLWithPath:p.systemLog))
            let result = try await p.coordinator.execute(reviewID:review.id)
            XCTAssertEqual(result.status,.needsAttention)
            let fresh = try CleanupCoordinator.fixture(engine:p.fixture.engine,systemFactory:{ try await p.hub.connect() })
            let pending = try await fresh.pendingRuns()
            XCTAssertEqual(pending.map(\.id),[review.id],"Uncertain group state must survive a new coordinator")
            await fresh.close()
            XCTAssertEqual(result.uncertainSources,[.systemLogs])
            XCTAssertEqual(result.batches.map(\.source),[.user,.systemCaches])
            XCTAssertTrue(result.batches.allSatisfy { $0.manifest.status == .restored })
            XCTAssertEqual(try String(contentsOfFile:p.userCache,encoding:.utf8),"user cache")
            XCTAssertEqual(try String(contentsOfFile:p.systemCache,encoding:.utf8),"system cache")
            XCTAssertEqual(try String(contentsOfFile:p.systemLog,encoding:.utf8),"changed before execution")
            do { _ = try await p.coordinator.execute(reviewID:review.id); XCTFail("An uncertain operation must never be retried from its old plan") } catch { }
            await finish(p)
        } catch { await finish(p); throw error }
    }
}
#endif
