import Foundation
import CryptoKit
import Darwin
@testable import AppSweepCore

@MainActor func trivyProducerChecks() async throws {
    let environment = ProcessInfo.processInfo.environment
    guard let binary = environment["APP_SWEEP_TRIVY_EXECUTABLE"], let original = environment["APP_SWEEP_TRIVY_INPUT"], let work = environment["APP_SWEEP_TEST_WORK_ROOT"] else { throw CheckFailure("Pinned task-owned Trivy inputs required") }
    let f = try OwnedFixture(), cache = f.home + "/Library/Caches/trivy", database = cache + "/db"
    let proof = work + "/trivy-proof-" + URL(fileURLWithPath: f.home).lastPathComponent
    try fm.createDirectory(atPath: proof, withIntermediateDirectories: true)
    for path in [cache,f.home + "/tmp",f.home + "/config",f.home + "/docker",f.home + "/sample/etc",f.home + "/sample/lib/apk/db"] { try fm.createDirectory(atPath: path, withIntermediateDirectories: true) }
    try Data("{}\n".utf8).write(to: URL(fileURLWithPath:f.home + "/config/empty.yaml"))
    let quoted = String(data: try JSONSerialization.data(withJSONObject: f.home,options:[.fragmentsAllowed]),encoding:.utf8)!
    let profile = f.home + "/producer.sb"
    try Data(("(version 1)\n(allow default)\n(deny file-write*)\n(allow file-write* (subpath " + quoted + ") (literal \"/dev/null\"))\n").utf8).write(to:URL(fileURLWithPath:profile))
    var env = ["PATH":"/usr/bin:/bin:/usr/sbin:/sbin","HOME":try SystemIdentity.home(),"TMPDIR":f.home + "/tmp","XDG_CONFIG_HOME":f.home + "/config","DOCKER_CONFIG":f.home + "/docker"]
    for key in ["HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","NO_PROXY"] { if let value = environment[key] { env[key] = value } }
    func run(_ args:[String],name:String) async throws {
        let path = f.home + "/" + name + ".log"; fm.createFile(atPath:path,contents:nil)
        let log = try FileHandle(forWritingTo:URL(fileURLWithPath:path));defer{try? log.close()}
        let p = Process();p.executableURL=URL(fileURLWithPath:"/usr/bin/sandbox-exec")
        p.arguments=["-f",profile,binary,"--cache-dir",cache,"--config",f.home + "/config/empty.yaml"] + args
        p.environment=env;p.currentDirectoryURL=URL(fileURLWithPath:f.home);p.standardOutput=log;p.standardError=log
        try p.run();let deadline=Date().addingTimeInterval(260)
        while p.isRunning && Date()<deadline {try await Task.sleep(nanoseconds:100_000_000)}
        if p.isRunning {p.terminate();throw CheckFailure("Owned Trivy producer timed out")}
        try fm.copyItem(atPath:path,toPath:proof + "/" + name + ".log")
        try check(p.terminationStatus == 0,"Trivy producer failed: " + name)
    }
    try fm.copyItem(atPath:original,toPath:database)
    let rule="development-trivy-database-v1", engine=try f.engine(rules:[rule]),report=try await engine.scanJunk()
    guard let item=report.selectableCandidates(includeUserData:false).first(where:{$0.path == database}) else {throw CheckFailure("Real Trivy database not selectable: " + report.candidates.compactMap(\.retentionReason).joined(separator:";"))}
    let before=try SafeFilesystem.snapshot(database),meta=try Data(contentsOf:URL(fileURLWithPath:database + "/metadata.json"))
    let digest=try VerifiedFileStream.digest(SafeFilesystem.snapshot(database + "/trivy.db"))
    let plan=try await engine.makePlan(reportID:report.id,selected:[item.id],includeUserData:false),batch=try await engine.execute(planID:plan.id)
    try check(batch.status == .isolated && !fm.fileExists(atPath:database),"Real Trivy quarantine failed")
    try await run(["image","--download-db-only","--no-progress","--timeout","4m"],name:"regenerated")
    _ = try ToolCacheRule.verify(database,home:f.home)
    try check(SafeFilesystem.snapshot(database).identity.inode != before.identity.inode,"Producer did not recreate database")
    let conflict=try await f.engine(rules:[rule]).restore(batchID:batch.id)
    try check(conflict.status != .restored && fm.fileExists(atPath:database),"New producer database overwritten during recovery")
    try fm.moveItem(atPath:database,toPath:f.home + "/regenerated-db")
    let restored=try await f.engine(rules:[rule]).restore(batchID:batch.id)
    try check(restored.status == .restored && SafeFilesystem.snapshot(database).identity.inode == before.identity.inode,"Original database identity did not recover")
    try check(VerifiedFileStream.digest(SafeFilesystem.snapshot(database + "/trivy.db")) == digest && Data(contentsOf:URL(fileURLWithPath:database + "/metadata.json")) == meta,"Recovered database/metadata bytes changed")
    try Data("3.22.0\n".utf8).write(to:URL(fileURLWithPath:f.home + "/sample/etc/alpine-release"))
    try Data("ID=alpine\nVERSION_ID=3.22.0\n".utf8).write(to:URL(fileURLWithPath:f.home + "/sample/etc/os-release"))
    try Data("P:busybox\nV:1.37.0-r0\nA:aarch64\no:busybox\n\n".utf8).write(to:URL(fileURLWithPath:f.home + "/sample/lib/apk/db/installed"))
    try await run(["rootfs","--skip-db-update","--skip-java-db-update","--offline-scan","--scanners","vuln","--format","json",f.home + "/sample"],name:"restored-offline-consumer")
    let consumer=try Data(contentsOf:URL(fileURLWithPath:proof + "/restored-offline-consumer.log"))
    try check(String(data:consumer,encoding:.utf8)?.contains("busybox") == true,"Restored producer did not inspect the registered package fixture")
    print("PASS real Trivy database download, quarantine, regeneration, conflict-safe byte recovery and offline consumer")
    try f.finish()
}
