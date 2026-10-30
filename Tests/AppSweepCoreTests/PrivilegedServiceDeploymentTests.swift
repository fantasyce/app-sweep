#if os(macOS)
import Foundation
import CryptoKit
import Darwin
import XCTest
import CFSafety
@testable import AppSweepCore

/// Explicit root CI in the disposable VM only. This tests the reviewed package,
/// its own daemon and root recovery metadata; it selects no cache, log or app.
final class PrivilegedServiceDeploymentTests: XCTestCase, @unchecked Sendable {
    private let task = "/Users/localtest/AppSweepAcceptanceGeneral-20261016"
    private let output = "/Users/localtest/AppSweepAcceptance/output/build-20261017-221406-txwWSO"
    private let packageDigest = "62562890a41fadcf93914d83cdbb62c8bfd2d65345a9e116bfa06a69267055b1"
    private func rootTask() throws -> SafeDirectory {
        guard getuid() == 0, geteuid() == 0,
              ProcessInfo.processInfo.environment["APP_SWEEP_PRIVILEGED_ACCEPTANCE"] == "1",
              try BoundedProcess.run("/usr/sbin/sysctl",arguments:["-n","hw.model"],timeout:3).trimmingCharacters(in:.whitespacesAndNewlines) == "VirtualMac2,1" else { throw XCTSkip("Explicit disposable VM root service acceptance required") }
        let directory = try SafeDirectory(path:task)
        guard try directory.ownIdentity.owner == 501 else { throw SweepError.denied("Unexpected VM task owner") }
        return try directory.privateChild("root-fixtures.noindex")
    }
    func testAKernelRootHealthCannotBecomeAnOrdinaryCleanupSession() async throws {
        _ = try rootTask()
        var sockets: [Int32] = [-1,-1]
        XCTAssertEqual(socketpair(AF_UNIX,SOCK_STREAM,0,&sockets),0)
        defer { sockets.forEach { if $0 >= 0 { close($0) } } }
        let serverFD = sockets[0], clientFD = sockets[1]
        let server = Task.detached { try SystemServiceHealth.serveIfInstallationPeer(socket:serverFD) }
        let frame = try await LocalControlChannel.readWhenReady(socket:clientFD,deadline:ProcessInfo.processInfo.systemUptime + 1)
        XCTAssertNoThrow(try SystemServiceHealth.validate(frame))
        try LocalControlChannel.write(SystemServiceHealth.acknowledgement(for:frame),socket:clientFD)
        let served = try await server.value
        XCTAssertTrue(served)
        XCTAssertThrowsError(try SystemServiceReply.helloNonce(frame))
        XCTAssertThrowsError(try LocalPeerAuthentication.authenticate(socket:sockets[0],requirement:"anchor apple"))
        XCTAssertLessThan(as_connect_system_service(10),0,"The ordinary connector must continue refusing root")
        guard try !SafeFilesystem.presence("/Library/Application Support/App Sweep/Service/control.sock") else { throw SweepError.incomplete("Missing-listener diagnostic requires the recorded absent task socket") }
        XCTAssertLessThan(as_connect_system_service_health(10),0)
        XCTAssertEqual(errno,ENOENT,"A missing startup socket must remain distinguishable from unsafe socket metadata")
        print("Actual kernel root health reply passed; ordinary cleanup authentication still refuses root")
    }
    static func stageReviewedPackage(path: String, owner: UInt32, digest: String, destination: SafeDirectory) throws -> String {
        let snapshot = try SafeFilesystem.snapshot(path)
        guard snapshot.identity.owner == owner, snapshot.identity.links == 1, snapshot.identity.mode & 0o170000 == 0o100000,
              snapshot.identity.mode & 0o22 == 0, snapshot.identity.size > 0, snapshot.identity.size <= 16 * 1024 * 1024 else { throw SweepError.denied("Reviewed package identity is not confirmed") }
        let data = try SafeFilesystem.readMetadata(path,maximumBytes:16 * 1024 * 1024)
        guard SHA256.hash(data:data).map({ String(format:"%02x",$0) }).joined() == digest else { throw SweepError.denied("Reviewed package digest changed") }
        try SafeFilesystem.verify(snapshot)
        guard as_private_descriptor(destination.fd) == 1,
              try !SafeFilesystem.presence(destination.path + "/reviewed-service.pkg") else { throw SweepError.denied("Reviewed package staging is not empty and private") }
        try destination.write(data,name:"reviewed-service.pkg")
        return destination.path + "/reviewed-service.pkg"
    }
    private func rootPackageStaging(operation: SafeDirectory) throws -> SafeDirectory {
        // An ordinary user owns the task home and can rename its children.
        // Stage executable Installer bytes under root's sticky temporary parent,
        // where another user cannot replace this newly created root-owned entry.
        for path in ["/","/private"] {
            let directory = try SafeDirectory(path:path)
            guard as_unshared_node_descriptor(directory.fd,0) == 1 else { throw SweepError.denied("Root staging ancestor is writable") }
        }
        let parent = try SafeDirectory(path:"/private/tmp"), identity = try parent.ownIdentity
        guard identity.owner == 0, identity.mode & 0o1000 != 0, as_no_grant_acl_descriptor(parent.fd) == 1 else { throw SweepError.denied("Root temporary parent is not protected by ownership/sticky mode") }
        let name = "AppSweepAcceptanceService-" + UUID().uuidString
        guard mkdirat(parent.fd,name,0o700) == 0 else { throw SweepError.denied("Root package staging already exists") }
        let directory = try parent.existingPrivateChild(name), created = try directory.ownIdentity
        try operation.write(JSONSerialization.data(withJSONObject:["createdFromAbsent":true,"path":directory.path,"device":created.device,"inode":created.inode,"purpose":"root-protected reviewed package copy; retain until acceptance cleanup"],options:[.sortedKeys]),name:"package-staging-ownership.json")
        return directory
    }
    private func install(_ package: String, operation: SafeDirectory, name: String) async throws {
        let fd = openat(operation.fd,name,O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,0o600)
        guard fd >= 0, as_private_descriptor(fd) == 1 else { if fd >= 0 { close(fd) }; throw SweepError.denied("Cannot create private installer evidence") }
        let log = FileHandle(fileDescriptor:fd,closeOnDealloc:true)
        let process = Process(); process.executableURL = URL(fileURLWithPath:"/usr/sbin/installer")
        process.arguments = ["-pkg",package,"-target","/"]
        process.standardInput = FileHandle.nullDevice; process.standardOutput = log; process.standardError = log
        try process.run()
        try operation.write(Data(String(process.processIdentifier).utf8),name:name + ".pid")
        let deadline = ProcessInfo.processInfo.systemUptime + 90
        while process.isRunning && ProcessInfo.processInfo.systemUptime < deadline { try await Task.sleep(nanoseconds:100_000_000) }
        guard !process.isRunning else { throw SweepError.incomplete("Installer observation timed out; preserve the live process and root journal, do not retry") }
        try log.synchronize(); try log.close()
        let data = try SafeFilesystem.readMetadata(operation.path + "/" + name)
        guard process.terminationStatus == 0 else { throw SweepError.filesystem("Reviewed Installer failed (\(process.terminationStatus)): " + String(decoding:data,as:UTF8.self)) }
        print("Reviewed Installer completed: " + operation.path + "/" + name)
    }
    private func health() async throws {
        let pins = try RootServiceConfiguration.load(), fd = as_connect_system_service_health(5000)
        guard fd >= 0 else { throw SweepError.incomplete("Installed root health connection failed") }
        defer { close(fd) }
        let frame = try await LocalControlChannel.readWhenReady(socket:fd,deadline:ProcessInfo.processInfo.systemUptime + 10)
        try SystemServiceHealth.validate(frame)
        _ = try LocalPeerAuthentication.authenticateRootService(socket:fd,requirement:pins.pins.requirement(for:.service))
        try pins.verifyUnchanged()
        try LocalControlChannel.write(SystemServiceHealth.acknowledgement(for:frame),socket:fd)
    }
    private func normalClient(_ command: String, reviewedOutput: String? = nil) throws -> [String:Any] {
        let cli = (reviewedOutput ?? output) + "/App Sweep.app/Contents/MacOS/app-sweep"
        let result = try BoundedProcess.capture("/usr/bin/sudo",arguments:["-n","-H","-u","localtest","--",cli,command],timeout:10,mergeStderr:true)
        guard result.status == 0, let object = try JSONSerialization.jsonObject(with:Data(result.text.utf8)) as? [String:Any] else { throw SweepError.incomplete("Signed normal-user client failed: " + result.text) }
        return object
    }
    private func requireAbsentComponentsOrExactOwnRollback(_ base: String) throws {
        for path in [base + "/Service/AppSweepSystemService",base + "/Service/config.json",base + "/Service/control.sock","/Library/LaunchDaemons/org.appsweep.system-service.plist"] {
            guard try !SafeFilesystem.presence(path) else { throw SweepError.denied("Existing component retained; no acceptance overwrite") }
        }
        if try !SafeFilesystem.presence(base) { return }
        // Preserve the exact failed VM installation and its recovery evidence.
        // An arbitrary existing installation, unknown journal or changed object
        // must never become an admissible retry fixture.
        let snapshot = try SafeFilesystem.snapshot(base)
        let batches = ["Installation.noindex/5BA0048D-86AC-4072-9119-21F6FD797157", "Installation.noindex/840F032F-2FF0-454E-8D7C-BAF25319AF59"]
        let hashes = [
            "Installation.noindex/5BA0048D-86AC-4072-9119-21F6FD797157/installation.json":"7228333c408c3a81eb3e6db0bd31723a46fa999be88c709286e0114bdfc10ef3",
            "Installation.noindex/5BA0048D-86AC-4072-9119-21F6FD797157/reverted-configuration":"95deecd04419072b4d92af7ccecec0b28ec681ecc7a914e4a0fef7cad529ee88",
            "Installation.noindex/5BA0048D-86AC-4072-9119-21F6FD797157/reverted-declaration":"30ee3ad87e8c9048382eee33aa10631758fcefdfddea90555b53a62632e6cc25",
            "Installation.noindex/5BA0048D-86AC-4072-9119-21F6FD797157/reverted-program":"7fa1d3346cf6d1c83657f976d5c8324b25c86065328e81e61e96315bb80e5748",
            "Installation.noindex/840F032F-2FF0-454E-8D7C-BAF25319AF59/installation.json":"f0ab3eb7e6cac729a19f03e935d034c5f37431d250cd47efff84bd7a0fd57f00",
            "Installation.noindex/840F032F-2FF0-454E-8D7C-BAF25319AF59/reverted-configuration":"4837f4791dac93efa5eca1d3b8e49c83c191d3ec9da80cc80420a731d3e90308",
            "Installation.noindex/840F032F-2FF0-454E-8D7C-BAF25319AF59/reverted-declaration":"30ee3ad87e8c9048382eee33aa10631758fcefdfddea90555b53a62632e6cc25",
            "Installation.noindex/840F032F-2FF0-454E-8D7C-BAF25319AF59/reverted-program":"1229e9f0c9d21c93aedc7c2752304f5cbf37c88feface152a69e45f79905fac6"
        ]
        let allowed = Set(["Service","Recovery.noindex","Installation.noindex"] + batches + Array(hashes.keys))
        guard snapshot.identity.owner == 0, snapshot.identity.device == 16_777_228,
              snapshot.identity.inode == 4_783_277, Set(snapshot.tree.map(\.relative)) == allowed,
              snapshot.tree.allSatisfy({ $0.identity.owner == 0 && !$0.identity.isLink && $0.identity.mode & 0o22 == 0 }) else { throw SweepError.denied("Retained installation is not the registered VM rollback fixture") }
        for relative in [""] + snapshot.tree.filter({ $0.identity.isDirectory }).map(\.relative) {
            let directory = try SafeDirectory(path:relative.isEmpty ? base : base + "/" + relative)
            guard as_unshared_node_descriptor(directory.fd,0) == 1 else { throw SweepError.denied("Rollback fixture directory has unconfirmed access") }
        }
        for (relative,digest) in hashes {
            let path = base + "/" + relative, item = try SafeFilesystem.snapshot(path)
            let parent = try SafeDirectory(path:URL(fileURLWithPath:path).deletingLastPathComponent().path)
            let fd = openat(parent.fd,URL(fileURLWithPath:path).lastPathComponent,O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
            guard fd >= 0 else { throw SweepError.denied("Rollback fixture file cannot be opened") }
            defer { close(fd) }
            guard as_unshared_node_descriptor(fd,0) == 1,
                  SHA256.hash(data:try SafeFilesystem.readMetadata(path,maximumBytes:16 * 1024 * 1024)).map({ String(format:"%02x",$0) }).joined() == digest else { throw SweepError.denied("Rollback fixture file changed; evidence retained") }
            try SafeFilesystem.verify(item)
        }
        try SafeFilesystem.verify(snapshot)
        print("Exact prior rolled-back VM installation admitted without removing its journal or retained components")
    }
    func testBReviewedPackageInstallUpgradeColdStartAndNormalClient() async throws {
        let fixtures = try rootTask(), base = "/Library/Application Support/App Sweep"
        try requireAbsentComponentsOrExactOwnRollback(base)
        let operation = try fixtures.privateChild(UUID().uuidString), staging = try rootPackageStaging(operation:operation)
        let package = try Self.stageReviewedPackage(path:output + "/App-Sweep-System-Service-2.1.0.pkg",owner:501,digest:packageDigest,destination:staging)
        try operation.write(JSONSerialization.data(withJSONObject:["createdFromAbsent":true,"globalBase":base,"package":package,"sha256":packageDigest],options:[.sortedKeys]),name:"ownership.json")
        try await install(package,operation:operation,name:"first-install.log")
        try await health()
        let status = try normalClient("system-status")
        XCTAssertEqual(status["protocolVersion"] as? Int,1)
        XCTAssertEqual(status["executionEnabled"] as? Bool,false,"System rules remain closed until their separate root acceptance")
        let recovery = try SafeDirectory(path:base + "/Recovery.noindex"), before = try recovery.ownIdentity
        let sentinelID = UUID(), batch = try recovery.privateChild("501").privateChild(sentinelID.uuidString)
        var record = RecoveryManifest(schemaVersion:RecoveryManifest.systemSchemaVersion,id:sentinelID,createdAt:Date(),status:.restored,entries:[],issue:"Root package upgrade preservation acceptance")
        record.requestingUserID = 501
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        let bytes = try encoder.encode(record); try batch.write(bytes,name:"manifest.json")
        try await install(package,operation:operation,name:"upgrade-install.log")
        try await health()
        let after = try SafeDirectory(path:recovery.path).ownIdentity
        XCTAssertEqual(before.device,after.device); XCTAssertEqual(before.inode,after.inode)
        XCTAssertEqual(try batch.read("manifest.json"),bytes)
        let page = try normalClient("system-recovery")
        let items = try XCTUnwrap(page["items"] as? [[String:Any]])
        XCTAssertTrue(items.contains { $0["id"] as? String == sentinelID.uuidString })
        let lifecycle = try LaunchdServiceLifecycle()
        try await lifecycle.stop(); try await lifecycle.start()
        try await health()
        XCTAssertEqual(try normalClient("system-status")["protocolVersion"] as? Int,1)
        print("Actual reviewed package install/upgrade, recovery preservation, daemon cold start and signed ordinary-client status/history passed; no cleanup or whole-VM restart: " + operation.path)
    }
    func testCReviewedV8UpgradePreservesRecoveryAndColdStartAuthenticatesNormalClient() async throws {
        let fixtures = try rootTask(), base = "/Library/Application Support/App Sweep"
        let reviewed = "/Users/localtest/AppSweepAcceptance/output/build-20261018-015404-Wz5GY0"
        let digest = "84beaee35eea26f1b350c3469210ff55aecb988ca8ce85e31885cf5275164658"
        let expected = [
            base + "/Service/AppSweepSystemService":"c9c2a3bf0b884c3126ef9b2ee5847487adc3ec692a9968a22819be789d0a19c5",
            base + "/Service/config.json":"63232481173b9d45af1313911b63914dc50985815d968518d61ee76ae1a6058d",
            "/Library/LaunchDaemons/org.appsweep.system-service.plist":"30ee3ad87e8c9048382eee33aa10631758fcefdfddea90555b53a62632e6cc25"
        ]
        for (path,hash) in expected {
            let before = try SafeFilesystem.snapshot(path)
            guard before.identity.owner == 0, before.identity.links == 1, before.identity.mode & 0o170000 == 0o100000,
                  before.identity.mode & 0o22 == 0, before.identity.size <= 16*1024*1024,
                  SHA256.hash(data:try SafeFilesystem.readMetadata(path,maximumBytes:16*1024*1024)).map({ String(format:"%02x",$0) }).joined() == hash else {
                throw SweepError.denied("Current VM service is not the exact reviewed v8 installation; do not upgrade")
            }
            try SafeFilesystem.verify(before)
        }
        try await health()
        XCTAssertEqual(try normalClient("system-status",reviewedOutput:reviewed)["protocolVersion"] as? Int,1)
        let operation = try fixtures.privateChild(UUID().uuidString), staging = try rootPackageStaging(operation:operation)
        let package = try Self.stageReviewedPackage(path:reviewed + "/App-Sweep-System-Service-2.1.0.pkg",owner:501,digest:digest,destination:staging)
        let recovery = try SafeDirectory(path:base + "/Recovery.noindex"), before = try recovery.ownIdentity
        let sentinelID = UUID(), batch = try recovery.privateChild("501").privateChild(sentinelID.uuidString)
        var sentinel = RecoveryManifest(schemaVersion:RecoveryManifest.systemSchemaVersion,id:sentinelID,createdAt:Date(),status:.restored,entries:[],issue:"Reviewed v8 upgrade preservation acceptance")
        sentinel.requestingUserID = 501
        let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601
        let bytes = try encoder.encode(sentinel); try batch.write(bytes,name:"manifest.json")
        try operation.write(JSONSerialization.data(withJSONObject:["purpose":"v8 upgrade and own service cold start only; no cleanup or reboot","packageSHA256":digest,"sentinelBatch":sentinelID.uuidString],options:[.sortedKeys]),name:"ownership.json")
        try await install(package,operation:operation,name:"v8-upgrade.log")
        try await health()
        let after = try recovery.ownIdentity
        // Creating the sentinel's user directory legitimately changes the
        // parent's size/mtime. Preserve its object and access, plus exact data.
        XCTAssertEqual(after.device,before.device); XCTAssertEqual(after.inode,before.inode)
        XCTAssertEqual(after.mode,before.mode); XCTAssertEqual(after.owner,before.owner)
        XCTAssertEqual(try batch.read("manifest.json"),bytes)
        let page = try normalClient("system-recovery",reviewedOutput:reviewed)
        XCTAssertTrue(try XCTUnwrap(page["items"] as? [[String:Any]]).contains { $0["id"] as? String == sentinelID.uuidString })
        let lifecycle = try LaunchdServiceLifecycle()
        try await lifecycle.stop(); try await lifecycle.start()
        try await health()
        let status = try normalClient("system-status",reviewedOutput:reviewed)
        XCTAssertEqual(status["protocolVersion"] as? Int,1)
        XCTAssertEqual(status["executionEnabled"] as? Bool,false,"Separate system rule acceptance remains closed")
        print("Reviewed v8 upgrade, recovery preservation and cold-start checks exercised; XCTest's final outcome is authoritative: " + operation.path)
    }
    func testDReviewedV8ServiceRemovalPreservesRecoveryAndRestoresOriginalComponents() async throws {
        let fixtures = try rootTask(), base = "/Library/Application Support/App Sweep"
        let reviewed = "/Users/localtest/AppSweepAcceptance/output/build-20261018-015404-Wz5GY0"
        let expected = [
            base + "/Service/AppSweepSystemService":"c9c2a3bf0b884c3126ef9b2ee5847487adc3ec692a9968a22819be789d0a19c5",
            base + "/Service/config.json":"63232481173b9d45af1313911b63914dc50985815d968518d61ee76ae1a6058d",
            "/Library/LaunchDaemons/org.appsweep.system-service.plist":"30ee3ad87e8c9048382eee33aa10631758fcefdfddea90555b53a62632e6cc25"
        ]
        var originals:[FileSnapshot] = []
        for (path,digest) in expected {
            let snapshot = try SafeFilesystem.snapshot(path)
            guard snapshot.identity.owner == 0, snapshot.identity.mode & 0o22 == 0,
                  SHA256.hash(data:try SafeFilesystem.readMetadata(path,maximumBytes:16*1024*1024)).map({ String(format:"%02x",$0) }).joined() == digest else {
                throw SweepError.denied("Only the exact task-installed v8 service can enter removal acceptance")
            }
            try SafeFilesystem.verify(snapshot); originals.append(snapshot)
        }
        func recoveryBytes() throws -> [String:Data] {
            let snapshot = try SafeFilesystem.snapshot(base + "/Recovery.noindex")
            var result:[String:Data] = [:]
            for entry in snapshot.tree where !entry.identity.isDirectory {
                guard entry.relative.hasSuffix("/manifest.json"), entry.identity.owner == 0 else { throw SweepError.denied("Unknown root recovery contents retained") }
                result[entry.relative] = try SafeFilesystem.readMetadata(snapshot.path + "/" + entry.relative)
            }
            try SafeFilesystem.verify(snapshot); return result
        }
        let before = try recoveryBytes(), recovery = try SafeDirectory(path:base + "/Recovery.noindex").ownIdentity
        guard !before.isEmpty else { throw SweepError.incomplete("Expected reviewed upgrade preservation records are absent") }
        try await health()
        _ = try normalClient("system-status",reviewedOutput:reviewed)
        let operation = try fixtures.privateChild(UUID().uuidString)
        try operation.write(Data("Only this VM's exact v8 service is removed reversibly; all cleanup recovery records retained; no app/cache/log cleanup or computer reboot".utf8),name:"ownership.txt")
        let removed = try await SystemServiceInstallation.remove()
        try operation.write(JSONEncoder().encode(removed),name:"removal-result.json")
        guard removed.status == .removed else { throw SweepError.incomplete(removed.issue ?? "Service removal did not complete") }
        for original in originals { XCTAssertFalse(try SafeFilesystem.presence(original.path)) }
        XCTAssertEqual(try recoveryBytes(),before)
        let launch = try BoundedProcess.capture("/bin/launchctl",arguments:["print","system/org.appsweep.system-service"],timeout:5,mergeStderr:true)
        XCTAssertEqual(launch.status,113,"Own service must be unregistered after reversible removal")
        let id = try XCTUnwrap(UUID(uuidString:URL(fileURLWithPath:removed.journalPath).deletingLastPathComponent().lastPathComponent))
        let restored = try await SystemServiceInstallation.restoreRemoval(id)
        try operation.write(JSONEncoder().encode(restored),name:"restoration-result.json")
        guard restored.status == .rolledBack else { throw SweepError.incomplete(restored.issue ?? "Service restoration did not complete") }
        for original in originals {
            let now = try SafeFilesystem.snapshot(original.path)
            XCTAssertTrue(now.identity.sameObject(as:original.identity))
            XCTAssertEqual(now.tree,original.tree)
        }
        let after = try SafeDirectory(path:base + "/Recovery.noindex").ownIdentity
        XCTAssertEqual(after.device,recovery.device); XCTAssertEqual(after.inode,recovery.inode)
        XCTAssertEqual(after.owner,recovery.owner); XCTAssertEqual(after.mode,recovery.mode)
        XCTAssertEqual(try recoveryBytes(),before)
        try await health()
        XCTAssertEqual(try normalClient("system-status",reviewedOutput:reviewed)["executionEnabled"] as? Bool,false)
        _ = try normalClient("system-recovery",reviewedOutput:reviewed)
        print("Actual v8 service removal and fresh restoration exercised; root recovery records unchanged; XCTest final outcome is authoritative: " + operation.path)
    }
}
#endif
