#if os(macOS)
import Foundation
import Darwin
import Security
import XCTest
import CFSafety
@testable import AppSweepCore

final class LocalPeerAuthenticationTests: XCTestCase {
    func testKernelSocketPairPeerCredentials() throws {
        var sockets: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        guard sockets.allSatisfy({ $0 >= 0 }) else { return }
        defer { sockets.forEach { close($0) } }
        var raw = ASPeerIdentity()
        XCTAssertEqual(as_peer_identity(sockets[0], &raw), 0, "A connected local socket must expose kernel peer credentials")
        XCTAssertEqual(raw.effective_uid, geteuid()); XCTAssertEqual(raw.real_uid, getuid()); XCTAssertEqual(raw.pid, getpid())

    }
    private enum ClientMode { case hardened, plain, debugger, libraryException }
    func testConnectedAdHocClientExactCodeHashAndExpiredPeer() async throws { try await connectedClient(.hardened) }
    func testMatchingCodeWithoutRuntimeHardeningIsRejected() async throws { try await connectedClient(.plain) }
    func testSignedDebuggingExceptionIsRejected() async throws { try await connectedClient(.debugger) }
    func testSignedLibraryValidationExceptionIsRejected() async throws { try await connectedClient(.libraryException) }
    private func connectedClient(_ mode: ClientMode) async throws {
        let fm = FileManager.default, home = try SystemIdentity.home()
        guard let base = ProcessInfo.processInfo.environment["APP_SWEEP_FIXTURES"], base.hasPrefix(home + "/AppSweepAcceptance"), getuid() != 0,
              let sdk = ProcessInfo.processInfo.environment["APP_SWEEP_SDK"] else { throw XCTSkip("Isolated owned peer fixture and SDK required") }
        let root = URL(fileURLWithPath: base).deletingLastPathComponent().path + "/peer-" + String(UUID().uuidString.prefix(12))
        guard try !SafeFilesystem.presence(root) else { throw SweepError.denied("Peer fixture exists") }
        try fm.createDirectory(atPath: root, withIntermediateDirectories: false, attributes: [.posixPermissions:0o700])
        defer { try? fm.removeItem(atPath: root) }
        let binary = root + "/client", socketPath = root + "/s"
        guard socketPath.utf8.count < 104 else { throw SweepError.invalid("Fixture socket path exceeds native limit") }
        let clang = ProcessInfo.processInfo.environment["APP_SWEEP_CLANG"] ?? "/usr/bin/clang"
        let compiled = try BoundedProcess.capture(clang, arguments: ["-isysroot", sdk, "-mmacosx-version-min=12.0", NativeAcceptanceTests.NativeFixture.resource("PeerClient", extension: "c").path, "-o", binary], timeout: 30, mergeStderr: true)
        guard compiled.status == 0 else { throw SweepError.incomplete("Peer fixture compile: " + compiled.text) }
        var signingArguments = ["--force", "--sign", "-", "--identifier", "org.appsweep.acceptance.peer-client"]
        if mode != .plain { signingArguments += ["--options", "runtime"] }
        if mode == .debugger || mode == .libraryException {
            let key = mode == .debugger ? "com.apple.security.get-task-allow" : "com.apple.security.cs.disable-library-validation"
            let entitlements = root + "/entitlements.plist"
            try PropertyListSerialization.data(fromPropertyList: [key:true], format: .xml, options: 0).write(to: URL(fileURLWithPath: entitlements))
            signingArguments += ["--entitlements", entitlements]
        }
        _ = try BoundedProcess.run("/usr/bin/codesign", arguments: signingArguments + [binary], timeout: 10)
        var code: SecStaticCode?, info: CFDictionary?
        XCTAssertEqual(SecStaticCodeCreateWithPath(URL(fileURLWithPath: binary) as CFURL, [], &code), errSecSuccess)
        let executableCode = try XCTUnwrap(code)
        XCTAssertEqual(SecStaticCodeCheckValidity(executableCode, [], nil), errSecSuccess)
        XCTAssertEqual(SecCodeCopySigningInformation(executableCode, SecCSFlags(rawValue:kSecCSSigningInformation), &info), errSecSuccess)
        let signing = try XCTUnwrap(info as? [String:Any]), hash = try XCTUnwrap(signing[kSecCodeInfoUnique as String] as? Data)
        let requirement = "cdhash H\"" + hash.map { String(format:"%02x", $0) }.joined() + "\""
        let listener = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listener >= 0 else { throw SweepError.filesystem("Fixture listener failed") }
        defer { close(listener) }
        XCTAssertEqual(fcntl(listener, F_SETFD, FD_CLOEXEC), 0)
        var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX); address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        _ = withUnsafeMutablePointer(to: &address.sun_path) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: 104) { destination in socketPath.withCString { strcpy(destination, $0) } }
        }
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        XCTAssertEqual(bound, 0); guard bound == 0 else { return }
        XCTAssertEqual(chmod(socketPath, 0o600), 0); XCTAssertEqual(listen(listener, 1), 0)
        let process = Process(); process.executableURL = URL(fileURLWithPath: binary); process.arguments = [socketPath]
        try process.run()
        defer { if process.isRunning { process.terminate() } }
        var ready = pollfd(fd: listener, events: Int16(POLLIN), revents: 0)
        XCTAssertEqual(poll(&ready, 1, 3000), 1)
        guard ready.revents & Int16(POLLIN) != 0 else { return }
        let connected = accept(listener, nil, nil)
        guard connected >= 0 else { throw SweepError.filesystem("Fixture accept failed") }
        defer { close(connected) }
        if mode == .hardened {
            let peer = try LocalPeerAuthentication.authenticate(socket: connected, requirement: requirement)
            XCTAssertEqual(peer.uid, geteuid()); XCTAssertEqual(peer.pid, process.processIdentifier); XCTAssertEqual(peer.auditToken.count, 32)
        } else {
            XCTAssertThrowsError(try LocalPeerAuthentication.authenticate(socket: connected, requirement: requirement), "A matching hash must not authorize a client with weakened runtime protections")
        }
        XCTAssertThrowsError(try LocalPeerAuthentication.authenticateRootService(socket: connected, requirement: requirement), "A user process must never impersonate the root service")
        XCTAssertThrowsError(try LocalPeerAuthentication.authenticate(socket: connected, requirement: "identifier org.example.untrusted-client"))
        var ack: UInt8 = 120; XCTAssertEqual(write(connected, &ack, 1), 1)
        for _ in 0..<30 { if !process.isRunning { break }; try await Task.sleep(nanoseconds: 100_000_000) }
        XCTAssertFalse(process.isRunning)
        guard !process.isRunning else { return }
        XCTAssertEqual(process.terminationStatus, 0)
        XCTAssertThrowsError(try LocalPeerAuthentication.authenticate(socket: connected, requirement: requirement), "A completed process must not retain authority through the old socket")
    }
    func testInvalidAndNonSocketDescriptorsCannotAuthenticate() throws {
        var raw = ASPeerIdentity()
        XCTAssertNotEqual(as_peer_identity(-1, &raw), 0)
        let null = open("/dev/null", O_RDONLY | O_CLOEXEC); defer { if null >= 0 { close(null) } }
        XCTAssertNotEqual(as_peer_identity(null, &raw), 0)
        XCTAssertThrowsError(try LocalPeerAuthentication.authenticate(socket: null, requirement: "anchor apple"))
    }
}
#endif
