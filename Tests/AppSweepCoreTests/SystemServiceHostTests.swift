#if os(macOS)
import Foundation
import Darwin
import XCTest
import CFSafety
@testable import AppSweepCore

final class SystemServiceHostTests: XCTestCase, @unchecked Sendable {
    func testBlockingFilesystemEngineDoesNotUseTheCooperativeOrMainExecutor() async throws {
        guard #available(macOS 14.0, *) else { throw XCTSkip("Native custom filesystem executor requires macOS 14; older runtimes retain default actor scheduling") }
        let context = try await SweepEngine().filesystemExecutionContext()
        XCTAssertFalse(context.mainThread, "Filesystem and native signature work must stay off the UI thread")
        XCTAssertFalse(context.queue.contains("cooperative"), "Blocking native signature validation must not monopolize Swift's cooperative workers")
    }
    func testNativeListenerStateSurvivesRenameAndRejectsNonListeners() throws {
        guard getuid() != 0, let base = ProcessInfo.processInfo.environment["TMPDIR"] else { throw XCTSkip("Ordinary task-owned temporary root required") }
        var template = Array((base + "listener-XXXXXX").utf8CString)
        let directory = try XCTUnwrap(mkdtemp(&template)).withMemoryRebound(to:CChar.self,capacity:template.count) { String(cString:$0) }
        defer { try? FileManager.default.removeItem(atPath:directory) }
        let path = directory + "/a", renamed = directory + "/b"
        XCTAssertLessThan(path.utf8.count,104)
        let fd = socket(AF_UNIX,SOCK_STREAM,0)
        XCTAssertGreaterThanOrEqual(fd,0); defer { if fd >= 0 { close(fd) } }
        XCTAssertEqual(as_unix_stream_listener(fd),0)
        var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8CString); address.sun_len = UInt8(2 + bytes.count)
        withUnsafeMutableBytes(of:&address.sun_path) { target in
            bytes.withUnsafeBytes { target.copyBytes(from:$0) }
        }
        let length = socklen_t(address.sun_len)
        XCTAssertEqual(withUnsafePointer(to:&address) { $0.withMemoryRebound(to:sockaddr.self,capacity:1) { Darwin.bind(fd,$0,length) } },0)
        XCTAssertEqual(as_unix_stream_listener(fd),0,"Binding a socket must not grant listener status")
        XCTAssertEqual(listen(fd,2),0)
        XCTAssertEqual(as_unix_stream_listener(fd),1,"A native Darwin listener must pass the production state predicate")
        try FileManager.default.moveItem(atPath:path,toPath:renamed)
        XCTAssertEqual(as_unix_stream_listener(fd),1,"launchd renames bound sockets; the original kernel name remains unchanged")
        var pair:[Int32] = [-1,-1]
        XCTAssertEqual(socketpair(AF_UNIX,SOCK_STREAM,0,&pair),0)
        defer { pair.forEach { if $0 >= 0 { close($0) } } }
        for value in pair { XCTAssertEqual(as_unix_stream_listener(value),0) }
        let datagram = socket(AF_UNIX,SOCK_DGRAM,0); defer { if datagram >= 0 { close(datagram) } }
        XCTAssertEqual(as_unix_stream_listener(datagram),0)
        XCTAssertEqual(as_unix_stream_listener(-1),0)
    }
    func testOrdinaryProcessCannotActivateOrRunTheSystemService() async throws {
        guard getuid() != 0, geteuid() != 0 else { throw XCTSkip("Non-root rejection case only; must never start a persistent daemon in a root test") }
        XCTAssertLessThan(as_activate_system_listener(),0)
        do { try await SystemServiceHost.run(); XCTFail("Ordinary process must not run a system listener") } catch { }
    }
    func testInvalidDescriptorsAndTimeoutsCannotBeAcceptedAsSystemListeners() {
        XCTAssertLessThan(as_accept_system_peer(-1,10),0)
        XCTAssertLessThan(as_accept_system_peer(-1,0),0)
        XCTAssertLessThan(as_accept_system_peer(-1,10001),0)
        let descriptor = open("/dev/null",O_RDONLY | O_CLOEXEC)
        defer { if descriptor >= 0 { close(descriptor) } }
        XCTAssertLessThan(as_accept_system_peer(descriptor,10),0)
        var sockets: [Int32] = [-1,-1]
        XCTAssertEqual(socketpair(AF_UNIX,SOCK_STREAM,0,&sockets),0)
        defer { sockets.forEach { if $0 >= 0 { close($0) } } }
        XCTAssertLessThan(as_accept_system_peer(sockets[0],10),0)
    }
}

private extension SweepEngine {
    func filesystemExecutionContext() throws -> (mainThread: Bool, queue: String) {
        (Thread.isMainThread, try nativeCurrentQueueLabel())
    }
}

private func nativeCurrentQueueLabel() throws -> String {
    typealias CurrentQueueLabel = @convention(c) (OpaquePointer?) -> UnsafePointer<CChar>
    guard let handle = dlopen(nil, RTLD_LAZY), let symbol = dlsym(handle, "dispatch_queue_get_label") else {
        throw SweepError.incomplete("Native dispatch execution context unavailable")
    }
    defer { dlclose(handle) }
    let label = unsafeBitCast(symbol, to: CurrentQueueLabel.self)
    return String(cString: label(nil))
}
#endif
