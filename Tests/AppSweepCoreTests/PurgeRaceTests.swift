import XCTest
@testable import AppSweepCore

final class PurgeRaceTests: XCTestCase {
    func testLateUnregisteredObjectIsNeverPermanentlyRemoved() throws {
        let f = try RecoveryTests.Fixture(); defer { try? f.clean() }
        let target = f.home + "/target"
        try FileManager.default.createDirectory(atPath: target, withIntermediateDirectories: false)
        try Data("known".utf8).write(to: URL(fileURLWithPath: target + "/known"))
        let root = ProcessInfo.processInfo.environment["APP_SWEEP_SOURCE_ROOT"] ?? URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().path
        let fixture = root + "/Tests/AppSweepCoreTests/Fixtures/"
        let clang = ProcessInfo.processInfo.environment["APP_SWEEP_CLANG"] ?? "/opt/swift/usr/bin/clang"
        let binary = f.home + "/purge-race", interposer = f.home + "/purge-interposer.dylib"
        var common: [String] = []
        if let sdk = ProcessInfo.processInfo.environment["APP_SWEEP_SDK"] { common += ["-isysroot", sdk] }
        #if os(macOS)
        let library = ["-dynamiclib"]
        #else
        let library = ["-shared", "-fPIC", "-ldl"]
        #endif
        let compiled = try BoundedProcess.capture(clang, arguments: common + ["-I", root + "/Sources/CFSafety/include", root + "/Sources/CFSafety/filesystem.c", fixture + "PurgeRace.c", "-o", binary], timeout: 30, mergeStderr: true)
        XCTAssertEqual(compiled.status, 0, compiled.text); guard compiled.status == 0 else { return }
        let hook = try BoundedProcess.capture(clang, arguments: common + library + [fixture + "PurgeRaceInterposer.c", "-o", interposer], timeout: 30, mergeStderr: true)
        XCTAssertEqual(hook.status, 0, hook.text); guard hook.status == 0 else { return }
        let result = try BoundedProcess.capture(binary, arguments: [f.home, interposer], timeout: 3, mergeStderr: true)
        XCTAssertEqual(result.status, 0, result.text)
        XCTAssertEqual(try String(contentsOfFile: target + "/late", encoding: .utf8), "unregistered")
    }
}
