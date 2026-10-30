import XCTest
@testable import AppSweepCore

final class ActivityTests: XCTestCase {
    func testEmptyMalformedOrIncompleteProcessListsAreUnknown() {
        for text in ["", "   \n", "not a process", "12", "12 /some/app\n", "42 /self\n42 /duplicate\n"] {
            XCTAssertThrowsError(try ActivityInspector.processes(text, ownPID: 42), text)
        }
    }
    func testLongCommandsAndSpacesArePreserved() throws {
        let command = "/Applications/Very Long Name.app/Contents/MacOS/app " + String(repeating: "x", count: 4000)
        let processes = try ActivityInspector.processes(" 42 /self\n 99 " + command + "\n", ownPID: 42)
        XCTAssertEqual(processes.count, 2)
        XCTAssertEqual(processes[1].pid, 99)
        XCTAssertEqual(processes[1].command, command)
    }
    func testLsofBusyRecordsRemainBusyEvenWhenAnotherQueryReportsFailure() {
        let text = "p96499\0cmdworker_shared\0\nf3\0n/owned/clone/header.h\0\n"
        for status: Int32 in [0, 1] {
            XCTAssertThrowsError(try BusyInspector.ensureUnused(CapturedProcess(status: status, text: text))) { error in
                XCTAssertTrue(error.localizedDescription.contains("仍被进程使用"), "Known open files must not be described as an unknown result: \(error)")
            }
        }
        XCTAssertNoThrow(try BusyInspector.ensureUnused(CapturedProcess(status: 1, text: "")))
        for output in [CapturedProcess(status: 1, text: "lsof: permission denied"), CapturedProcess(status: 2, text: "")] {
            XCTAssertThrowsError(try BusyInspector.ensureUnused(output)) { error in
                XCTAssertTrue(error.localizedDescription.contains("未确认"))
            }
        }
    }
    func testBusyMessageIdentifiesTheProcessHoldingAnExtension() {
        let text = "p39147\0cSafari\0\nf87\0n/owned/IINA.app/Contents/PlugIns/OpenInIINA.appex/Contents/MacOS/OpenInIINA\0\n"
        XCTAssertThrowsError(try BusyInspector.ensureUnused(CapturedProcess(status: 1, text: text))) { error in
            XCTAssertTrue(error.localizedDescription.contains("Safari"), "The user needs the actual blocking application, not an instruction to wait indefinitely")
        }
    }
    func testIndexerOccupancySuggestsWaitingRatherThanStoppingSystemServices() {
        let text = "p123\0cmdworker_shared\0\nf3\0n/owned/application/resource\0\n"
        XCTAssertThrowsError(try BusyInspector.ensureUnused(CapturedProcess(status: 1, text: text))) { error in
            XCTAssertTrue(error.localizedDescription.contains("稍后"))
            XCTAssertFalse(error.localizedDescription.contains("退出相关应用"), "Indexing is not an instruction to quit a system process")
        }
    }
    func testBuildToolsAreDetectedEvenWhenToolchainPathContainsSpaces() {
        for command in ["/Applications/Xcode 15.app/Contents/Developer/usr/bin/xcodebuild -project a", "/usr/bin/clang -c a.c", "/tools/swift-frontend -c a.swift", "/tools/XCBBuildService"] {
            XCTAssertTrue(ActivityInspector.isBuildTool(command), command)
        }
        for command in ["/usr/bin/ps -ww -axo pid=,command=", "/Applications/Notclang.app/Contents/MacOS/app", "/bin/cat /tmp/clang-log"] {
            XCTAssertFalse(ActivityInspector.isBuildTool(command), command)
        }
    }
}
