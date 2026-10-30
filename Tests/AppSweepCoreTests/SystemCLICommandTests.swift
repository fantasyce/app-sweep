#if os(macOS)
import Foundation
import XCTest
@testable import AppSweepCore

final class SystemCLICommandTests: XCTestCase {
    private func cli() throws -> String {
        let path = Bundle(for:SystemCLICommandTests.self).bundleURL.deletingLastPathComponent().appendingPathComponent("app-sweep").path
        guard FileManager.default.isExecutableFile(atPath:path) else { throw XCTSkip("Native SwiftPM sibling CLI required") }
        guard !FileManager.default.fileExists(atPath:RootServiceConfiguration.path) else { throw XCTSkip("These CLI rejection checks require the uninstalled-service fixture") }
        return path
    }
    func testInvalidSystemArgumentsFailAsUsageBeforeAnyServiceConnection() throws {
        let executable = try cli()
        let invalid = [
            ["system-status","--path","/System"],
            ["system-scan"],
            ["system-scan","--category","arbitrary"],
            ["system-scan","--category","caches","--category","logs"],
            ["system-apply","--category","caches","--yes"],
            ["system-recovery","--after","../other-user"],
            ["system-restore","--batch","/System"],
            ["system-purge","--batch",UUID().uuidString,"--confirm","yes"],
            ["system-unknown"]
        ]
        for args in invalid {
            let result = try BoundedProcess.capture(executable,arguments:args,timeout:10,mergeStderr:true)
            XCTAssertEqual(result.status,64,"Invalid arguments must be refused before the absent service is queried: \(args); \(result.text)")
        }
    }
    func testRecognizedReadCommandsReportServiceFailureInsteadOfSuccessOrUnknownCommand() throws {
        let executable = try cli()
        for args in [["system-status"],["system-scan","--category","logs"],["system-recovery"],["system-batch","--batch",UUID().uuidString]] {
            let result = try BoundedProcess.capture(executable,arguments:args,timeout:10,mergeStderr:true)
            XCTAssertEqual(result.status,1)
            XCTAssertFalse(result.text.contains("未知命令"),result.text)
            XCTAssertFalse(result.text.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty)
        }
    }
}
#endif
