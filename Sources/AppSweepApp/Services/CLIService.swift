import Foundation

enum CLIServiceError: LocalizedError {
    case executableMissing
    case commandFailed(status: Int32, stdout: String, stderr: String)
    case reportMissing(String)

    var errorDescription: String? {
        switch self {
        case .executableMissing:
            return "The bundled app-sweep CLI could not be found."
        case .commandFailed(let status, let stdout, let stderr):
            let body = [stderr, stdout].filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }.joined(separator: "\n")
            return "Command failed with status \(status).\n\(body)"
        case .reportMissing(let path):
            return "The CLI did not write the expected JSON report: \(path)"
        }
    }
}

struct CLIResult<ReportType: Sendable>: Sendable {
    let report: ReportType
    let reportURL: URL
    let stdout: String
    let stderr: String
}

struct CLIService {
    let executableURL: URL

    init() throws {
        if let bundled = Bundle.main.resourceURL?.appendingPathComponent("app-sweep-cli"),
           FileManager.default.isExecutableFile(atPath: bundled.path) {
            executableURL = bundled
            return
        }

        let developerPath = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent(".build/release/app-sweep")
        if FileManager.default.isExecutableFile(atPath: developerPath.path) {
            executableURL = developerPath
            return
        }

        let targetDeveloperPath = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent(".build/release/AppSweepCLI")
        if FileManager.default.isExecutableFile(atPath: targetDeveloperPath.path) {
            executableURL = targetDeveloperPath
            return
        }

        throw CLIServiceError.executableMissing
    }

    func scan(appPath: String) async throws -> CLIResult<Report> {
        try await run(["scan", appPath], reportPrefix: "scan")
    }

    func scanKnown(bundleIdentifier: String, appName: String) async throws -> CLIResult<Report> {
        try await run(["scan-known", bundleIdentifier, appName], reportPrefix: "scan-known")
    }

    func audit(appPath: String, full: Bool) async throws -> CLIResult<AuditReport> {
        try await run([full ? "audit-full" : "audit", appPath], reportPrefix: full ? "audit-full" : "audit")
    }

    func auditKnown(bundleIdentifier: String, appName: String, full: Bool) async throws -> CLIResult<AuditReport> {
        try await run([full ? "audit-full-known" : "audit-known", bundleIdentifier, appName], reportPrefix: full ? "audit-full-known" : "audit-known")
    }

    func backup(appPath: String, backupRoot: URL) async throws -> CLIResult<Report> {
        try await run(["backup", appPath, "--backup-root", backupRoot.path], reportPrefix: "backup")
    }

    func uninstall(appPath: String, backupRoot: URL?) async throws -> CLIResult<Report> {
        var args = ["uninstall", appPath, "--execute", "--trash-confirm"]
        if let backupRoot {
            args += ["--backup-root", backupRoot.path]
        }
        return try await run(args, reportPrefix: "uninstall")
    }

    func restore(reportPath: String) async throws -> CLIResult<RestoreReport> {
        try await run(["restore-report", reportPath, "--execute", "--restore-confirm"], reportPrefix: "restore")
    }

    private func run<T: Decodable & Sendable>(_ args: [String], reportPrefix: String) async throws -> CLIResult<T> {
        let reportURL = try makeReportURL(prefix: reportPrefix)
        var finalArgs = args
        finalArgs += ["--json", reportURL.path]

        let process = Process()
        process.executableURL = executableURL
        process.arguments = finalArgs

        let stdoutURL = temporaryOutputURL(prefix: "stdout")
        let stderrURL = temporaryOutputURL(prefix: "stderr")
        FileManager.default.createFile(atPath: stdoutURL.path, contents: nil)
        FileManager.default.createFile(atPath: stderrURL.path, contents: nil)
        let stdoutHandle = try FileHandle(forWritingTo: stdoutURL)
        let stderrHandle = try FileHandle(forWritingTo: stderrURL)
        process.standardOutput = stdoutHandle
        process.standardError = stderrHandle

        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    try process.run()
                    process.waitUntilExit()

                    stdoutHandle.closeFile()
                    stderrHandle.closeFile()
                    defer {
                        try? FileManager.default.removeItem(at: stdoutURL)
                        try? FileManager.default.removeItem(at: stderrURL)
                    }

                    let stdoutText = (try? String(contentsOf: stdoutURL)) ?? ""
                    let stderrText = (try? String(contentsOf: stderrURL)) ?? ""

                    guard process.terminationStatus == 0 else {
                        continuation.resume(throwing: CLIServiceError.commandFailed(
                            status: process.terminationStatus,
                            stdout: stdoutText,
                            stderr: stderrText
                        ))
                        return
                    }

                    guard FileManager.default.fileExists(atPath: reportURL.path) else {
                        continuation.resume(throwing: CLIServiceError.reportMissing(reportURL.path))
                        return
                    }

                    let data = try Data(contentsOf: reportURL)
                    let report = try JSONDecoder().decode(T.self, from: data)
                    continuation.resume(returning: CLIResult(
                        report: report,
                        reportURL: reportURL,
                        stdout: stdoutText,
                        stderr: stderrText
                    ))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private func makeReportURL(prefix: String) throws -> URL {
        let root = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("App Sweep/reports/gui-\(AppFormatters.timestampSlug())", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root.appendingPathComponent("\(prefix)-\(UUID().uuidString.prefix(8)).json")
    }

    private func temporaryOutputURL(prefix: String) -> URL {
        URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("app-sweep-\(prefix)-\(UUID().uuidString).txt")
    }
}
