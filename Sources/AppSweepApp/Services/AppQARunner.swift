import AppKit
import Foundation

struct AppQASummary: Codable, Sendable {
    let generatedAt: String
    let appPath: String
    let backupReportPath: String?
    let restored: RestoreSummary?
    let scanBeforeExisting: Int
    let backupFailed: Int
    let uninstallTrashed: Int
    let uninstallFailed: Int
    let scanAfterExisting: Int
    let auditAfterStrongMatches: Int
    let auditAfterRegistrationMatches: Int
    let auditAfterUnreadableErrors: Int
    let reportPaths: [String: String]
    let verdict: String
}

enum AppQAError: LocalizedError {
    case missingRequiredOption(String)
    case missingExecutionConfirmation
    case missingAppAndRestoreSource(String)

    var errorDescription: String? {
        switch self {
        case .missingRequiredOption(let option):
            return "QA mode requires \(option)."
        case .missingExecutionConfirmation:
            return "QA mode requires --qa-execute-uninstall to run uninstall checks."
        case .missingAppAndRestoreSource(let path):
            return "QA app path does not exist and no backup report was supplied: \(path)"
        }
    }
}

enum AppQARunner {
    static func maybeRunFromArguments() -> Bool {
        let args = CommandLine.arguments
        guard args.contains("--qa-app-test") else { return false }

        Task {
            do {
                let summary = try await run(arguments: args)
                let outPath = outputPath(from: args)
                try write(summary: summary, to: outPath)
                fputs("QA summary: \(outPath)\n", stdout)
                await MainActor.run {
                    NSApp.terminate(nil)
                }
            } catch {
                fputs("QA failed: \(error.localizedDescription)\n", stderr)
                await MainActor.run {
                    NSApp.terminate(nil)
                }
            }
        }

        return true
    }

    private static func run(arguments: [String]) async throws -> AppQASummary {
        guard let appPath = value(after: "--app", in: arguments) else {
            throw AppQAError.missingRequiredOption("--app <App.app>")
        }
        guard arguments.contains("--qa-execute-uninstall") else {
            throw AppQAError.missingExecutionConfirmation
        }
        let backupReportPath = value(after: "--backup-report", in: arguments)
        let cli = try CLIService()
        var reports: [String: String] = [:]
        var restored: RestoreSummary?

        if !FileManager.default.fileExists(atPath: appPath) {
            guard let backupReportPath else {
                throw AppQAError.missingAppAndRestoreSource(appPath)
            }
            let restore = try await cli.restore(reportPath: backupReportPath)
            restored = restore.report.summary
            reports["restore"] = restore.reportURL.path
        }

        let scanBefore = try await cli.scan(appPath: appPath)
        reports["scanBefore"] = scanBefore.reportURL.path

        let app = scanBefore.report.app
        let backupRoot = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("App Sweep/backups/app-qa-\(AppFormatters.timestampSlug())", isDirectory: true)
        let backup = try await cli.backup(appPath: appPath, backupRoot: backupRoot)
        reports["backup"] = backup.reportURL.path

        let uninstall = try await cli.uninstall(appPath: appPath, backupRoot: nil)
        reports["uninstall"] = uninstall.reportURL.path

        let scanAfter = try await cli.scanKnown(bundleIdentifier: app.bundleIdentifier, appName: app.displayName)
        reports["scanAfter"] = scanAfter.reportURL.path

        let auditAfter = try await cli.auditKnown(bundleIdentifier: app.bundleIdentifier, appName: app.displayName, full: false)
        reports["auditAfter"] = auditAfter.reportURL.path

        let backupFailed = backup.report.candidates.filter { $0.status == .backupFailed }.count
        let uninstallTrashed = uninstall.report.candidates.filter { $0.status == .trashed }.count
        let uninstallFailed = uninstall.report.candidates.filter { $0.status == .trashFailed }.count
        let verdict = scanAfter.report.summary.existingCandidates == 0 && uninstallFailed == 0
            ? "passed"
            : "needs-review"

        return AppQASummary(
            generatedAt: ISO8601DateFormatter().string(from: Date()),
            appPath: appPath,
            backupReportPath: backupReportPath,
            restored: restored,
            scanBeforeExisting: scanBefore.report.summary.existingCandidates,
            backupFailed: backupFailed,
            uninstallTrashed: uninstallTrashed,
            uninstallFailed: uninstallFailed,
            scanAfterExisting: scanAfter.report.summary.existingCandidates,
            auditAfterStrongMatches: auditAfter.report.summary.strongPathMatchCount,
            auditAfterRegistrationMatches: auditAfter.report.summary.registrationMatchCount,
            auditAfterUnreadableErrors: auditAfter.report.summary.unreadableErrorCount,
            reportPaths: reports,
            verdict: verdict
        )
    }

    private static func outputPath(from args: [String]) -> String {
        if let value = value(after: "--out", in: args) {
            return NSString(string: value).expandingTildeInPath
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("App Sweep/reports/app-qa-\(AppFormatters.timestampSlug()).json")
            .path
    }

    private static func write(summary: AppQASummary, to path: String) throws {
        let outputURL = URL(fileURLWithPath: path)
        try FileManager.default.createDirectory(
            at: outputURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(summary)
        try data.write(to: outputURL, options: .atomic)
    }

    private static func value(after option: String, in args: [String]) -> String? {
        guard let index = args.firstIndex(of: option), args.indices.contains(index + 1) else {
            return nil
        }
        return args[index + 1]
    }
}
