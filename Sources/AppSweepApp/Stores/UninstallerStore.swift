import Foundation

@MainActor
final class UninstallerStore: ObservableObject {
    @Published var apps: [InstalledApp] = []
    @Published var selectedApp: InstalledApp?
    @Published var scanReport: Report?
    @Published var auditReport: AuditReport?
    @Published var restoreReport: RestoreReport?
    @Published var isRunning = false
    @Published var statusMessage = "Ready"
    @Published var errorMessage: String?
    @Published var logLines: [String] = []
    @Published var lastReportURL: URL?
    @Published var backupRootURL: URL
    @Published var backupItems: [BackupItem] = []
    @Published var lastBackupDirectory: URL?

    private let inventory = AppInventoryService()
    private let cli: CLIService

    var canRunAction: Bool {
        selectedApp != nil && !isRunning
    }

    init() {
        backupRootURL = Self.defaultBackupRootURL()
        do {
            cli = try CLIService()
            appendLog("Using CLI: \(cli.executableURL.path)")
        } catch {
            cli = CLIService(executableURL: URL(fileURLWithPath: "/usr/bin/false"))
            errorMessage = error.localizedDescription
        }
        refreshApps()
        refreshBackups(log: false)
    }

    private init(cli: CLIService) {
        self.cli = cli
        backupRootURL = Self.defaultBackupRootURL()
    }

    func refreshApps() {
        apps = inventory.loadInstalledApps()
        if let selectedApp, !apps.contains(selectedApp) {
            self.selectedApp = nil
            scanReport = nil
            auditReport = nil
        }
        appendLog("Loaded \(apps.count) applications from /Applications and ~/Applications.")
    }

    func select(_ app: InstalledApp) {
        selectedApp = app
        scanReport = nil
        auditReport = nil
        restoreReport = nil
        errorMessage = nil
        statusMessage = "Selected \(app.name)"
    }

    func chooseApplication() {
        guard let url = AppKitPanels.chooseApplication() else { return }
        let app = installedApp(from: url)
        if !apps.contains(app) {
            apps.append(app)
            apps.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        }
        select(app)
    }

    func runScan() {
        guard let selectedApp else { return }
        run("Scanning \(selectedApp.name)") {
            let result = try await self.cli.scan(appPath: selectedApp.path)
            self.scanReport = result.report
            self.lastReportURL = result.reportURL
            self.statusMessage = "Scan complete: \(result.report.summary.existingCandidates) existing candidates"
            self.appendCLIOutput(result.stdout, result.stderr)
        }
    }

    func runFullAudit() {
        guard let selectedApp else { return }
        run("Running full audit for \(selectedApp.name)") {
            let result = try await self.cli.audit(appPath: selectedApp.path, full: true)
            self.auditReport = result.report
            self.lastReportURL = result.reportURL
            self.statusMessage = "Full audit complete: \(result.report.summary.strongPathMatchCount) strong matches"
            self.appendCLIOutput(result.stdout, result.stderr)
        }
    }

    func runBackup() {
        guard let selectedApp else { return }
        run("Backing up \(selectedApp.name)") {
            let backupRoot = self.defaultBackupRoot()
            let result = try await self.cli.backup(appPath: selectedApp.path, backupRoot: backupRoot)
            self.scanReport = result.report
            self.lastReportURL = result.reportURL
            self.handleBackupLocations(from: result.report, fallbackRoot: backupRoot)
            self.statusMessage = "Backup complete: \(result.report.candidates.filter { $0.status == .backedUp }.count) items"
            self.appendCLIOutput(result.stdout, result.stderr)
        }
    }

    func runUninstall(backupFirst: Bool) {
        guard let selectedApp else { return }
        run("Uninstalling \(selectedApp.name)") {
            let backupRoot = backupFirst ? self.defaultBackupRoot() : nil
            let result = try await self.cli.uninstall(
                appPath: selectedApp.path,
                backupRoot: backupRoot
            )
            self.scanReport = result.report
            self.lastReportURL = result.reportURL
            if let backupRoot {
                self.handleBackupLocations(from: result.report, fallbackRoot: backupRoot)
            }
            self.statusMessage = "Uninstall complete: \(result.report.candidates.filter { $0.status == .trashed }.count) moved to Trash"
            self.appendCLIOutput(result.stdout, result.stderr)
            self.refreshApps()
        }
    }

    func chooseAndRestoreBackupReport() {
        guard let url = AppKitPanels.chooseBackupReport() else { return }
        run("Restoring from \(url.lastPathComponent)") {
            let result = try await self.cli.restore(reportPath: url.path)
            self.restoreReport = result.report
            self.lastReportURL = result.reportURL
            self.statusMessage = "Restore complete: \(result.report.summary.restored) restored"
            self.appendCLIOutput(result.stdout, result.stderr)
            self.refreshApps()
        }
    }

    func refreshBackups(log: Bool = true) {
        let root = defaultBackupRoot()
        backupRootURL = root
        if log {
            appendLog("Refreshing backups from \(root.path)")
        }

        Task {
            let items = await Task.detached(priority: .utility) {
                BackupCatalog.load(from: root)
            }.value
            self.backupItems = items
        }
    }

    func revealBackupRoot() {
        do {
            try FileManager.default.createDirectory(at: backupRootURL, withIntermediateDirectories: true)
            AppKitPanels.revealInFinder(backupRootURL)
            appendLog("Revealed backup root: \(backupRootURL.path)")
        } catch {
            errorMessage = error.localizedDescription
            statusMessage = "Failed"
            appendLog("ERROR: \(error.localizedDescription)")
        }
    }

    func revealBackup(_ item: BackupItem) {
        AppKitPanels.revealInFinder(item.url)
        appendLog("Revealed backup: \(item.url.path)")
    }

    func deleteBackup(_ item: BackupItem) {
        guard isManagedBackupURL(item.url) else {
            errorMessage = "Refusing to delete a path outside the GUI backup folder."
            statusMessage = "Failed"
            appendLog("ERROR: Refused to delete unmanaged backup path \(item.url.path)")
            return
        }

        isRunning = true
        errorMessage = nil
        statusMessage = "Deleting backup \(item.name)"
        appendLog("Deleting backup: \(item.url.path)")

        Task {
            do {
                let targetURL = item.url
                try await Task.detached(priority: .utility) {
                    try FileManager().removeItem(at: targetURL)
                }.value
                if self.lastBackupDirectory?.standardizedFileURL.path == targetURL.standardizedFileURL.path {
                    self.lastBackupDirectory = nil
                }
                self.statusMessage = "Deleted backup: \(item.name)"
                self.appendLog("Deleted backup: \(targetURL.path)")
                self.refreshBackups(log: false)
            } catch {
                self.errorMessage = error.localizedDescription
                self.statusMessage = "Failed"
                self.appendLog("ERROR: \(error.localizedDescription)")
            }
            self.isRunning = false
        }
    }

    private func run(_ message: String, operation: @escaping () async throws -> Void) {
        isRunning = true
        errorMessage = nil
        statusMessage = message
        appendLog(message)

        Task {
            do {
                try await operation()
            } catch {
                errorMessage = error.localizedDescription
                statusMessage = "Failed"
                appendLog("ERROR: \(error.localizedDescription)")
            }
            isRunning = false
        }
    }

    private func installedApp(from url: URL) -> InstalledApp {
        let bundle = Bundle(url: url)
        let bundleIdentifier = bundle?.bundleIdentifier ?? ""
        let fallbackName = url.deletingPathExtension().lastPathComponent
        let displayName = (bundle?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)?.nilIfBlank
            ?? (bundle?.object(forInfoDictionaryKey: "CFBundleName") as? String)?.nilIfBlank
            ?? fallbackName
        return InstalledApp(
            id: url.standardizedFileURL.path,
            name: displayName,
            path: url.standardizedFileURL.path,
            bundleIdentifier: bundleIdentifier,
            isAppleProtected: bundleIdentifier.hasPrefix("com.apple.")
        )
    }

    private func defaultBackupRoot() -> URL {
        Self.defaultBackupRootURL()
    }

    private static func defaultBackupRootURL() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("App Sweep/backups/gui", isDirectory: true)
    }

    private func handleBackupLocations(from report: Report, fallbackRoot: URL) {
        let backupDirectories = extractBackupDirectories(from: report)
        if let path = backupDirectories.first {
            let url = URL(fileURLWithPath: path)
            lastBackupDirectory = url
            appendLog("Backup directory: \(url.path)")
        } else if report.candidates.contains(where: { $0.status == .backedUp || $0.status == .trashed }) {
            appendLog("Backup root: \(fallbackRoot.path)")
        }
        refreshBackups(log: false)
    }

    private func extractBackupDirectories(from report: Report) -> [String] {
        let paths = report.candidates.compactMap { candidate -> String? in
            guard let backupPath = Self.extractBackupPath(from: candidate.detail) else { return nil }
            if let filesRange = backupPath.range(of: "/files/") {
                return String(backupPath[..<filesRange.lowerBound])
            }
            return URL(fileURLWithPath: backupPath).deletingLastPathComponent().deletingLastPathComponent().path
        }
        return Array(Set(paths)).sorted()
    }

    private static func extractBackupPath(from detail: String?) -> String? {
        guard let detail else { return nil }
        let prefix = "Backed up to "
        guard let range = detail.range(of: prefix) else { return nil }
        let remainder = detail[range.upperBound...]
        let firstLine = remainder.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false).first
        return firstLine.map(String.init)?.trimmingCharacters(in: .whitespacesAndNewlines).nilIfBlank
    }

    private func isManagedBackupURL(_ url: URL) -> Bool {
        let rootPath = backupRootURL.standardizedFileURL.path
        let targetPath = url.standardizedFileURL.path
        return targetPath.hasPrefix(rootPath + "/") && targetPath != rootPath
    }

    private func appendCLIOutput(_ stdout: String, _ stderr: String) {
        [stdout, stderr]
            .flatMap { $0.split(separator: "\n").map(String.init) }
            .filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
            .forEach(appendLog)
    }

    private func appendLog(_ line: String) {
        logLines.append("[\(Date().formatted(date: .omitted, time: .standard))] \(line)")
        if logLines.count > 300 {
            logLines.removeFirst(logLines.count - 300)
        }
    }
}

extension CLIService {
    fileprivate init(executableURL: URL) {
        self.executableURL = executableURL
    }
}
