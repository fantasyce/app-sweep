import Foundation

enum CommandError: Error, CustomStringConvertible {
    case invalidUsage(String)
    case appNotFound(String)
    case notAnAppBundle(String)
    case protectedAppleApp(String)
    case missingBundleIdentifier(String)
    case commandFailed(String)

    var description: String {
        switch self {
        case .invalidUsage(let message), .appNotFound(let message), .notAnAppBundle(let message),
             .protectedAppleApp(let message), .missingBundleIdentifier(let message),
             .commandFailed(let message):
            return message
        }
    }
}

enum Confidence: String, Codable {
    case high
    case medium
    case reportOnly
    case blocked
}

enum CandidateAction: String, Codable {
    case trash
    case reportOnly
    case blocked
}

enum CandidateStatus: String, Codable {
    case exists
    case missing
    case trashed
    case backedUp
    case backupFailed
    case trashFailed
    case skipped
}

struct AppIdentity: Codable {
    let appPath: String
    let bundleIdentifier: String
    let bundleName: String
    let displayName: String
    let executableName: String
    let normalizedNames: [String]
    let teamIdentifier: String?
}

struct Candidate: Codable {
    let path: String
    let reason: String
    let confidence: Confidence
    let action: CandidateAction
    let risk: String
    let exists: Bool
    let isDirectory: Bool
    let isSymlink: Bool
    let sizeBytes: UInt64
    var status: CandidateStatus
    var detail: String?
}

struct Report: Codable {
    let generatedAt: String
    let command: String
    let toolVersion: String
    let app: AppIdentity
    let summary: Summary
    let candidates: [Candidate]
}

struct AuditReport: Codable {
    let generatedAt: String
    let command: String
    let toolVersion: String
    let app: AppIdentity
    let strongPatterns: [String]
    let strongPathMatches: [String]
    let genericNameMatches: [String]
    let registrations: [AuditSection]
    let unreadableErrors: [String]
    let summary: AuditSummary
}

struct PathOperationReport: Codable {
    let generatedAt: String
    let command: String
    let toolVersion: String
    let candidate: Candidate
}

struct RestoreReport: Codable {
    let generatedAt: String
    let command: String
    let toolVersion: String
    let sourceReportPath: String
    let items: [RestoreItem]
    let summary: RestoreSummary
}

struct RestoreItem: Codable {
    let originalPath: String
    let backupPath: String?
    let status: String
    let detail: String?
}

struct RestoreSummary: Codable {
    let restored: Int
    let skippedExisting: Int
    let missingBackup: Int
    let failed: Int
}

struct FindRootSpec {
    let path: String
    let maxDepth: Int?
    let timeoutSeconds: Int
}

struct AuditSection: Codable {
    let name: String
    let command: String
    let matches: [String]
}

struct AuditSummary: Codable {
    let strongPathMatchCount: Int
    let genericNameMatchCount: Int
    let registrationMatchCount: Int
    let unreadableErrorCount: Int
}

struct Summary: Codable {
    let totalCandidates: Int
    let existingCandidates: Int
    let trashEligibleExisting: Int
    let reportOnlyExisting: Int
    let blockedExisting: Int
    let totalExistingBytes: UInt64
}

struct Options {
    let command: String
    let appPath: String
    let knownAppName: String?
    let jsonPath: String?
    let backupRoot: String?
    let execute: Bool
    let trashConfirm: Bool
    let restoreConfirm: Bool
}

nonisolated(unsafe) let fileManager = FileManager.default
let toolVersion = "5.5.0-cli"

func usage() -> String {
    """
    Usage:
      app-sweep scan <App.app> [--json <report.json>]
      app-sweep scan-known <bundle-id> <app-name> [--json <report.json>]
      app-sweep audit <App.app> [--json <report.json>]
      app-sweep audit-known <bundle-id> <app-name> [--json <report.json>]
      app-sweep audit-full <App.app> [--json <report.json>]
      app-sweep audit-full-known <bundle-id> <app-name> [--json <report.json>]
      app-sweep trash-path <path> --execute --trash-confirm [--json <report.json>]
      app-sweep restore-report <backup-report.json> --execute --restore-confirm [--json <report.json>]
      app-sweep backup <App.app> --backup-root <dir> [--json <report.json>]
      app-sweep backup-known <bundle-id> <app-name> --backup-root <dir> [--json <report.json>]
      app-sweep uninstall <App.app> --execute --trash-confirm [--backup-root <dir>] [--json <report.json>]
      app-sweep uninstall-known <bundle-id> <app-name> --execute --trash-confirm [--backup-root <dir>] [--json <report.json>]

    Notes:
      scan and audit are read-only.
      backup copies app bundle and trash-eligible existing candidates into a timestamped backup folder.
      restore-report restores only backed-up items from a previous backup JSON and never overwrites existing paths.
      uninstall moves only trash-eligible existing candidates to Trash and requires --execute --trash-confirm.
      if the primary app bundle cannot be moved to Trash, remaining leftovers are skipped to avoid a partial uninstall.
      *-known variants work from bundle id and app name when the .app bundle is already gone.
      audit checks global strong path matches, weak name matches, package receipts, launchctl, background tasks, and launch/helper content.
      audit-full performs a broader read-only scan from root volumes and records unreadable permission errors.
    """
}

func parseOptions(_ args: [String]) throws -> Options {
    guard args.count >= 2 else {
        throw CommandError.invalidUsage(usage())
    }

    let command = args[0]
    guard ["scan", "scan-known", "audit", "audit-known", "audit-full", "audit-full-known", "trash-path", "restore-report", "backup", "backup-known", "uninstall", "uninstall-known"].contains(command) else {
        throw CommandError.invalidUsage(usage())
    }

    let appPath = args[1]
    var knownAppName: String?
    var jsonPath: String?
    var backupRoot: String?
    var execute = false
    var trashConfirm = false
    var restoreConfirm = false

    var index = 2
    if isKnownCommand(command) {
        guard args.count >= 3 else {
            throw CommandError.invalidUsage("\(command) requires <bundle-id> <app-name>\n\n\(usage())")
        }
        knownAppName = args[2]
        index = 3
    }

    while index < args.count {
        let arg = args[index]
        switch arg {
        case "--json":
            guard index + 1 < args.count else { throw CommandError.invalidUsage("--json requires a path") }
            jsonPath = args[index + 1]
            index += 2
        case "--backup-root":
            guard index + 1 < args.count else { throw CommandError.invalidUsage("--backup-root requires a path") }
            backupRoot = args[index + 1]
            index += 2
        case "--execute":
            execute = true
            index += 1
        case "--trash-confirm":
            trashConfirm = true
            index += 1
        case "--restore-confirm":
            restoreConfirm = true
            index += 1
        case "--help", "-h":
            throw CommandError.invalidUsage(usage())
        default:
            throw CommandError.invalidUsage("Unknown option: \(arg)\n\n\(usage())")
        }
    }

    if (command == "backup" || command == "backup-known"), backupRoot == nil {
        throw CommandError.invalidUsage("\(command) requires --backup-root\n\n\(usage())")
    }

    if (command == "uninstall" || command == "uninstall-known" || command == "trash-path"), (!execute || !trashConfirm) {
        throw CommandError.invalidUsage("\(command) requires --execute --trash-confirm\n\n\(usage())")
    }

    if command == "restore-report", (!execute || !restoreConfirm) {
        throw CommandError.invalidUsage("restore-report requires --execute --restore-confirm\n\n\(usage())")
    }

    return Options(
        command: command,
        appPath: appPath,
        knownAppName: knownAppName,
        jsonPath: jsonPath,
        backupRoot: backupRoot,
        execute: execute,
        trashConfirm: trashConfirm,
        restoreConfirm: restoreConfirm
    )
}

func isKnownCommand(_ command: String) -> Bool {
    ["scan-known", "audit-known", "audit-full-known", "backup-known", "uninstall-known"].contains(command)
}

func knownAppIdentity(bundleIdentifier: String, appName: String) throws -> AppIdentity {
    if bundleIdentifier == "com.apple.finder" || bundleIdentifier.hasPrefix("com.apple.") {
        throw CommandError.protectedAppleApp("Refusing to process Apple/system app with bundle id: \(bundleIdentifier)")
    }

    let normalizedNames = normalizedNameVariants([appName])
    return AppIdentity(
        appPath: "/Applications/\(appName).app",
        bundleIdentifier: bundleIdentifier,
        bundleName: appName,
        displayName: appName,
        executableName: appName,
        normalizedNames: normalizedNames,
        teamIdentifier: nil
    )
}

func appIdentityFromOptions(_ options: Options) throws -> AppIdentity {
    if isKnownCommand(options.command) {
        guard let knownAppName = options.knownAppName else {
            throw CommandError.invalidUsage("\(options.command) requires an app name")
        }
        return try knownAppIdentity(bundleIdentifier: options.appPath, appName: knownAppName)
    }

    return try loadAppIdentity(appPath: options.appPath)
}

func expandTilde(_ path: String) -> String {
    NSString(string: path).expandingTildeInPath
}

func standardPath(_ path: String) -> String {
    URL(fileURLWithPath: expandTilde(path)).standardizedFileURL.path
}

func homePath(_ suffix: String = "") -> String {
    let base = fileManager.homeDirectoryForCurrentUser.path
    return suffix.isEmpty ? base : base + "/" + suffix
}

func loadAppIdentity(appPath rawAppPath: String) throws -> AppIdentity {
    let appPath = standardPath(rawAppPath)
    var isDirectory: ObjCBool = false
    guard fileManager.fileExists(atPath: appPath, isDirectory: &isDirectory) else {
        throw CommandError.appNotFound("App does not exist: \(appPath)")
    }
    guard isDirectory.boolValue, appPath.hasSuffix(".app") else {
        throw CommandError.notAnAppBundle("Path is not an .app bundle: \(appPath)")
    }

    let infoPath = appPath + "/Contents/Info.plist"
    guard let info = NSDictionary(contentsOfFile: infoPath) as? [String: Any] else {
        throw CommandError.notAnAppBundle("Unable to read Info.plist: \(infoPath)")
    }
    guard let bundleIdentifier = info["CFBundleIdentifier"] as? String, !bundleIdentifier.isEmpty else {
        throw CommandError.missingBundleIdentifier("App has no CFBundleIdentifier: \(appPath)")
    }
    if bundleIdentifier == "com.apple.finder" || bundleIdentifier.hasPrefix("com.apple.") {
        throw CommandError.protectedAppleApp("Refusing to process Apple/system app with bundle id: \(bundleIdentifier)")
    }

    let url = URL(fileURLWithPath: appPath)
    let fallbackName = url.deletingPathExtension().lastPathComponent
    let bundleName = (info["CFBundleName"] as? String)?.nilIfBlank ?? fallbackName
    let displayName = (info["CFBundleDisplayName"] as? String)?.nilIfBlank ?? bundleName
    let executableName = (info["CFBundleExecutable"] as? String)?.nilIfBlank ?? bundleName
    let normalizedNames = normalizedNameVariants([fallbackName, bundleName, displayName, executableName])
    let teamIdentifier = readTeamIdentifier(appPath: appPath)

    return AppIdentity(
        appPath: appPath,
        bundleIdentifier: bundleIdentifier,
        bundleName: bundleName,
        displayName: displayName,
        executableName: executableName,
        normalizedNames: normalizedNames,
        teamIdentifier: teamIdentifier
    )
}

func readTeamIdentifier(appPath: String) -> String? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
    process.arguments = ["-dv", appPath]

    let pipe = Pipe()
    process.standardError = pipe
    process.standardOutput = Pipe()

    do {
        try process.run()
        process.waitUntilExit()
    } catch {
        return nil
    }

    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    guard let output = String(data: data, encoding: .utf8) else { return nil }
    for line in output.split(separator: "\n") {
        if line.hasPrefix("TeamIdentifier=") {
            return String(line.dropFirst("TeamIdentifier=".count)).nilIfBlank
        }
    }
    return nil
}

func normalizedNameVariants(_ names: [String]) -> [String] {
    var result: [String] = []
    for name in names {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { continue }
        let variants = [
            trimmed,
            trimmed.lowercased(),
            trimmed.replacingOccurrences(of: " ", with: ""),
            trimmed.lowercased().replacingOccurrences(of: " ", with: ""),
            trimmed.replacingOccurrences(of: "-", with: ""),
            trimmed.lowercased().replacingOccurrences(of: "-", with: "")
        ]
        for variant in variants where !variant.isEmpty && !result.contains(variant) {
            result.append(variant)
        }
    }
    return result
}

func scanCandidates(for app: AppIdentity) -> [Candidate] {
    var candidates: [Candidate] = []
    var seen = Set<String>()

    func add(_ path: String, reason: String, confidence: Confidence, action: CandidateAction, risk: String) {
        let standardized = standardPath(path)
        guard !seen.contains(standardized) else { return }
        seen.insert(standardized)

        let inspected = inspectCandidate(path: standardized, reason: reason, confidence: confidence, action: action, risk: risk)
        candidates.append(inspected)
    }

    let bundleID = app.bundleIdentifier
    let appNames = app.normalizedNames

    add(app.appPath, reason: "App bundle selected by user", confidence: .high, action: .trash, risk: "normal")

    let highBundlePaths = [
        homePath("Library/Application Support/\(bundleID)"),
        homePath("Library/Caches/\(bundleID)"),
        homePath("Library/Caches/com.apple.nsurlsessiond/Downloads/\(bundleID)"),
        homePath("Library/Preferences/\(bundleID).plist"),
        homePath("Library/Preferences/\(bundleID).plist.lockfile"),
        homePath("Library/Preferences/ByHost/\(bundleID)"),
        homePath("Library/Logs/\(bundleID)"),
        homePath("Library/Saved Application State/\(bundleID).savedState"),
        homePath("Library/HTTPStorages/\(bundleID)"),
        homePath("Library/HTTPStorages/\(bundleID).binarycookies"),
        homePath("Library/WebKit/\(bundleID)"),
        homePath("Library/Containers/\(bundleID)"),
        homePath("Library/Group Containers/\(bundleID)"),
        homePath("Library/Application Scripts/\(bundleID)"),
        homePath("Library/Cookies/\(bundleID).binarycookies"),
        homePath("Library/LaunchAgents/\(bundleID).plist")
    ]
    for path in highBundlePaths {
        add(path, reason: "Exact bundle identifier match: \(bundleID)", confidence: .high, action: .trash, risk: "low")
    }

    let highBundlePrefixParents = [
        homePath("Library/Caches"),
        homePath("Library/HTTPStorages"),
        homePath("Library/Preferences"),
        homePath("Library/Cookies"),
        homePath("Library/Logs"),
        homePath("Library/WebKit"),
        homePath("Library/Application Support"),
        homePath("Library/Containers"),
        homePath("Library/Group Containers"),
        homePath("Library/Application Scripts"),
        homePath("Library/Saved Application State"),
        homePath("Library/LaunchAgents")
    ]
    for parent in highBundlePrefixParents {
        addGlob(parent: parent, prefix: bundleID + ".", reason: "Bundle identifier prefix match: \(bundleID)", confidence: .high, action: .trash, risk: "low", into: &candidates, seen: &seen)
    }

    for name in appNames {
        let mediumPaths = [
            homePath("Library/Application Support/\(name)"),
            homePath("Library/Caches/\(name)"),
            homePath("Library/Logs/\(name)"),
            homePath("Library/WebKit/\(name)"),
            homePath("Library/Preferences/\(name).plist"),
            homePath("Library/Application Scripts/\(name)"),
            homePath("Library/Containers/\(name)"),
            homePath("Library/Group Containers/\(name)"),
            homePath("Library/Saved Application State/\(name).savedState"),
            homePath("Library/Services/\(name).service"),
            homePath("Library/QuickLook/\(name).qlgenerator"),
            homePath("Library/Spotlight/\(name).mdimporter"),
            homePath("Library/PreferencePanes/\(name).prefPane"),
            homePath("Library/Internet Plug-Ins/\(name).plugin"),
            homePath(".config/\(name)"),
            homePath(".cache/\(name)"),
            homePath(".local/share/\(name)"),
            homePath(".\(name)")
        ]
        for path in mediumPaths {
            add(path, reason: "Exact app-name variant match: \(name)", confidence: .medium, action: .trash, risk: "medium")
        }
    }

    addGlob(parent: homePath("Library/Preferences/ByHost"), prefix: bundleID + ".", reason: "ByHost plist prefix matches bundle identifier: \(bundleID)", confidence: .high, action: .trash, risk: "low", into: &candidates, seen: &seen)
    addPrivateVarFolderBundleMatches(app: app, into: &candidates, seen: &seen)

    let reportOnlyRoots = [
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/Library/PrivilegedHelperTools",
        "/Library/Application Support",
        "/Library/Caches",
        "/Library/Preferences",
        "/Library/Logs",
        "/Library/SystemExtensions",
        "/Library/Extensions",
        "/Library/QuickLook",
        "/Library/Spotlight",
        "/Library/PreferencePanes",
        "/Library/Internet Plug-Ins",
        "/Library/Services",
        "/Library/Receipts",
        "/private/var/db/receipts",
        "/usr/local/bin",
        "/opt/homebrew/bin"
    ]
    for root in reportOnlyRoots {
        addNameMatches(in: root, app: app, into: &candidates, seen: &seen)
    }

    return deduplicatedCandidates(candidates).sorted {
        if $0.exists != $1.exists { return $0.exists && !$1.exists }
        if $0.confidence.rawValue != $1.confidence.rawValue { return $0.confidence.rawValue < $1.confidence.rawValue }
        return $0.path < $1.path
    }
}

func deduplicatedCandidates(_ candidates: [Candidate]) -> [Candidate] {
    var seen = Set<String>()
    var result: [Candidate] = []

    for candidate in candidates {
        let key = fileIdentityKey(candidate.path) ?? "path:\(standardPath(candidate.path).lowercased())"
        guard !seen.contains(key) else { continue }
        seen.insert(key)
        result.append(candidate)
    }

    return result
}

func fileIdentityKey(_ path: String) -> String? {
    let url = URL(fileURLWithPath: path)
    guard let values = try? url.resourceValues(forKeys: [.fileResourceIdentifierKey, .volumeIdentifierKey]),
          let fileID = values.fileResourceIdentifier,
          let volumeID = values.volumeIdentifier else {
        return nil
    }
    return "file:\(volumeID):\(fileID)"
}

func addGlob(parent: String, prefix: String, reason: String, confidence: Confidence, action: CandidateAction, risk: String, into candidates: inout [Candidate], seen: inout Set<String>) {
    let parentPath = standardPath(parent)
    guard let children = try? fileManager.contentsOfDirectory(atPath: parentPath) else { return }
    for child in children where child.hasPrefix(prefix) {
        let path = parentPath + "/" + child
        guard !seen.contains(path) else { continue }
        seen.insert(path)
        candidates.append(inspectCandidate(path: path, reason: reason, confidence: confidence, action: action, risk: risk))
    }
}

func addNameMatches(in root: String, app: AppIdentity, into candidates: inout [Candidate], seen: inout Set<String>) {
    let rootPath = standardPath(root)
    guard let children = try? fileManager.contentsOfDirectory(atPath: rootPath) else { return }
    for child in children {
        let lowered = child.lowercased()
        let matched = lowered.contains(app.bundleIdentifier.lowercased()) ||
            app.normalizedNames.contains(where: { !$0.isEmpty && lowered.contains($0.lowercased()) })
        guard matched else { continue }
        let path = rootPath + "/" + child
        guard !seen.contains(path) else { continue }
        seen.insert(path)
        candidates.append(inspectCandidate(path: path, reason: "Name or bundle identifier appears in system-level location: \(rootPath)", confidence: .reportOnly, action: .reportOnly, risk: "high"))
    }
}

func addPrivateVarFolderBundleMatches(app: AppIdentity, into candidates: inout [Candidate], seen: inout Set<String>) {
    let root = "/private/var/folders"
    guard let firstLevel = try? fileManager.contentsOfDirectory(atPath: root) else { return }

    for first in firstLevel where !first.hasPrefix(".") {
        let firstPath = root + "/" + first
        guard isDirectory(firstPath),
              let secondLevel = try? fileManager.contentsOfDirectory(atPath: firstPath) else { continue }

        for second in secondLevel where !second.hasPrefix(".") {
            let secondPath = firstPath + "/" + second
            guard isDirectory(secondPath) else { continue }

            for bucket in ["C", "T"] {
                let bucketPath = secondPath + "/" + bucket
                guard isDirectory(bucketPath) else { continue }
                addCandidate(
                    bucketPath + "/" + app.bundleIdentifier,
                    reason: "Exact bundle identifier cache under /private/var/folders: \(app.bundleIdentifier)",
                    confidence: .high,
                    action: .trash,
                    risk: "medium",
                    into: &candidates,
                    seen: &seen
                )
                addGlob(
                    parent: bucketPath,
                    prefix: app.bundleIdentifier + ".",
                    reason: "Bundle identifier prefix cache under /private/var/folders: \(app.bundleIdentifier)",
                    confidence: .high,
                    action: .trash,
                    risk: "medium",
                    into: &candidates,
                    seen: &seen
                )
            }
        }
    }
}

func addCandidate(_ path: String, reason: String, confidence: Confidence, action: CandidateAction, risk: String, into candidates: inout [Candidate], seen: inout Set<String>) {
    let standardized = standardPath(path)
    guard !seen.contains(standardized) else { return }
    seen.insert(standardized)
    candidates.append(inspectCandidate(path: standardized, reason: reason, confidence: confidence, action: action, risk: risk))
}

func isDirectory(_ path: String) -> Bool {
    var isDirectory: ObjCBool = false
    return fileManager.fileExists(atPath: path, isDirectory: &isDirectory) && isDirectory.boolValue
}

func inspectCandidate(path: String, reason: String, confidence: Confidence, action requestedAction: CandidateAction, risk: String) -> Candidate {
    var isDirectory: ObjCBool = false
    let exists = fileManager.fileExists(atPath: path, isDirectory: &isDirectory)
    let isSymlink = isSymbolicLink(path)
    let blockedReason = blockReason(for: path, isSymlink: isSymlink)
    let action: CandidateAction
    let confidenceOut: Confidence
    let detail: String?

    if let blockedReason {
        action = .blocked
        confidenceOut = .blocked
        detail = blockedReason
    } else {
        action = requestedAction
        confidenceOut = requestedAction == .reportOnly ? .reportOnly : confidence
        detail = nil
    }

    return Candidate(
        path: path,
        reason: reason,
        confidence: confidenceOut,
        action: action,
        risk: action == .blocked ? "blocked" : risk,
        exists: exists,
        isDirectory: exists && isDirectory.boolValue,
        isSymlink: isSymlink,
        sizeBytes: exists ? directorySize(at: path) : 0,
        status: exists ? .exists : .missing,
        detail: detail
    )
}

func isSymbolicLink(_ path: String) -> Bool {
    guard let values = try? URL(fileURLWithPath: path).resourceValues(forKeys: [.isSymbolicLinkKey]) else {
        return false
    }
    return values.isSymbolicLink == true
}

func blockReason(for path: String, isSymlink: Bool) -> String? {
    let standardized = standardPath(path)
    if isSymlink {
        return "Symlink candidates are never removed automatically"
    }

    let allowedAppleOwnedUserCache = standardPath(homePath("Library/Caches/com.apple.nsurlsessiond/Downloads"))
    if standardized.hasPrefix(allowedAppleOwnedUserCache + "/") {
        return nil
    }

    let protectedExact = [
        "/System",
        "/bin",
        "/sbin",
        "/usr",
        "/private/var/db",
        homePath("Library/Keychains"),
        homePath("Library/Mobile Documents"),
        homePath("Documents"),
        homePath("Desktop"),
        homePath("Pictures"),
        homePath("Movies"),
        homePath("Music"),
        homePath("Downloads")
    ]

    for protected in protectedExact {
        let protectedPath = standardPath(protected)
        if standardized == protectedPath || standardized.hasPrefix(protectedPath + "/") {
            if standardized.hasPrefix("/usr/local/") || standardized.hasPrefix("/usr/local/bin/") {
                continue
            }
            return "Protected path: \(protectedPath)"
        }
    }

    let protectedFragments = [
        "/com.apple.",
        "/SystemConfiguration/"
    ]
    for fragment in protectedFragments where standardized.contains(fragment) {
        return "Protected Apple/system fragment: \(fragment)"
    }

    return nil
}

func directorySize(at path: String) -> UInt64 {
    var isDirectory: ObjCBool = false
    guard fileManager.fileExists(atPath: path, isDirectory: &isDirectory) else { return 0 }
    if !isDirectory.boolValue {
        return fileSize(at: path)
    }

    guard let enumerator = fileManager.enumerator(
        at: URL(fileURLWithPath: path),
        includingPropertiesForKeys: [.isRegularFileKey, .totalFileAllocatedSizeKey, .fileAllocatedSizeKey],
        options: [.skipsHiddenFiles],
        errorHandler: nil
    ) else {
        return 0
    }

    var total: UInt64 = 0
    for case let fileURL as URL in enumerator {
        guard let values = try? fileURL.resourceValues(forKeys: [.isRegularFileKey, .totalFileAllocatedSizeKey, .fileAllocatedSizeKey]),
              values.isRegularFile == true else { continue }
        total += UInt64(values.totalFileAllocatedSize ?? values.fileAllocatedSize ?? 0)
    }
    return total
}

func fileSize(at path: String) -> UInt64 {
    guard let attributes = try? fileManager.attributesOfItem(atPath: path),
          let size = attributes[.size] as? NSNumber else {
        return 0
    }
    return size.uint64Value
}

func makeSummary(candidates: [Candidate]) -> Summary {
    let existing = candidates.filter(\.exists)
    return Summary(
        totalCandidates: candidates.count,
        existingCandidates: existing.count,
        trashEligibleExisting: existing.filter { $0.action == .trash }.count,
        reportOnlyExisting: existing.filter { $0.action == .reportOnly }.count,
        blockedExisting: existing.filter { $0.action == .blocked }.count,
        totalExistingBytes: existing.reduce(UInt64(0)) { $0 + $1.sizeBytes }
    )
}

func deepAudit(app: AppIdentity, full: Bool = false) -> AuditReport {
    let patterns = auditStrongPatterns(for: app)
    let strong = globalFindMatches(patterns: patterns, generic: false, full: full, limit: nil)
    let generic = globalFindMatches(patterns: genericAuditPatterns(for: app), generic: true, full: full, limit: full ? 2000 : nil)
    let registrations = registrationAudit(app: app, patterns: patterns)
    let errors = globalFindErrors()
    let registrationCount = registrations.reduce(0) { $0 + $1.matches.count }

    return AuditReport(
        generatedAt: isoTimestamp(),
        command: full ? "audit-full" : "audit",
        toolVersion: toolVersion,
        app: app,
        strongPatterns: patterns,
        strongPathMatches: strong,
        genericNameMatches: generic,
        registrations: registrations,
        unreadableErrors: errors,
        summary: AuditSummary(
            strongPathMatchCount: strong.count,
            genericNameMatchCount: generic.count,
            registrationMatchCount: registrationCount,
            unreadableErrorCount: errors.count
        )
    )
}

func auditStrongPatterns(for app: AppIdentity) -> [String] {
    var patterns = [app.bundleIdentifier]
    let bundleParts = app.bundleIdentifier.split(separator: ".").map(String.init)
    for part in bundleParts where part.count >= 8 && part.rangeOfCharacter(from: .decimalDigits) != nil {
        patterns.append(part)
    }
    if let teamIdentifier = app.teamIdentifier {
        patterns.append(teamIdentifier)
    }
    return normalizedNameVariants(patterns)
        .filter { $0.count >= 3 }
        .deduplicated()
}

func genericAuditPatterns(for app: AppIdentity) -> [String] {
    app.normalizedNames
        .filter { $0.count >= 4 }
        .deduplicated()
}

func globalFindMatches(patterns: [String], generic: Bool, full: Bool = false, limit: Int? = nil) -> [String] {
    guard !patterns.isEmpty else { return [] }
    let roots: [FindRootSpec] = full ? [
        FindRootSpec(path: "/", maxDepth: 3, timeoutSeconds: 15),
        FindRootSpec(path: "/Applications", maxDepth: nil, timeoutSeconds: 30),
        FindRootSpec(path: NSHomeDirectory() + "/Applications", maxDepth: nil, timeoutSeconds: 15),
        FindRootSpec(path: NSHomeDirectory() + "/Library", maxDepth: nil, timeoutSeconds: 45),
        FindRootSpec(path: NSHomeDirectory() + "/.config", maxDepth: nil, timeoutSeconds: 15),
        FindRootSpec(path: NSHomeDirectory() + "/.cache", maxDepth: nil, timeoutSeconds: 15),
        FindRootSpec(path: NSHomeDirectory() + "/.local", maxDepth: nil, timeoutSeconds: 15),
        FindRootSpec(path: "/Users", maxDepth: 4, timeoutSeconds: 20),
        FindRootSpec(path: "/Library", maxDepth: nil, timeoutSeconds: 45),
        FindRootSpec(path: "/System", maxDepth: nil, timeoutSeconds: 45),
        FindRootSpec(path: "/System/Volumes/Data/Applications", maxDepth: nil, timeoutSeconds: 30),
        FindRootSpec(path: "/System/Volumes/Data/Library", maxDepth: nil, timeoutSeconds: 45),
        FindRootSpec(path: "/private", maxDepth: 8, timeoutSeconds: 30),
        FindRootSpec(path: "/usr/local", maxDepth: nil, timeoutSeconds: 20),
        FindRootSpec(path: "/opt", maxDepth: nil, timeoutSeconds: 20),
        FindRootSpec(path: "/etc", maxDepth: nil, timeoutSeconds: 15),
        FindRootSpec(path: "/var", maxDepth: 8, timeoutSeconds: 30)
    ] : [
        FindRootSpec(path: "/Applications", maxDepth: 3, timeoutSeconds: 10),
        FindRootSpec(path: NSHomeDirectory() + "/Applications", maxDepth: 3, timeoutSeconds: 10),
        FindRootSpec(path: NSHomeDirectory() + "/Library", maxDepth: 5, timeoutSeconds: 15),
        FindRootSpec(path: NSHomeDirectory() + "/.config", maxDepth: 5, timeoutSeconds: 10),
        FindRootSpec(path: NSHomeDirectory() + "/.cache", maxDepth: 5, timeoutSeconds: 10),
        FindRootSpec(path: NSHomeDirectory() + "/.local/share", maxDepth: 5, timeoutSeconds: 10),
        FindRootSpec(path: "/Library", maxDepth: 4, timeoutSeconds: 15),
        FindRootSpec(path: "/usr/local", maxDepth: 5, timeoutSeconds: 10),
        FindRootSpec(path: "/opt", maxDepth: 5, timeoutSeconds: 10),
        FindRootSpec(path: "/private/var/db/receipts", maxDepth: 1, timeoutSeconds: 10),
        FindRootSpec(path: "/private/tmp", maxDepth: 3, timeoutSeconds: 10),
        FindRootSpec(path: "/tmp", maxDepth: 3, timeoutSeconds: 10),
        FindRootSpec(path: "/etc", maxDepth: 3, timeoutSeconds: 10)
    ]
    let excludes = [
        NSHomeDirectory() + "/App Sweep/backups",
        NSHomeDirectory() + "/App Sweep/reports",
        NSHomeDirectory() + "/.Trash",
        "/System/Volumes/Data" + NSHomeDirectory() + "/App Sweep/backups",
        "/System/Volumes/Data" + NSHomeDirectory() + "/App Sweep/reports",
        "/System/Volumes/Data" + NSHomeDirectory() + "/.Trash",
        "/dev",
        "/Volumes",
        "/Network"
    ]

    var matches = Set<String>()
    for root in roots where fileManager.fileExists(atPath: root.path) {
        let remainingLimit = limit.map { max($0 - matches.count, 0) }
        if remainingLimit == 0 { break }
        for line in runFind(root: root, patterns: patterns, excludes: excludes, limit: remainingLimit) {
            matches.insert(line)
        }
    }

    return matches.sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
}

func runFind(root: FindRootSpec, patterns: [String], excludes: [String], limit: Int?) -> [String] {
    let outputPath = NSTemporaryDirectory() + "app-sweep-find-output-\(getpid())-\(UUID().uuidString).txt"
    fileManager.createFile(atPath: outputPath, contents: nil)
    fileManager.createFile(atPath: findErrorPath(), contents: nil)

    guard let outputHandle = FileHandle(forWritingAtPath: outputPath),
          let errorHandle = FileHandle(forWritingAtPath: findErrorPath()) else {
        appendFindError("Unable to open temporary files for find root: \(root.path)")
        return []
    }
    errorHandle.seekToEndOfFile()

    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/find")
    process.arguments = findArguments(root: root, patterns: patterns, excludes: excludes)
    process.standardOutput = outputHandle
    process.standardError = errorHandle

    do {
        try process.run()
    } catch {
        outputHandle.closeFile()
        errorHandle.closeFile()
        try? fileManager.removeItem(atPath: outputPath)
        appendFindError("Unable to start find for \(root.path): \(error.localizedDescription)")
        return []
    }

    let semaphore = DispatchSemaphore(value: 0)
    DispatchQueue.global().async {
        process.waitUntilExit()
        semaphore.signal()
    }

    if semaphore.wait(timeout: .now() + .seconds(root.timeoutSeconds)) == .timedOut {
        process.terminate()
        _ = semaphore.wait(timeout: .now() + .seconds(3))
        appendFindError("Timed out after \(root.timeoutSeconds)s while scanning \(root.path)")
    }

    outputHandle.closeFile()
    errorHandle.closeFile()
    defer { try? fileManager.removeItem(atPath: outputPath) }

    let data = (try? String(contentsOfFile: outputPath)) ?? ""
    var lines = data
        .split(separator: "\n")
        .map(String.init)
        .filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }

    if let limit, lines.count > limit {
        lines = Array(lines.prefix(limit))
    }
    return lines
}

func findArguments(root: FindRootSpec, patterns: [String], excludes: [String]) -> [String] {
    var arguments = ["-x", root.path]
    if let maxDepth = root.maxDepth {
        arguments.append(contentsOf: ["-maxdepth", String(maxDepth)])
    }

    if !excludes.isEmpty {
        arguments.append("(")
        for (index, exclude) in excludes.enumerated() {
            if index > 0 { arguments.append("-o") }
            arguments.append(contentsOf: ["-path", exclude + "/*"])
        }
        arguments.append(contentsOf: [")", "-prune", "-o"])
    }

    arguments.append("(")
    for (index, pattern) in patterns.enumerated() {
        if index > 0 { arguments.append("-o") }
        arguments.append(contentsOf: ["-iname", "*" + pattern + "*"])
    }
    arguments.append(contentsOf: [")", "-print"])
    return arguments
}

func globalFindErrors() -> [String] {
    let path = findErrorPath()
    guard let data = try? String(contentsOfFile: path) else { return [] }
    return data
        .split(separator: "\n")
        .map(String.init)
        .deduplicated()
}

func findErrorPath() -> String {
    NSTemporaryDirectory() + "app-sweep-find-errors-\(getpid()).txt"
}

func appendFindError(_ message: String) {
    let path = findErrorPath()
    fileManager.createFile(atPath: path, contents: nil)
    guard let handle = FileHandle(forWritingAtPath: path) else { return }
    handle.seekToEndOfFile()
    if let data = (message + "\n").data(using: .utf8) {
        handle.write(data)
    }
    handle.closeFile()
}

func registrationAudit(app: AppIdentity, patterns: [String]) -> [AuditSection] {
    let regex = patterns
        .map(escapeExtendedRegex)
        .joined(separator: "|")
    guard !regex.isEmpty else { return [] }
    let uid = getuid()
    let grep = "/usr/bin/egrep -i \(shellQuote(regex))"
    let sections: [(String, String)] = [
        ("pkgutil receipts", "/usr/sbin/pkgutil --pkgs | \(grep) || true"),
        ("launchctl gui", "/bin/launchctl print gui/\(uid) 2>/dev/null | \(grep) || true"),
        ("launchctl system", "/bin/launchctl print system 2>/dev/null | \(grep) || true"),
        ("background task management", "/usr/bin/sfltool dumpbtm 2>/dev/null | \(grep) || true"),
        ("launch/helper content", contentGrepCommand(regex: regex))
    ]

    return sections.map { name, command in
        let result = shell(command, timeoutSeconds: 20)
        var matches = result.stdout
            .split(separator: "\n")
            .map(String.init)
            .filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
            .deduplicated()
        if result.status == 124 {
            matches.append("Timed out while running registration audit section: \(name)")
        }
        return AuditSection(name: name, command: command, matches: matches)
    }
}

func contentGrepCommand(regex: String) -> String {
    let roots = [
        NSHomeDirectory() + "/Library/LaunchAgents",
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/Library/PrivilegedHelperTools",
        NSHomeDirectory() + "/Library/Preferences",
        "/Library/Preferences",
        "/private/var/db/receipts"
    ]
    let existingRoots = roots
        .filter { fileManager.fileExists(atPath: $0) }
        .map(shellQuote)
        .joined(separator: " ")
    guard !existingRoots.isEmpty else { return "true" }
    return "/usr/bin/grep -RIlE \(shellQuote(regex)) \(existingRoots) 2>/dev/null || true"
}

func shell(_ command: String, timeoutSeconds: Int = 20) -> (status: Int32, stdout: String, stderr: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/zsh")
    process.arguments = ["-lc", command]

    let out = Pipe()
    let err = Pipe()
    process.standardOutput = out
    process.standardError = err

    do {
        try process.run()
    } catch {
        return (127, "", error.localizedDescription)
    }

    let semaphore = DispatchSemaphore(value: 0)
    DispatchQueue.global().async {
        process.waitUntilExit()
        semaphore.signal()
    }

    var timedOut = false
    if semaphore.wait(timeout: .now() + .seconds(timeoutSeconds)) == .timedOut {
        timedOut = true
        process.terminate()
        _ = semaphore.wait(timeout: .now() + .seconds(3))
    }

    let stdout = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    let stderr = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    if timedOut {
        let timeoutMessage = "Timed out after \(timeoutSeconds)s: \(command)"
        return (124, stdout, [stderr, timeoutMessage].filter { !$0.isEmpty }.joined(separator: "\n"))
    }
    return (process.terminationStatus, stdout, stderr)
}

func shellQuote(_ value: String) -> String {
    "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
}

func escapeExtendedRegex(_ value: String) -> String {
    let special = #"[][\.^$*+?{}|()]"#
    var escaped = ""
    for scalar in value.unicodeScalars {
        let char = String(scalar)
        if special.contains(char) {
            escaped += "\\" + char
        } else {
            escaped += char
        }
    }
    return escaped
}

func backup(app: AppIdentity, candidates: [Candidate], root: String) -> [Candidate] {
    let timestamp = isoTimestampForPath()
    let backupRoot = standardPath(root) + "/\(app.displayName)-\(timestamp)"
    let filesRoot = backupRoot + "/files"
    try? fileManager.createDirectory(atPath: filesRoot, withIntermediateDirectories: true)

    var updated: [Candidate] = []
    let sources = candidates.filter { $0.exists && $0.action == .trash }
    for var candidate in sources {
        let destination = filesRoot + "/" + safeBackupName(for: candidate.path)
        do {
            try copyItemReplacingExisting(from: candidate.path, to: destination)
            candidate.status = .backedUp
            candidate.detail = "Backed up to \(destination)"
        } catch {
            candidate.status = .backupFailed
            candidate.detail = "Backup failed: \(error.localizedDescription)"
        }
        updated.append(candidate)
    }

    var untouched = candidates.filter { !($0.exists && $0.action == .trash) }
    untouched.append(contentsOf: updated)
    return untouched.sorted { $0.path < $1.path }
}

func safeBackupName(for path: String) -> String {
    var name = path
        .replacingOccurrences(of: "/", with: "__")
        .replacingOccurrences(of: ":", with: "_")
    if name.hasPrefix("__") {
        name.removeFirst(2)
    }
    return name
}

func copyItemReplacingExisting(from source: String, to destination: String) throws {
    let parent = URL(fileURLWithPath: destination).deletingLastPathComponent().path
    try fileManager.createDirectory(atPath: parent, withIntermediateDirectories: true)
    if fileManager.fileExists(atPath: destination) {
        try fileManager.removeItem(atPath: destination)
    }
    try fileManager.copyItem(atPath: source, toPath: destination)
}

func uninstall(candidates: [Candidate]) -> [Candidate] {
    var updated = candidates
    let primaryIndex = updated.indices.first {
        updated[$0].exists && updated[$0].action == .trash && isPrimaryAppBundleCandidate(updated[$0])
    }

    if let primaryIndex {
        trashCandidate(&updated[primaryIndex])
        if updated[primaryIndex].status == .trashFailed {
            for index in updated.indices where index != primaryIndex {
                guard updated[index].exists else { continue }
                if updated[index].action == .trash {
                    updated[index].status = .skipped
                    updated[index].detail = "Skipped because the primary app bundle could not be moved to Trash"
                } else {
                    updated[index].status = .skipped
                }
            }
            return updated
        }
    }

    for index in updated.indices {
        if index == primaryIndex { continue }
        guard updated[index].exists, updated[index].action == .trash else {
            if updated[index].exists {
                updated[index].status = .skipped
            }
            continue
        }
        trashCandidate(&updated[index])
    }
    return updated
}

func isPrimaryAppBundleCandidate(_ candidate: Candidate) -> Bool {
    candidate.reason == "App bundle selected by user" && candidate.path.hasSuffix(".app")
}

func trashCandidate(_ candidate: inout Candidate) {
    let previousDetail = candidate.detail
    do {
        var resultingURL: NSURL?
        try fileManager.trashItem(at: URL(fileURLWithPath: candidate.path), resultingItemURL: &resultingURL)
        candidate.status = .trashed
        let trashDetail = resultingURL?.path.map { "Moved to Trash: \($0)" } ?? "Moved to Trash"
        candidate.detail = joinedDetail(previousDetail, trashDetail)
    } catch {
        candidate.status = .trashFailed
        candidate.detail = joinedDetail(previousDetail, "Trash failed: \(error.localizedDescription)")
    }
}

func joinedDetail(_ first: String?, _ second: String) -> String {
    [first?.nilIfBlank, second.nilIfBlank]
        .compactMap { $0 }
        .joined(separator: "\n")
}

func trashPath(_ path: String) -> Candidate {
    var candidate = inspectCandidate(
        path: standardPath(path),
        reason: "Explicit path selected by user",
        confidence: .medium,
        action: .trash,
        risk: "medium"
    )

    guard candidate.exists else {
        candidate.status = .missing
        return candidate
    }
    guard candidate.action == .trash else {
        candidate.status = .skipped
        return candidate
    }

    do {
        var resultingURL: NSURL?
        try fileManager.trashItem(at: URL(fileURLWithPath: candidate.path), resultingItemURL: &resultingURL)
        candidate.status = .trashed
        candidate.detail = resultingURL?.path.map { "Moved to Trash: \($0)" } ?? "Moved to Trash"
    } catch {
        candidate.status = .trashFailed
        candidate.detail = "Trash failed: \(error.localizedDescription)"
    }
    return candidate
}

func restoreFromReport(_ reportPath: String) throws -> RestoreReport {
    let sourcePath = standardPath(reportPath)
    let data = try Data(contentsOf: URL(fileURLWithPath: sourcePath))
    let sourceReport = try JSONDecoder().decode(Report.self, from: data)
    var items: [RestoreItem] = []

    for candidate in sourceReport.candidates {
        let originalPath = candidate.path
        guard let backupPath = extractBackupPath(from: candidate.detail) else {
            continue
        }

        guard fileManager.fileExists(atPath: backupPath) else {
            items.append(RestoreItem(originalPath: originalPath, backupPath: backupPath, status: "missingBackup", detail: nil))
            continue
        }

        if fileManager.fileExists(atPath: originalPath) {
            items.append(RestoreItem(originalPath: originalPath, backupPath: backupPath, status: "skippedExisting", detail: "Original path already exists"))
            continue
        }

        do {
            let parent = URL(fileURLWithPath: originalPath).deletingLastPathComponent().path
            try fileManager.createDirectory(atPath: parent, withIntermediateDirectories: true)
            try fileManager.copyItem(atPath: backupPath, toPath: originalPath)
            items.append(RestoreItem(originalPath: originalPath, backupPath: backupPath, status: "restored", detail: nil))
        } catch {
            items.append(RestoreItem(originalPath: originalPath, backupPath: backupPath, status: "failed", detail: error.localizedDescription))
        }
    }

    let summary = RestoreSummary(
        restored: items.filter { $0.status == "restored" }.count,
        skippedExisting: items.filter { $0.status == "skippedExisting" }.count,
        missingBackup: items.filter { $0.status == "missingBackup" || $0.status == "missingBackupPath" }.count,
        failed: items.filter { $0.status == "failed" }.count
    )

    return RestoreReport(
        generatedAt: isoTimestamp(),
        command: "restore-report",
        toolVersion: toolVersion,
        sourceReportPath: sourcePath,
        items: items,
        summary: summary
    )
}

func extractBackupPath(from detail: String?) -> String? {
    guard let detail else { return nil }
    let prefix = "Backed up to "
    guard let range = detail.range(of: prefix) else { return nil }
    let remainder = detail[range.upperBound...]
    let firstLine = remainder.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false).first
    return firstLine.map(String.init)?.trimmingCharacters(in: .whitespacesAndNewlines).nilIfBlank
}

func writeReport(_ report: Report, to path: String?) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let data = try encoder.encode(report)
    if let path {
        let outputPath = standardPath(path)
        let parent = URL(fileURLWithPath: outputPath).deletingLastPathComponent().path
        try fileManager.createDirectory(atPath: parent, withIntermediateDirectories: true)
        try data.write(to: URL(fileURLWithPath: outputPath), options: .atomic)
        print("JSON report: \(outputPath)")
    } else {
        print(String(data: data, encoding: .utf8) ?? "{}")
    }
}

func writeAuditReport(_ report: AuditReport, to path: String?) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let data = try encoder.encode(report)
    if let path {
        let outputPath = standardPath(path)
        let parent = URL(fileURLWithPath: outputPath).deletingLastPathComponent().path
        try fileManager.createDirectory(atPath: parent, withIntermediateDirectories: true)
        try data.write(to: URL(fileURLWithPath: outputPath), options: .atomic)
        print("JSON audit report: \(outputPath)")
    } else {
        print(String(data: data, encoding: .utf8) ?? "{}")
    }
}

func writePathOperationReport(_ report: PathOperationReport, to path: String?) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let data = try encoder.encode(report)
    if let path {
        let outputPath = standardPath(path)
        let parent = URL(fileURLWithPath: outputPath).deletingLastPathComponent().path
        try fileManager.createDirectory(atPath: parent, withIntermediateDirectories: true)
        try data.write(to: URL(fileURLWithPath: outputPath), options: .atomic)
        print("JSON path report: \(outputPath)")
    } else {
        print(String(data: data, encoding: .utf8) ?? "{}")
    }
}

func writeRestoreReport(_ report: RestoreReport, to path: String?) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let data = try encoder.encode(report)
    if let path {
        let outputPath = standardPath(path)
        let parent = URL(fileURLWithPath: outputPath).deletingLastPathComponent().path
        try fileManager.createDirectory(atPath: parent, withIntermediateDirectories: true)
        try data.write(to: URL(fileURLWithPath: outputPath), options: .atomic)
        print("JSON restore report: \(outputPath)")
    } else {
        print(String(data: data, encoding: .utf8) ?? "{}")
    }
}

func printHumanSummary(_ report: Report) {
    print("Command: \(report.command)")
    print("Tool: \(report.toolVersion)")
    print("App: \(report.app.displayName)")
    print("Bundle ID: \(report.app.bundleIdentifier)")
    if let teamIdentifier = report.app.teamIdentifier {
        print("Team ID: \(teamIdentifier)")
    }
    print("Existing candidates: \(report.summary.existingCandidates)/\(report.summary.totalCandidates)")
    print("Trash eligible: \(report.summary.trashEligibleExisting)")
    print("Report only: \(report.summary.reportOnlyExisting)")
    print("Blocked: \(report.summary.blockedExisting)")
    print("Existing size: \(formatBytes(report.summary.totalExistingBytes))")
    print("")
    for candidate in report.candidates where candidate.exists || candidate.status != .missing {
        print("[\(candidate.confidence.rawValue)] [\(candidate.action.rawValue)] [\(candidate.status.rawValue)] \(candidate.path)")
        print("  reason: \(candidate.reason)")
        print("  size: \(formatBytes(candidate.sizeBytes))")
        if let detail = candidate.detail {
            print("  detail: \(detail)")
        }
    }
}

func printHumanAuditSummary(_ report: AuditReport) {
    print("Command: \(report.command)")
    print("Tool: \(report.toolVersion)")
    print("App: \(report.app.displayName)")
    print("Bundle ID: \(report.app.bundleIdentifier)")
    if let teamIdentifier = report.app.teamIdentifier {
        print("Team ID: \(teamIdentifier)")
    }
    print("Strong path matches: \(report.summary.strongPathMatchCount)")
    print("Generic name matches: \(report.summary.genericNameMatchCount)")
    print("Registration matches: \(report.summary.registrationMatchCount)")
    print("Unreadable errors: \(report.summary.unreadableErrorCount)")
    print("")

    if !report.strongPathMatches.isEmpty {
        print("Strong path matches:")
        for path in report.strongPathMatches.prefix(80) {
            print("  \(path)")
        }
    }

    for section in report.registrations where !section.matches.isEmpty {
        print("")
        print(section.name + ":")
        for match in section.matches.prefix(80) {
            print("  \(match)")
        }
    }

    if !report.genericNameMatches.isEmpty {
        print("")
        print("Generic name matches, first 80:")
        for path in report.genericNameMatches.prefix(80) {
            print("  \(path)")
        }
    }
}

func printHumanPathOperationSummary(_ report: PathOperationReport) {
    let candidate = report.candidate
    print("Command: \(report.command)")
    print("Tool: \(report.toolVersion)")
    print("[\(candidate.confidence.rawValue)] [\(candidate.action.rawValue)] [\(candidate.status.rawValue)] \(candidate.path)")
    print("  reason: \(candidate.reason)")
    print("  size: \(formatBytes(candidate.sizeBytes))")
    if let detail = candidate.detail {
        print("  detail: \(detail)")
    }
}

func printHumanRestoreSummary(_ report: RestoreReport) {
    print("Command: \(report.command)")
    print("Tool: \(report.toolVersion)")
    print("Source report: \(report.sourceReportPath)")
    print("Restored: \(report.summary.restored)")
    print("Skipped existing: \(report.summary.skippedExisting)")
    print("Missing backup: \(report.summary.missingBackup)")
    print("Failed: \(report.summary.failed)")
    print("")
    for item in report.items where item.status != "skippedExisting" {
        print("[\(item.status)] \(item.originalPath)")
        if let backupPath = item.backupPath {
            print("  backup: \(backupPath)")
        }
        if let detail = item.detail {
            print("  detail: \(detail)")
        }
    }
}

func formatBytes(_ bytes: UInt64) -> String {
    let formatter = ByteCountFormatter()
    formatter.allowedUnits = [.useKB, .useMB, .useGB]
    formatter.countStyle = .file
    return formatter.string(fromByteCount: Int64(bytes))
}

func isoTimestamp() -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return formatter.string(from: Date())
}

func isoTimestampForPath() -> String {
    isoTimestamp()
        .replacingOccurrences(of: ":", with: "-")
        .replacingOccurrences(of: ".", with: "-")
}

extension String {
    var nilIfBlank: String? {
        let value = trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }
}

extension Array where Element: Hashable {
    func deduplicated() -> [Element] {
        var seen = Set<Element>()
        var result: [Element] = []
        for value in self where !seen.contains(value) {
            seen.insert(value)
            result.append(value)
        }
        return result
    }
}

do {
    let options = try parseOptions(Array(CommandLine.arguments.dropFirst()))
    if options.command == "restore-report" {
        let report = try restoreFromReport(options.appPath)
        printHumanRestoreSummary(report)
        try writeRestoreReport(report, to: options.jsonPath)
        exit(0)
    }

    if options.command == "trash-path" {
        let candidate = trashPath(options.appPath)
        let report = PathOperationReport(
            generatedAt: isoTimestamp(),
            command: options.command,
            toolVersion: toolVersion,
            candidate: candidate
        )
        printHumanPathOperationSummary(report)
        try writePathOperationReport(report, to: options.jsonPath)
        exit(0)
    }

    let app = try appIdentityFromOptions(options)

    if options.command == "audit" || options.command == "audit-known" || options.command == "audit-full" || options.command == "audit-full-known" {
        _ = try? fileManager.removeItem(atPath: findErrorPath())
        let report = deepAudit(app: app, full: options.command == "audit-full" || options.command == "audit-full-known")
        printHumanAuditSummary(report)
        try writeAuditReport(report, to: options.jsonPath)
        exit(0)
    }

    var candidates = scanCandidates(for: app)

    if options.command == "backup" || options.command == "backup-known" || ((options.command == "uninstall" || options.command == "uninstall-known") && options.backupRoot != nil) {
        guard let backupRoot = options.backupRoot else {
            throw CommandError.invalidUsage("backup root is required")
        }
        candidates = backup(app: app, candidates: candidates, root: backupRoot)
    }

    if options.command == "uninstall" || options.command == "uninstall-known" {
        candidates = uninstall(candidates: candidates)
    }

    let report = Report(
        generatedAt: isoTimestamp(),
        command: options.command,
        toolVersion: toolVersion,
        app: app,
        summary: makeSummary(candidates: candidates),
        candidates: candidates
    )
    printHumanSummary(report)
    try writeReport(report, to: options.jsonPath)
} catch let error as CommandError {
    fputs("error: \(error.description)\n", stderr)
    exit(2)
} catch {
    fputs("error: \(error.localizedDescription)\n", stderr)
    exit(1)
}
