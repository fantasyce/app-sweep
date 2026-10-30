import Foundation
import Darwin
@testable import AppSweepCore

/// Declaration-boundary checks only. These fixtures are never registered or
/// executed, and the parser reference below is not an ownership authorization.
@MainActor func systemHelperDeclarationChecks() throws {
    let f = try OwnedFixture()
    let library = f.home + "/MachineLibrary"
    let label = "org.example.nativehelper." + UUID().uuidString.lowercased()
    let binary = library + "/PrivilegedHelperTools/" + label
    let plist = library + "/LaunchDaemons/" + label + ".plist"
    for path in [library + "/PrivilegedHelperTools", library + "/LaunchDaemons"] {
        try fm.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }
    let scope = try SystemCleanupScope.fixture(libraryRoot: library, applicationsRoot: f.home + "/Applications", userHome: f.home, requesterUID: getuid())
    let appIdentity = try SafeDirectory(path: f.app).ownIdentity
    let appInfo: [String: Any] = ["SMPrivilegedExecutables": [label: "identifier \"" + label + "\""]]
    let base: [String: Any] = ["Label": label, "ProgramArguments": [binary], "MachServices": [label: true]]

    func declaration(_ info: [String: Any]) throws -> Candidate {
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: URL(fileURLWithPath: plist))
        let snapshot = try SafeFilesystem.snapshot(plist)
        let reference = InstalledSystemHelperReference(label: label, applicationIdentity: appIdentity,
            applicationCodeHash: Data(repeating: 0, count: 20), helperCodeHash: Data(repeating: 0, count: 20),
            plistIdentity: snapshot.identity, plistDigest: try VerifiedFileStream.digest(snapshot))
        return Candidate(id: UUID(), path: plist, category: .backgroundComponent, bundleIdentifier: f.identifier,
            applicationPath: f.app, evidence: [], rule: InstalledSystemHelperRule.name, identity: snapshot.identity,
            bytes: snapshot.bytes, retentionReason: nil, systemHelper: reference)
    }

    try UninstallDependencies.ensureNoInstalledPrivilegedHelpers(info: appInfo, libraryRoot: library)
    let original = try declaration(base)
    try check(InstalledSystemHelperRule.declaration(original, scope: scope) == plist, "Exact dormant Mach declaration rejected")
    try reject("installed declaration prevents body-only uninstall") {
        try UninstallDependencies.ensureNoInstalledPrivilegedHelpers(info: appInfo, libraryRoot: library)
    }
    var explicitDormant = base
    explicitDormant["Program"] = binary
    explicitDormant["RunAtLoad"] = false
    explicitDormant["KeepAlive"] = false
    explicitDormant["ProcessType"] = "Background"
    try check(InstalledSystemHelperRule.declaration(declaration(explicitDormant), scope: scope) == plist, "Explicit dormant declaration rejected")
    print("PASS exact dormant Mach declaration permits parsing without authorizing lifecycle")

    let rejectedFields: [(String, Any)] = [
        ("RunAtLoad", "yes"),
        ("KeepAlive", true),
        ("Sockets", ["Listener": ["SockPathName": "/var/run/" + label + ".sock", "SockPathMode": 438]]),
        ("Version", ["unknown": "77"]),
        ("AssociatedBundleIdentifiers", [f.identifier, "org.example.unrelated"]),
        ("ProgramArguments", [binary, "fixture-user"]),
        ("Program", binary + ".other"),
        ("Label", label + ".other"),
        ("MachServices", [label: true, label + ".shared": true])
    ]
    for (key, value) in rejectedFields {
        var info = base
        info[key] = value
        let candidate = try declaration(info)
        try reject("unsupported helper declaration: " + key) {
            _ = try InstalledSystemHelperRule.declaration(candidate, scope: scope)
        }
    }
    var socketOnly = base
    socketOnly.removeValue(forKey: "MachServices")
    socketOnly["RunAtLoad"] = true
    socketOnly["Sockets"] = ["Listener": ["SockPathName": "/var/run/" + label + ".sock", "SockPathMode": 438]]
    socketOnly["Version"] = "77"
    let socketCandidate = try declaration(socketOnly)
    try reject("Socket declaration with an unowned endpoint stays blocked") {
        _ = try InstalledSystemHelperRule.declaration(socketCandidate, scope: scope)
    }

    let reviewed = try declaration(base)
    _ = try declaration(explicitDormant)
    try reject("changed declaration bytes invalidate the review") {
        _ = try InstalledSystemHelperRule.declaration(reviewed, scope: scope)
    }
    let sameBytes = try declaration(base), bytes = try Data(contentsOf: URL(fileURLWithPath: plist))
    let held = library + "/held-original.plist"
    try fm.moveItem(atPath: plist, toPath: held)
    try bytes.write(to: URL(fileURLWithPath: plist), options: .withoutOverwriting)
    try reject("same-byte replacement cannot borrow the reviewed file identity") {
        _ = try InstalledSystemHelperRule.declaration(sameBytes, scope: scope)
    }
    try fm.removeItem(atPath: plist)
    try fm.moveItem(atPath: held, toPath: plist)
    try fm.removeItem(atPath: plist)
    try Data("Owned test bytes; never executable".utf8).write(to: URL(fileURLWithPath: binary), options: .withoutOverwriting)
    try reject("installed helper alone prevents body-only uninstall") {
        try UninstallDependencies.ensureNoInstalledPrivilegedHelpers(info: appInfo, libraryRoot: library)
    }
    try f.finish()
}
