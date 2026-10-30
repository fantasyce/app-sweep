import Foundation
import Darwin
@testable import AppSweepCore

@MainActor struct OwnedHelper {
    let f: OwnedFixture
    let scope: SystemCleanupScope
    let label: String
    let binary: String
    let plist: String
    let embedded: String
    var target: String { "gui/" + String(getuid()) + "/" + label }
    init(automatic: Bool = false, sleeping: Bool = false) throws {
        f = try OwnedFixture(); label = "org.example.backendhelper." + UUID().uuidString.lowercased()
        let library = f.home + "/MachineLibrary"
        binary = library + "/PrivilegedHelperTools/" + label; plist = library + "/LaunchDaemons/" + label + ".plist"
        embedded = f.app + "/Contents/Library/LaunchServices/" + label
        for path in [library + "/PrivilegedHelperTools", library + "/LaunchDaemons", library + "/Run", f.app + "/Contents/Library/LaunchServices"] {
            try fm.createDirectory(atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        var info = try AppInspector.metadata(f.app, component: false).0
        info["SMPrivilegedExecutables"] = [label: "identifier \"" + label + "\""]
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: URL(fileURLWithPath: f.app + "/Contents/Info.plist"))
        let metadata = f.home + "/helper.plist", source = f.home + "/helper.c"
        try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier":label,"CFBundleVersion":"1","SMAuthorizedClients":["identifier \"" + f.identifier + "\""]], format: .xml, options: 0).write(to: URL(fileURLWithPath: metadata))
        try Data((sleeping ? "#include <unistd.h>\nint main(void) { sleep(30); return 0; }\n" : "int main(void) { return 0; }\n").utf8).write(to: URL(fileURLWithPath: source))
        guard let sdk = ProcessInfo.processInfo.environment["APP_SWEEP_SDK"] else { throw CheckFailure("SDK required") }
        _ = try BoundedProcess.run("/usr/bin/clang", arguments: ["-isysroot",sdk,"-mmacosx-version-min=12.0",source,"-Wl,-sectcreate,__TEXT,__info_plist,"+metadata,"-o",embedded], timeout: 15)
        _ = try BoundedProcess.run("/usr/bin/codesign", arguments: ["--force","--sign","-","--identifier",label,embedded], timeout: 10)
        _ = try BoundedProcess.run("/usr/bin/codesign", arguments: ["--force","--sign","-",f.app], timeout: 10)
        try fm.copyItem(atPath: embedded, toPath: binary)
        var declaration: [String:Any] = ["Label":label,"ProgramArguments":[binary],"MachServices":[label:true]]
        if automatic {
            declaration.removeValue(forKey: "MachServices")
            declaration["RunAtLoad"] = true; declaration["Version"] = "77"
            declaration["AssociatedBundleIdentifiers"] = [f.identifier]
            declaration["Sockets"] = ["Listener":["SockPathName":library + "/Run/" + label + ".sock","SockPathMode":438]]
        }
        try PropertyListSerialization.data(fromPropertyList: declaration, format: .xml, options: 0).write(to: URL(fileURLWithPath: plist))
        scope = try SystemCleanupScope.fixture(libraryRoot: library, applicationsRoot: f.home + "/Applications", userHome: f.home, requesterUID: getuid())
    }
    func retire() throws {
        let state = try BoundedProcess.capture("/bin/launchctl", arguments: ["print",target], timeout: 5, mergeStderr: true)
        if state.status == 0 { _ = try BoundedProcess.run("/bin/launchctl", arguments: ["bootout",target], timeout: 5) }
        try check(BoundedProcess.capture("/bin/launchctl", arguments: ["print",target], timeout: 5, mergeStderr: true).status == 113, "Owned helper job still registered")
        try f.finish()
    }
}

@MainActor func helperGuardChecks() async throws {
    let h = try OwnedHelper(sleeping: true)
    let process = Process(); process.executableURL = URL(fileURLWithPath: h.binary); try process.run()
    do {
        let busy = try await SystemCleanupEngine(scope: h.scope).scan(.applicationHelpers)
        try check(!busy.selectableCandidates(includeUserData: true).contains { [h.binary,h.plist].contains($0.path) }, "Running helper became selectable")
        try check(process.isRunning && fm.fileExists(atPath: h.binary), "Product stopped or removed running helper")
    } catch { if process.isRunning { process.terminate() }; throw error }
    if process.isRunning { process.terminate() }
    let deadline = Date().addingTimeInterval(5)
    while process.isRunning && Date() < deadline { try await Task.sleep(nanoseconds: 50_000_000) }
    try check(!process.isRunning, "Owned helper failed to exit")
    print("PASS running helper blocks selection and is left running by the product")

    // Re-sign only the installed owned fixture with a different version. Both
    // declarations still agree; the missing native publisher chain must reject.
    let source = h.f.home + "/changed.c", metadata = h.f.home + "/helper.plist"
    try Data("int main(void) { return 17; }\n".utf8).write(to: URL(fileURLWithPath: source))
    let sdk = ProcessInfo.processInfo.environment["APP_SWEEP_SDK"]!
    _ = try BoundedProcess.run("/usr/bin/clang", arguments: ["-isysroot",sdk,source,"-Wl,-sectcreate,__TEXT,__info_plist,"+metadata,"-o",h.binary], timeout: 15)
    _ = try BoundedProcess.run("/usr/bin/codesign", arguments: ["--force","--sign","-","--identifier",h.label,h.binary], timeout: 10)
    try reject("ad-hoc matching identifiers cannot bridge helper version differences") {
        _ = try InstalledSystemHelperRule.signedRelationship(application: h.f.app, identifier: h.f.identifier, label: h.label, installed: h.binary)
    }
    try fm.removeItem(atPath: h.binary); try fm.copyItem(atPath: h.embedded, toPath: h.binary)
    let wrapper = h.f.home + "/Applications/Independent Wrapper.app", flat = wrapper + "/Wrapper/Flat.app"
    try fm.createDirectory(atPath: flat, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier":"org.example.independentwrapped","CFBundleExecutable":"fixture","CFBundlePackageType":"APPL","SMPrivilegedExecutables":[h.label:"identifier \""+h.label+"\""]], format: .xml, options: 0).write(to: URL(fileURLWithPath: flat + "/Info.plist"))
    try fm.copyItem(atPath: "/usr/bin/true", toPath: flat + "/fixture")
    let shared = try await SystemCleanupEngine(scope: h.scope).scan(.applicationHelpers)
    try check(!shared.selectableCandidates(includeUserData: true).contains { [h.binary,h.plist].contains($0.path) }, "Wrapped bystander's shared declaration was ignored")
    print("PASS flattened/wrapped shared clients remain an ownership veto")
    try fm.removeItem(atPath: wrapper)
    try h.retire()

    let loaded = try OwnedHelper()
    do {
        var declaration = try PropertyListSerialization.propertyList(from: Data(contentsOf: URL(fileURLWithPath: loaded.plist)), format: nil) as! [String:Any]
        declaration["RunAtLoad"] = true
        try PropertyListSerialization.data(fromPropertyList: declaration, format: .xml, options: 0).write(to: URL(fileURLWithPath: loaded.plist))
        _ = try BoundedProcess.run("/bin/launchctl", arguments: ["bootstrap","gui/" + String(getuid()),loaded.plist], timeout: 5)
        let report = try await SystemCleanupEngine(scope: loaded.scope).scan(.applicationHelpers)
        try check(!report.selectableCandidates(includeUserData: true).contains { [loaded.binary,loaded.plist].contains($0.path) }, "Registered automatic service was authorized")
        try check(BoundedProcess.capture("/bin/launchctl", arguments: ["print",loaded.target], timeout: 5, mergeStderr: true).status == 0, "Product unregistered an automatic job")
        print("PASS registered automatic service retained without stopping or unregistering")
    } catch { try? loaded.retire(); throw error }
    try loaded.retire()
}

@MainActor func helperVersionProofChecks() throws {
    // Only read the installed application and binaries. Do not register, stop,
    // replace, quarantine or launch Docker or its helpers.
    let app = "/Applications/Docker.app", label = "com.docker.vmnetd"
    let proof = try InstalledSystemHelperRule.signedRelationship(application: app, identifier: "com.docker.docker", label: label, installed: "/Library/PrivilegedHelperTools/" + label)
    try check(proof.installed != proof.embedded, "Read-only installed-version fixture no longer differs; update evidence")
    print("PASS real Developer ID signed installed/embedded version difference retains exact bidirectional ownership")
    try reject("unrelated signed executable cannot substitute for a declared helper") {
        _ = try InstalledSystemHelperRule.signedRelationship(application: app, identifier: "com.docker.docker", label: label, installed: "/usr/bin/true")
    }
}

@MainActor func helperLifecycleChecks() async throws {
    for automatic in [true, false] {
        let h = try OwnedHelper(automatic: automatic)
        if !automatic { _ = try BoundedProcess.run("/bin/launchctl", arguments: ["bootstrap", "gui/" + String(getuid()), h.plist], timeout: 5) }
        do {
            let engine = try SystemCleanupEngine(scope: h.scope), report = try await engine.scan(.applicationHelpers)
            let pair = report.selectableCandidates(includeUserData: false).filter { [h.binary,h.plist].contains($0.path) }
            try check(pair.count == 2, "Stopped helper pair rejected: " + report.candidates.compactMap(\.retentionReason).joined(separator: "; "))
            let original = try SafeFilesystem.snapshot(h.binary)
            let plan = try await engine.makePlan(reportID: report.id, selected: Set(pair.map(\.id)))
            let batch = try await engine.execute(planID: plan.id)
            try check(batch.status == .isolated, "Helper pair isolation failed: " + (batch.issue ?? "") + batch.entries.compactMap(\.message).joined(separator: "; "))
            try check(fm.fileExists(atPath: h.f.app) && !fm.fileExists(atPath: h.binary) && !fm.fileExists(atPath: h.plist), "Dependency stage altered application or left helper")
            try check(BoundedProcess.capture("/bin/launchctl", arguments: ["print", h.target], timeout: 5, mergeStderr: true).status == 113, "Isolated helper remains registered")
            try Data("newer independent file".utf8).write(to: URL(fileURLWithPath: h.binary), options: .withoutOverwriting)
            let conflict = try await SystemCleanupEngine(scope: h.scope).restore(batchID: batch.id)
            try check(conflict.status == .needsAttention && String(contentsOfFile: h.binary, encoding: .utf8) == "newer independent file", "Helper restore overwrote conflict")
            try fm.moveItem(atPath: h.binary, toPath: h.f.home + "/newer-held")
            let restored = try await SystemCleanupEngine(scope: h.scope).restore(batchID: batch.id)
            try check(restored.status == .restored, "Helper recovery failed: " + (restored.issue ?? "") + restored.entries.compactMap(\.message).joined(separator: "; "))
            try check(SafeFilesystem.snapshot(h.binary).identity.inode == original.identity.inode, "Helper identity changed after recovery")
            let registration = try BoundedProcess.capture("/bin/launchctl", arguments: ["print",h.target], timeout: 5, mergeStderr: true)
            try check(automatic ? registration.status == 113 : registration.status == 0 && registration.text.contains("state = not running"), "Restore started or lost original service state")
            print("PASS " + (automatic ? "unregistered automatic/socket" : "registered dormant Mach") + " helper isolates/restores without starting; conflicts preserved")
        } catch { try? h.retire(); throw error }
        try h.retire()
    }
}
