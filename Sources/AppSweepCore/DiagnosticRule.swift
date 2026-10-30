import Foundation

/// Independent interpretation of Apple's documented two-object IPS crash format.
/// Redacted, incomplete, ambiguous or differently structured reports are retained.
enum DiagnosticRule {
    static func headerIdentifier(_ data: Data) -> String? {
        guard data.count <= 2 * 1024 * 1024, let newline = data.firstIndex(of: 10),
              let header = try? JSONSerialization.jsonObject(with: data[..<newline]) as? [String: Any],
              header["bug_type"] as? String == "309",
              let identifier = header["bundleID"] as? String,
              AppInspector.validIdentifier(identifier), !identifier.hasPrefix("com.apple."),
              !identifier.lowercased().contains("appsweep"), !identifier.lowercased().contains("app-sweep") else { return nil }
        return identifier
    }

    static func owns(_ data: Data, identifier: String, applicationPath: String) -> Bool {
        guard headerIdentifier(data) == identifier, let newline = data.firstIndex(of: 10),
              let body = try? JSONSerialization.jsonObject(with: data[data.index(after: newline)...]) as? [String: Any],
              let bundle = body["bundleInfo"] as? [String: Any], bundle["CFBundleIdentifier"] as? String == identifier,
              let executable = body["procPath"] as? String,
              canonical(applicationPath), applicationPath.hasSuffix(".app"), canonical(executable) else { return false }
        return URL(fileURLWithPath: executable).deletingLastPathComponent().path == applicationPath + "/Contents/MacOS"
    }

    private static func canonical(_ path: String) -> Bool {
        path.hasPrefix("/") && !path.hasSuffix("/") && !path.contains("//") && !path.contains("\0") &&
        !path.split(separator: "/").contains(where: { $0 == "." || $0 == ".." || $0.contains("<") || $0.contains(">") })
    }
}
