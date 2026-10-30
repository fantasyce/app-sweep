import Foundation

/// Independently parses the public text crash-report header, without filename attribution.
enum LegacyCrashRule {
    static let name = "text-crash-third-party-30d-v1"
    private static func header(_ data: Data) -> (identifier: String, executable: String)? {
        guard data.count <= 2 * 1024 * 1024,
              let text = String(data: data, encoding: .utf8), !text.contains("\0") else { return nil }
        var normalized = text.replacingOccurrences(of: "\r\n", with: "\n")
        if normalized.first == "\u{feff}" { normalized.removeFirst() }
        let preamble = "-------------------------------------\nTranslated Report (Full Report Below)\n-------------------------------------\n\n"
        if normalized.hasPrefix(preamble) { normalized.removeFirst(preamble.count) }
        guard let end = normalized.range(of: "\n\n"), normalized[..<end.lowerBound].utf8.count <= 65_536 else { return nil }
        let fields: Set<String> = ["Process", "Path", "Identifier", "Report Version"]
        var values: [String: String] = [:]
        let lines = normalized[..<end.lowerBound].split(separator: "\n", omittingEmptySubsequences: false)
        guard lines.count <= 200 else { return nil }
        for line in lines {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let key = String(line[..<colon]).trimmingCharacters(in: .whitespaces)
            guard fields.contains(key) else { continue }
            guard values[key] == nil else { return nil }
            values[key] = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
        }
        guard let identifier = values["Identifier"], AppInspector.validIdentifier(identifier),
              !identifier.lowercased().hasPrefix("com.apple."),
              !identifier.lowercased().contains("appsweep"), !identifier.lowercased().contains("app-sweep"),
              let executable = values["Path"], canonical(executable),
              let process = values["Process"], process.range(of: #"^.+ \[[1-9][0-9]*\]$"#, options: .regularExpression) != nil,
              let version = values["Report Version"], ["12", "104"].contains(version) else { return nil }
        return (identifier, executable)
    }
    static func headerIdentifier(_ data: Data) -> String? { header(data)?.identifier }
    static func owns(_ data: Data, identifier: String, applicationPath: String) -> Bool {
        guard let header = header(data), header.identifier == identifier,
              applicationPath.hasSuffix(".app"), canonical(applicationPath) else { return false }
        return URL(fileURLWithPath: header.executable).deletingLastPathComponent().path == applicationPath + "/Contents/MacOS"
    }
    private static func canonical(_ path: String) -> Bool {
        path.hasPrefix("/") && !path.hasSuffix("/") && !path.contains("//") &&
        !path.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) &&
        !path.split(separator: "/").contains(where: { $0 == "." || $0 == ".." || $0.contains("<") || $0.contains(">") || $0.contains("*") || $0.contains("?") })
    }
}
