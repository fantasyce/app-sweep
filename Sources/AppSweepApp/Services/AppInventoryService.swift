import AppKit
import Foundation

struct AppInventoryService {
    func loadInstalledApps() -> [InstalledApp] {
        let roots = [
            "/Applications",
            FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications").path
        ]

        var apps: [InstalledApp] = []
        var seen = Set<String>()

        for root in roots where FileManager.default.fileExists(atPath: root) {
            guard let children = try? FileManager.default.contentsOfDirectory(atPath: root) else { continue }
            for child in children where child.hasSuffix(".app") {
                let path = URL(fileURLWithPath: root).appendingPathComponent(child).standardizedFileURL.path
                guard !seen.contains(path), isDirectory(path) else { continue }
                seen.insert(path)

                let url = URL(fileURLWithPath: path)
                let bundle = Bundle(url: url)
                let bundleIdentifier = bundle?.bundleIdentifier ?? ""
                let fallbackName = url.deletingPathExtension().lastPathComponent
                let displayName = (bundle?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)?.nilIfBlank
                    ?? (bundle?.object(forInfoDictionaryKey: "CFBundleName") as? String)?.nilIfBlank
                    ?? fallbackName

                apps.append(InstalledApp(
                    id: path,
                    name: displayName,
                    path: path,
                    bundleIdentifier: bundleIdentifier,
                    isAppleProtected: bundleIdentifier.hasPrefix("com.apple.")
                ))
            }
        }

        return apps.sorted {
            $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }
    }

    private func isDirectory(_ path: String) -> Bool {
        var isDirectory: ObjCBool = false
        return FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory) && isDirectory.boolValue
    }
}

extension String {
    var nilIfBlank: String? {
        let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
