import Foundation

struct BackupItem: Identifiable, Equatable, Sendable {
    var id: String { url.path }

    let url: URL
    let name: String
    let appName: String
    let modifiedAt: Date
    let sizeBytes: UInt64
    let fileCount: Int
}

enum BackupCatalog {
    static func load(from root: URL) -> [BackupItem] {
        let fileManager = FileManager()
        guard let children = try? fileManager.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: [.isDirectoryKey, .contentModificationDateKey],
            options: [.skipsHiddenFiles]
        ) else {
            return []
        }

        return children.compactMap { url -> BackupItem? in
            guard ((try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) ?? false) else {
                return nil
            }

            let size = directorySize(at: url)
            let modifiedAt = (try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            let name = url.lastPathComponent
            return BackupItem(
                url: url,
                name: name,
                appName: appName(from: name),
                modifiedAt: modifiedAt,
                sizeBytes: size.bytes,
                fileCount: size.files
            )
        }
        .sorted { lhs, rhs in
            if lhs.modifiedAt == rhs.modifiedAt {
                return lhs.name.localizedCaseInsensitiveCompare(rhs.name) == .orderedAscending
            }
            return lhs.modifiedAt > rhs.modifiedAt
        }
    }

    private static func appName(from backupName: String) -> String {
        guard let marker = backupName.range(of: "-20", options: .backwards) else {
            return backupName
        }
        let name = String(backupName[..<marker.lowerBound]).trimmingCharacters(in: .whitespacesAndNewlines)
        return name.isEmpty ? backupName : name
    }

    private static func directorySize(at url: URL) -> (bytes: UInt64, files: Int) {
        let fileManager = FileManager()
        guard let enumerator = fileManager.enumerator(
            at: url,
            includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey, .totalFileAllocatedSizeKey],
            options: [.skipsHiddenFiles],
            errorHandler: nil
        ) else {
            return (0, 0)
        }

        var bytes: UInt64 = 0
        var files = 0
        for case let fileURL as URL in enumerator {
            guard let values = try? fileURL.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey, .totalFileAllocatedSizeKey]),
                  values.isRegularFile == true else {
                continue
            }
            files += 1
            let allocatedSize = values.totalFileAllocatedSize ?? values.fileSize ?? 0
            bytes += UInt64(max(allocatedSize, 0))
        }
        return (bytes, files)
    }
}
