#if os(macOS)
import Foundation
import Darwin
import CFSafety

/// A conservative read-open check, not a macOS authorization API. No database
/// content is read, queried or logged. Missing/changed objects stay unknown.
/// Actual scan scopes and execution plans must still validate their own access.
public enum AccessPreparationProbe {
    public static func user() -> AccessReadiness.Result {
        guard getuid() == geteuid(), getuid() != 0, let home = try? SystemIdentity.home() else { return .unknown }
        return user(home: home, probe: readOpen)
    }
    static func user(home: String, probe: (String) -> AccessReadiness.Result) -> AccessReadiness.Result {
        let primary = probe(home + "/Library/Application Support/com.apple.TCC")
        // A fresh account may not have a per-user database. Only absence permits
        // the fixed system probe; a denial or uncertain result must stay visible.
        guard primary == .missing else { return primary }
        return probe("/Library/Application Support/com.apple.TCC")
    }
    static func system() -> AccessReadiness.Result {
        guard getuid() == 0, geteuid() == 0 else { return .unknown }
        // The service no longer indexes user documents. Check its actual fixed
        // system roots, not a privacy database unrelated to these operations.
        for path in ["/Library/Caches", "/Library/Logs"] {
            let fd = as_open_directory(path)
            guard fd >= 0 else { return failure(errno) }
            var value = stat()
            let valid = fstat(fd, &value) == 0 && value.st_mode & S_IFMT == S_IFDIR && value.st_uid == 0
            as_close(fd)
            guard valid else { return .unknown }
        }
        return .readable
    }
    private static func readOpen(parent: String) -> AccessReadiness.Result {
        let directory = as_open_directory(parent)
        guard directory >= 0 else { return failure(errno) }
        defer { as_close(directory) }
        let fd = openat(directory, "TCC.db", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return failure(errno) }
        defer { as_close(fd) }
        var value = stat()
        guard fstat(fd, &value) == 0, value.st_mode & S_IFMT == S_IFREG else { return .unknown }
        return .readable
    }
    static func failure(_ code: Int32) -> AccessReadiness.Result {
        switch code {
        case EACCES, EPERM: return .denied
        case ENOENT: return .missing
        default: return .unknown
        }
    }
}
#endif
