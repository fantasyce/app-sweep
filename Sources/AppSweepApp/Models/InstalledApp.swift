import Foundation

struct InstalledApp: Identifiable, Hashable, Sendable {
    let id: String
    let name: String
    let path: String
    let bundleIdentifier: String
    let isAppleProtected: Bool

    var subtitle: String {
        bundleIdentifier.isEmpty ? path : bundleIdentifier
    }
}
