import AppKit
import SwiftUI

// Presentation only: an icon never supplies ownership evidence or cleanup authority.
@MainActor
struct ApplicationIcon: View {
    let path: String
    var size: CGFloat = 36
    @State private var icon: NSImage?
    @Environment(\.colorScheme) private var scheme
    private static let cache: NSCache<NSString, NSImage> = {
        let cache = NSCache<NSString, NSImage>()
        cache.countLimit = 128
        return cache
    }()

    var body: some View {
        Group {
            if let icon {
                Image(nsImage: icon).resizable().interpolation(.high).scaledToFit()
            } else {
                SketchIcon(symbol: .application)
                    .padding(6).foregroundColor(PaperPalette(scheme: scheme).secondary)
            }
        }
        .padding(3)
        .frame(width: size + 6, height: size + 6)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .accessibilityHidden(true)
        .task(id: path) {
            icon = nil
            // Finder resolves installed application aliases too. This read-only display
            // lookup does not change the Core's separate refusal to mutate links.
            guard !path.isEmpty, FileManager.default.fileExists(atPath: path) else { return }
            if let cached = Self.cache.object(forKey: path as NSString) {
                icon = cached
            } else {
                let loaded = NSWorkspace.shared.icon(forFile: path)
                Self.cache.setObject(loaded, forKey: path as NSString)
                icon = loaded
            }
        }
    }
}
