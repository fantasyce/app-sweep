import SwiftUI

struct PaperPalette {
    let scheme: ColorScheme
    var paper: Color { color("FFFFFF", "252630") }
    var surface: Color { color("F7F8FB", "20212A") }
    var sidebar: Color { color("F0F0F6", "1B1C26") }
    var linen: Color { color("F7F8FB", "20212A") }
    var ink: Color { color("24242D", "ECECF3") }
    var secondary: Color { color("656775", "A4A3B4") }
    var line: Color { color("E9E9EF", "383945") }
    var accent: Color { color("7555BA", "AD91ED") }
    var sage: Color { color("EEE8F8", "393047") }
    var coral: Color { color("FBECEE", "493039") }
    var onAccent: Color { color("FFFFFF", "211733") }
    private func color(_ light: String, _ dark: String) -> Color {
        let value = UInt64(scheme == .dark ? dark : light, radix: 16)!
        return Color(red: Double((value >> 16) & 255) / 255, green: Double((value >> 8) & 255) / 255, blue: Double(value & 255) / 255)
    }
}
// Shared flat backgrounds never capture input or enter accessibility.
struct PaperBackground: View {
    @Environment(\.colorScheme) private var scheme
    var sidebar = false
    var body: some View {
        let palette = PaperPalette(scheme: scheme)
        (sidebar ? palette.sidebar : palette.paper)
            .allowsHitTesting(false).accessibilityHidden(true)
    }
}
// Keep the established component API while using regular native-style geometry.
struct PencilFrame: Shape {
    func path(in rect: CGRect) -> Path {
        RoundedRectangle(cornerRadius: 8, style: .continuous).path(in: rect.insetBy(dx: 0.5, dy: 0.5))
    }
}
struct PaperButton: ButtonStyle {
    @Environment(\.colorScheme) private var scheme
    @Environment(\.isEnabled) private var isEnabled
    var caution = false
    func makeBody(configuration: Configuration) -> some View {
        let palette = PaperPalette(scheme: scheme)
        configuration.label.font(SketchFont.body(14, weight: .medium)).padding(.horizontal, 18).padding(.vertical, 10)
            .foregroundColor(caution ? palette.ink : palette.onAccent)
            .background((caution ? palette.coral : palette.accent).opacity(configuration.isPressed ? 0.82 : 1))
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .contentShape(Rectangle())
            .opacity(isEnabled ? 1 : 0.45)
    }
}
enum SketchFont {
    // Retain the startup API; the system font needs no registration.
    static func register() { }
    static func body(_ size: CGFloat = 14, weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight)
    }
}
func byteText(_ bytes: Int64) -> String { ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file) }
