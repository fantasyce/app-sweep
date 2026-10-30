import AppKit
import SwiftUI

// Standard symbols keep drawing, hit testing and accessibility independent.
enum SketchSymbol { case clean, applications, recovery, settings, chevron, check, application }

struct SketchIcon: View {
    let symbol: SketchSymbol
    var body: some View {
        Image(systemName: systemName)
            .font(.system(size: 16, weight: .regular))
            .frame(width: 18, height: 18).accessibilityHidden(true)
    }
    private var systemName: String {
        switch symbol {
        case .clean: "sparkles"
        case .applications: "square.grid.2x2"
        case .recovery: "arrow.uturn.backward"
        case .settings: "slider.horizontal.3"
        case .chevron: "chevron.right"
        case .check: "checkmark"
        case .application: "app"
        }
    }
}

struct SketchDisclosure<Content: View>: View {
    let title: String
    private let externalExpansion: Binding<Bool>?
    private let content: Content
    @State private var localExpansion = false
    init(_ title: String, isExpanded: Binding<Bool>? = nil, @ViewBuilder content: () -> Content) {
        self.title = title; externalExpansion = isExpanded; self.content = content()
    }
    private var expansion: Binding<Bool> { externalExpansion ?? $localExpansion }
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Button { expansion.wrappedValue.toggle() } label: {
                HStack(spacing: 6) {
                    SketchIcon(symbol: .chevron).rotationEffect(.degrees(expansion.wrappedValue ? 90 : 0))
                    Text(title).multilineTextAlignment(.leading)
                    Spacer(minLength: 0)
                }.padding(.vertical, 4).frame(maxWidth: .infinity, alignment: .leading).contentShape(Rectangle())
            }.buttonStyle(.plain)
                .accessibilityLabel(title).accessibilityValue(expansion.wrappedValue ? "已展开" : "已收起")
                .accessibilityHint("按下可展开或收起内容")
            if expansion.wrappedValue { content.padding(.leading, 24) }
        }
    }
}

struct SketchMenuItem: Identifiable {
    let id: String
    let title: String
    var enabled = true
    var selected = false
    let action: () -> Void
}

struct SketchMenu: View {
    let title: String
    var symbol: SketchSymbol? = nil
    let items: [SketchMenuItem]
    @Environment(\.colorScheme) private var scheme
    @State private var presented = false
    @State private var focused: String?
    private var palette: PaperPalette { PaperPalette(scheme: scheme) }
    var body: some View {
        Button { presented.toggle() } label: {
            HStack(spacing: 7) {
                if let symbol { SketchIcon(symbol: symbol) }
                Text(title)
                SketchIcon(symbol: .chevron).rotationEffect(.degrees(90)).scaleEffect(0.7)
            }.padding(.horizontal, 10).padding(.vertical, 6)
                .background(palette.linen, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 7, style: .continuous).stroke(palette.line, lineWidth: 1))
                .contentShape(Rectangle())
        }.buttonStyle(.plain).font(SketchFont.body(13))
            .accessibilityLabel(title).accessibilityValue(presented ? "已展开" : "已收起")
            .popover(isPresented: $presented, arrowEdge: .bottom) {
                ScrollViewReader { proxy in
                    ScrollView {
                        VStack(spacing: 2) {
                            ForEach(items) { item in
                                Button { presented = false; item.action() } label: {
                                    HStack(spacing: 8) {
                                        SketchIcon(symbol: .check).opacity(item.selected ? 1 : 0)
                                        Text(item.title).multilineTextAlignment(.leading)
                                        Spacer(minLength: 0)
                                    }.padding(.horizontal, 10).padding(.vertical, 8).frame(maxWidth: .infinity, alignment: .leading).contentShape(Rectangle())
                                }.buttonStyle(SketchMenuRow(highlighted: focused == item.id)).disabled(!item.enabled).id(item.id)
                                    .onHover { inside in if inside && item.enabled { focused = item.id } }
                                    .accessibilityAddTraits(item.selected ? .isSelected : [])
                            }
                        }.padding(8)
                    }.frame(width: 300, height: min(340, CGFloat(items.count) * 36 + 16))
                        .onChange(of: focused) { value in if let value { proxy.scrollTo(value) } }
                }.font(SketchFont.body(13)).foregroundColor(palette.ink).background(PaperBackground())
                    .overlay(PencilFrame().stroke(palette.line, lineWidth: 1)).padding(2)
                    .onAppear { focused = items.first(where: \.enabled)?.id }
                    .onExitCommand { presented = false }
                    .background(MenuKeyboardInput { key in
                        if key == 53 { presented = false; return true }
                        if key == 36 || key == 76 || key == 49 {
                            if let item = items.first(where: { $0.id == focused && $0.enabled }) {
                                presented = false; item.action()
                            }
                            return true
                        }
                        guard key == 125 || key == 126 else { return false }
                        let enabled = items.filter(\.enabled)
                        guard !enabled.isEmpty else { return true }
                        let index = enabled.firstIndex(where: { $0.id == focused }) ?? 0
                        focused = enabled[(index + (key == 125 ? 1 : enabled.count - 1)) % enabled.count].id
                        return true
                    })
            }
    }
}

private struct SketchMenuRow: ButtonStyle {
    var highlighted: Bool
    @Environment(\.colorScheme) private var scheme
    @Environment(\.isEnabled) private var enabled
    @State private var hovered = false
    func makeBody(configuration: Configuration) -> some View {
        let palette = PaperPalette(scheme: scheme)
        configuration.label.background(highlighted || hovered || configuration.isPressed ? palette.sage : .clear)
            .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
            .opacity(enabled ? 1 : 0.45).onHover { hovered = $0 }
    }
}

// Scope keyboard handling to the popover's own responder. Return must never
// fall through to the main window's default scan/execute button.
private struct MenuKeyboardInput: NSViewRepresentable {
    let handle: (UInt16) -> Bool
    func makeNSView(context: Context) -> KeyView { let view = KeyView(); view.handle = handle; return view }
    func updateNSView(_ view: KeyView, context: Context) { view.handle = handle }
    final class KeyView: NSView {
        var handle: (UInt16) -> Bool = { _ in false }
        override var acceptsFirstResponder: Bool { true }
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            DispatchQueue.main.async { [weak self] in
                guard let self, let window = self.window else { return }
                window.makeKey(); window.makeFirstResponder(self)
            }
        }
        override func keyDown(with event: NSEvent) {
            if !handle(event.keyCode) { super.keyDown(with: event) }
        }
        override func performKeyEquivalent(with event: NSEvent) -> Bool {
            guard event.modifierFlags.intersection([.command, .control, .option]).isEmpty else { return super.performKeyEquivalent(with: event) }
            return handle(event.keyCode) || super.performKeyEquivalent(with: event)
        }
    }
}

// Keep macOS checkbox semantics and keyboard support; draw only its appearance.
struct SketchCheckbox: ToggleStyle {
    @Environment(\.colorScheme) private var scheme
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        let palette = PaperPalette(scheme: scheme)
        Toggle(isOn: configuration.$isOn) {
            HStack(alignment: .top, spacing: 8) {
                ZStack {
                    RoundedRectangle(cornerRadius: 4).fill(configuration.isOn ? palette.accent : palette.paper)
                    RoundedRectangle(cornerRadius: 4).stroke(configuration.isOn ? palette.accent : palette.secondary.opacity(0.8), lineWidth: 1)
                    if configuration.isOn {
                        Image(systemName: "checkmark").font(.system(size: 10, weight: .bold)).foregroundColor(palette.onAccent)
                    }
                }.frame(width: 16, height: 16).padding(.top, 2).accessibilityHidden(true)
                configuration.label
            }.contentShape(Rectangle())
        }.toggleStyle(.button).buttonStyle(.plain).opacity(enabled ? 1 : 0.45)
    }
}

// Apply the roomier initial size once, then respect the user's saved window size.
struct InitialPaperWindow: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView { WindowProbe() }
    func updateNSView(_ nsView: NSView, context: Context) { }
    private final class WindowProbe: NSView {
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            guard let window, !UserDefaults.standard.bool(forKey: "roomierPaperWindowV30") else { return }
            DispatchQueue.main.async { [weak window] in
                guard let window, let screen = window.screen ?? NSScreen.main else { return }
                let available = screen.visibleFrame
                window.setContentSize(NSSize(width: min(1100, available.width - 40), height: min(740, available.height - 80)))
                window.center()
                UserDefaults.standard.set(true, forKey: "roomierPaperWindowV30")
            }
        }
    }
}
