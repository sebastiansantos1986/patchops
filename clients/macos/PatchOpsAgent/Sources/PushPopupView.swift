import AppKit
import SwiftUI

@MainActor
final class PushPopupPresenter {
    static let shared = PushPopupPresenter()
    private var panels: [String: NSPanel] = [:]

    func show(_ notification: RemoteNotification, action: @escaping (String) -> Void) {
        guard panels[notification.id] == nil else { return }
        let appearance = notification.appearance
        let width = CGFloat(min(720, max(420, appearance?.popupWidth ?? 540)))
        let view = PushPopupView(notification: notification) { [weak self] selectedAction in
            self?.panels[notification.id]?.close()
            self?.panels.removeValue(forKey: notification.id)
            action(selectedAction)
        }
        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: width, height: 430),
            styleMask: [.borderless, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        panel.contentView = NSHostingView(rootView: view)
        panel.backgroundColor = .clear
        panel.isOpaque = false
        panel.hasShadow = true
        panel.level = .floating
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.isMovableByWindowBackground = true
        panel.title = notification.title
        position(panel, preference: appearance?.position ?? "center")
        panels[notification.id] = panel
        if let sound = appearance?.sound, !sound.isEmpty { NSSound(named: NSSound.Name(sound))?.play() }
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
    }

    private func position(_ panel: NSPanel, preference: String) {
        guard let frame = NSScreen.main?.visibleFrame else { panel.center(); return }
        let margin: CGFloat = 22
        switch preference {
        case "topRight": panel.setFrameOrigin(.init(x: frame.maxX - panel.frame.width - margin, y: frame.maxY - panel.frame.height - margin))
        case "topLeft": panel.setFrameOrigin(.init(x: frame.minX + margin, y: frame.maxY - panel.frame.height - margin))
        case "bottomRight": panel.setFrameOrigin(.init(x: frame.maxX - panel.frame.width - margin, y: frame.minY + margin))
        case "bottomLeft": panel.setFrameOrigin(.init(x: frame.minX + margin, y: frame.minY + margin))
        default: panel.center()
        }
    }
}

struct PushPopupView: View {
    let notification: RemoteNotification
    let onAction: (String) -> Void
    private var appearance: RemoteNotificationAppearance? { notification.appearance }
    private var accent: Color { Color(patchOpsHex: appearance?.accentColor ?? "#2563EB") }

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .top, spacing: 16) {
                ZStack {
                    RoundedRectangle(cornerRadius: 15).fill(LinearGradient(colors: [accent, accent.opacity(0.72)], startPoint: .topLeading, endPoint: .bottomTrailing))
                    Image(systemName: appearance?.symbol ?? "arrow.down.circle.fill").font(.system(size: 27, weight: .semibold)).foregroundStyle(.white)
                }.frame(width: 58, height: 58)
                VStack(alignment: .leading, spacing: 5) {
                    Text(appearance?.appName ?? "PatchOps Security Updates").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                    Text(notification.title).font(.system(size: 24, weight: .bold)).fixedSize(horizontal: false, vertical: true)
                    if !notification.subtitle.isEmpty { Text(notification.subtitle).font(.subheadline.weight(.medium)).foregroundStyle(accent) }
                }
                Spacer()
                if appearance?.showClose ?? true { Button { onAction("dismiss") } label: { Image(systemName: "xmark").frame(width: 26, height: 26) }.buttonStyle(.plain).foregroundStyle(.secondary) }
            }.padding(24)

            Divider().opacity(0.55)
            VStack(alignment: .leading, spacing: 18) {
                Text(notification.body).font(.system(size: 15)).foregroundStyle(.secondary).lineSpacing(4).fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 10) {
                    Label("Safe test mode", systemImage: "checkmark.shield.fill").foregroundStyle(.green)
                    Spacer()
                    if let organization = appearance?.organization, !organization.isEmpty { Text(organization).foregroundStyle(.secondary) }
                }.font(.caption.weight(.medium))
            }.padding(24)

            Divider().opacity(0.55)
            HStack(spacing: 12) {
                if let email = appearance?.supportEmail, !email.isEmpty { Text(email).font(.caption).foregroundStyle(.secondary).lineLimit(1) }
                Spacer()
                Button(appearance?.secondaryLabel ?? "Remind Me Later") { onAction("defer") }.buttonStyle(.bordered).controlSize(.large)
                Button(appearance?.primaryLabel ?? "Install Now") { onAction("install_now") }.buttonStyle(.borderedProminent).tint(accent).controlSize(.large)
            }.padding(20)
        }
        .frame(width: CGFloat(min(720, max(420, appearance?.popupWidth ?? 540))))
        .background(.regularMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 22, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 22, style: .continuous).stroke(Color.primary.opacity(0.12), lineWidth: 1))
    }
}

private extension Color {
    init(patchOpsHex: String) {
        let value = patchOpsHex.trimmingCharacters(in: CharacterSet(charactersIn: "#"))
        let number = UInt64(value, radix: 16) ?? 0x2563EB
        self.init(red: Double((number >> 16) & 0xFF) / 255, green: Double((number >> 8) & 0xFF) / 255, blue: Double(number & 0xFF) / 255)
    }
}
