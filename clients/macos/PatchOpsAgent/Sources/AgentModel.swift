import Foundation
import SwiftUI

@MainActor
final class AgentModel: ObservableObject {
    @Published var snapshot: DeviceSnapshot?
    @Published var state: AgentState = .ready
    @Published var statusMessage = "Ready to collect read-only inventory"
    @Published var settings = AgentSettings()
    @Published var lastSync: Date?
    @Published var selectedSection: SidebarSection? = .overview
    lazy var notifications = NotificationManager { [weak self] in self?.settings ?? AgentSettings() }

    private let collector = InventoryCollector()
    private let client = APIClient()
    private let keychain = KeychainStore()

    init() {
        loadSettings()
        loadSnapshot()
    }

    func scan() {
        state = .scanning
        statusMessage = "Scanning applications and system details…"
        Task.detached(priority: .userInitiated) { [collector] in
            let result = collector.collect()
            await MainActor.run {
                self.snapshot = result
                self.state = .healthy
                self.statusMessage = "Collected \(result.software.count) applications"
                self.saveSnapshot(result)
            }
        }
    }

    func sync() {
        guard let snapshot else {
            statusMessage = "Collect inventory before syncing"
            return
        }
        state = .syncing
        statusMessage = "Enrolling and uploading to PatchOps…"
        Task {
            do {
                let enrollment = try await client.enroll(snapshot: snapshot, settings: settings)
                try await client.upload(snapshot: snapshot, enrollment: enrollment, settings: settings)
                settings.deviceID = enrollment.deviceId
                settings.agentToken = enrollment.agentToken
                saveSettings()
                state = .healthy
                lastSync = Date()
                statusMessage = "Synced securely in POC mode"
            } catch {
                state = .failed
                statusMessage = error.localizedDescription
            }
        }
    }

    func saveSettings() {
        keychain.write(settings.enrollmentToken, account: "enrollment-token")
        keychain.write(settings.agentToken, account: "agent-token")
        var publicSettings = settings
        publicSettings.enrollmentToken = ""
        publicSettings.agentToken = nil
        guard let data = try? JSONEncoder().encode(publicSettings) else { return }
        try? data.write(to: settingsURL, options: .atomic)
    }

    private func loadSettings() {
        var containedLegacySecrets = false
        if let data = try? Data(contentsOf: settingsURL), let value = try? JSONDecoder().decode(AgentSettings.self, from: data) {
            settings = value
            containedLegacySecrets = !value.enrollmentToken.isEmpty || value.agentToken != nil
        }
        settings.enrollmentToken = keychain.read("enrollment-token") ?? settings.enrollmentToken
        settings.agentToken = keychain.read("agent-token") ?? settings.agentToken
        if containedLegacySecrets { saveSettings() }
    }

    private func saveSnapshot(_ value: DeviceSnapshot) {
        guard let data = try? JSONEncoder().encode(value) else { return }
        try? data.write(to: snapshotURL, options: .atomic)
    }

    private func loadSnapshot() {
        guard let data = try? Data(contentsOf: snapshotURL), let value = try? JSONDecoder().decode(DeviceSnapshot.self, from: data) else { return }
        snapshot = value
    }

    private var supportDirectory: URL {
        let url = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("PatchOpsAgent", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
    private var settingsURL: URL { supportDirectory.appendingPathComponent("settings.json") }
    private var snapshotURL: URL { supportDirectory.appendingPathComponent("inventory.json") }
}

enum SidebarSection: String, CaseIterable, Identifiable {
    case overview = "Overview"
    case inventory = "Inventory"
    case notifications = "Notifications"
    case settings = "Settings"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .overview: return "gauge.with.dots.needle.67percent"
        case .inventory: return "shippingbox"
        case .notifications: return "bell.badge"
        case .settings: return "gearshape"
        }
    }
}
