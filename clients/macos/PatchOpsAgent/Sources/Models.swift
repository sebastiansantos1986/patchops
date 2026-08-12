import Foundation

struct SoftwareItem: Codable, Identifiable, Hashable {
    var id: String { bundleIdentifier + version }
    let name: String
    let publisher: String
    let version: String
    let installSource: String
    let bundleIdentifier: String

    enum CodingKeys: String, CodingKey {
        case name, publisher, version
        case installSource = "install_source"
        case bundleIdentifier = "bundle_identifier"
    }
}

struct OSInventory: Codable {
    let name: String
    let version: String
    let build: String
}

struct DeviceSnapshot: Codable {
    let capturedAt: String
    let hostname: String
    let serialNumber: String
    let model: String
    let architecture: String
    let os: OSInventory
    let uptimeSeconds: Int
    let lastRebootAt: String
    let batteryPercent: Int?
    let software: [SoftwareItem]

    enum CodingKeys: String, CodingKey {
        case hostname, model, architecture, os, software
        case capturedAt = "captured_at"
        case serialNumber = "serial_number"
        case uptimeSeconds = "uptime_seconds"
        case lastRebootAt = "last_reboot_at"
        case batteryPercent = "battery_percent"
    }
}

struct EnrollmentResponse: Codable {
    let deviceId: String
    let agentToken: String
    let policyVersion: String

    enum CodingKeys: String, CodingKey {
        case deviceId = "device_id"
        case agentToken = "agent_token"
        case policyVersion = "policy_version"
    }
}

struct RemoteNotification: Codable, Identifiable {
    let id: String
    let deviceID: String
    let title: String
    let subtitle: String
    let body: String
    let category: String
    let presentation: String?
    let appearance: RemoteNotificationAppearance?

    enum CodingKeys: String, CodingKey {
        case id, title, subtitle, body, category, presentation, appearance
        case deviceID = "device_id"
    }
}

struct RemoteNotificationAppearance: Codable {
    let appName: String?
    let organization: String?
    let accentColor: String?
    let symbol: String?
    let popupWidth: Int?
    let position: String?
    let sound: String?
    let primaryLabel: String?
    let secondaryLabel: String?
    let showClose: Bool?
    let maxDeferrals: Int?
    let requireDeferralReason: Bool?
    let supportEmail: String?
    let supportPhone: String?
    let helpURL: String?

    enum CodingKeys: String, CodingKey {
        case organization, symbol, position, sound
        case appName = "app_name"
        case accentColor = "accent_color"
        case popupWidth = "popup_width"
        case primaryLabel = "primary_label"
        case secondaryLabel = "secondary_label"
        case showClose = "show_close"
        case maxDeferrals = "max_deferrals"
        case requireDeferralReason = "require_deferral_reason"
        case supportEmail = "support_email"
        case supportPhone = "support_phone"
        case helpURL = "help_url"
    }
}

struct NotificationEnvelope: Codable {
    let notifications: [RemoteNotification]
}

struct AgentSettings: Codable {
    var apiURL = "http://127.0.0.1:3000/api"
    var tenantID = "acme-prod"
    var enrollmentToken = "POC-MACOS-ENROLL-TOKEN"
    var deviceID: String?
    var agentToken: String?
}

enum AgentState: String {
    case ready = "Ready"
    case scanning = "Scanning"
    case syncing = "Syncing"
    case healthy = "Healthy"
    case failed = "Needs attention"
}
