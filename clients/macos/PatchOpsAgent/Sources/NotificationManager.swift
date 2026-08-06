import AppKit
import Foundation
import UserNotifications

@MainActor
final class NotificationManager: NSObject, UNUserNotificationCenterDelegate, ObservableObject {
    private let settingsProvider: () -> AgentSettings
    @Published var authorizationGranted = false
    @Published var lastAction = "No notification action yet"

    init(settingsProvider: @escaping () -> AgentSettings) {
        self.settingsProvider = settingsProvider
        super.init()
        UNUserNotificationCenter.current().delegate = self
        registerCategories()
    }

    func requestPermission() async {
        do {
            authorizationGranted = try await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge])
        } catch {
            lastAction = "Notification permission failed: \(error.localizedDescription)"
        }
    }

    func sendUpdateNotification() async {
        if !authorizationGranted { await requestPermission() }
        let content = UNMutableNotificationContent()
        content.title = "Security updates are ready"
        content.subtitle = "Google Chrome and Zoom"
        content.body = "Two verified updates are ready. LAB MODE records your choice without installing software."
        content.sound = .default
        content.categoryIdentifier = "PATCHOPS_UPDATE"
        do {
            try await UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
            lastAction = "Notification delivered"
        } catch {
            lastAction = "Delivery failed: \(error.localizedDescription)"
        }
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .sound, .list]
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        let action: String
        switch response.actionIdentifier {
        case "PATCHOPS_INSTALL": action = "install_now"
        case "PATCHOPS_LATER": action = "defer"
        case "PATCHOPS_DETAILS": action = "details"
        default: action = "dismiss"
        }
        do {
            try await APIClient().recordNotification(action: action, settings: settingsProvider())
            lastAction = "Recorded \(action) in simulation mode"
        } catch {
            lastAction = "Action failed: \(error.localizedDescription)"
        }
    }

    private func registerCategories() {
        let install = UNNotificationAction(identifier: "PATCHOPS_INSTALL", title: "Install now", options: [.foreground])
        let later = UNNotificationAction(identifier: "PATCHOPS_LATER", title: "Later")
        let details = UNNotificationAction(identifier: "PATCHOPS_DETAILS", title: "Details", options: [.foreground])
        let category = UNNotificationCategory(identifier: "PATCHOPS_UPDATE", actions: [install, later, details], intentIdentifiers: [])
        UNUserNotificationCenter.current().setNotificationCategories([category])
    }
}
