import Foundation

enum APIError: LocalizedError {
    case invalidURL
    case rejected(Int, String)

    var errorDescription: String? {
        switch self {
        case .invalidURL: return "The PatchOps API URL is invalid."
        case let .rejected(status, message): return "PatchOps API returned \(status): \(message)"
        }
    }
}

struct APIClient {
    private let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }()

    func enroll(snapshot: DeviceSnapshot, settings: AgentSettings) async throws -> EnrollmentResponse {
        let body: [String: String] = [
            "tenant_id": settings.tenantID,
            "hostname": snapshot.hostname,
            "platform": "macos",
            "serial_number": snapshot.serialNumber,
            "agent_version": "0.5.0"
        ]
        let data = try JSONSerialization.data(withJSONObject: body)
        return try await send(path: "/agent/enroll", data: data, settings: settings, authorization: "Enrollment \(settings.enrollmentToken)")
    }

    func upload(snapshot: DeviceSnapshot, enrollment: EnrollmentResponse, settings: AgentSettings) async throws {
        var heartbeat: [String: Any] = [
            "device_id": enrollment.deviceId,
            "seen_at": snapshot.capturedAt,
            "uptime_seconds": snapshot.uptimeSeconds,
            "last_reboot_at": snapshot.lastRebootAt,
            "reboot_pending": false,
            "online": true
        ]
        heartbeat["battery_percent"] = snapshot.batteryPercent ?? NSNull()
        _ = try await sendRaw(path: "/agent/heartbeat", data: try JSONSerialization.data(withJSONObject: heartbeat), settings: settings, authorization: "Bearer \(enrollment.agentToken)")

        let inventory = InventoryUpload(deviceID: enrollment.deviceId, capturedAt: snapshot.capturedAt, os: snapshot.os, software: snapshot.software)
        _ = try await sendRaw(path: "/agent/inventory", data: try encoder.encode(inventory), settings: settings, authorization: "Bearer \(enrollment.agentToken)")
    }

    func fetchNotifications(settings: AgentSettings) async throws -> [RemoteNotification] {
        guard let deviceID = settings.deviceID, let agentToken = settings.agentToken else { return [] }
        guard var components = URLComponents(string: settings.apiURL + "/agent/notifications") else { throw APIError.invalidURL }
        components.queryItems = [URLQueryItem(name: "device_id", value: deviceID)]
        guard let url = components.url else { throw APIError.invalidURL }
        var request = URLRequest(url: url)
        request.setValue("Bearer \(agentToken)", forHTTPHeaderField: "Authorization")
        let responseData = try await perform(request)
        return try JSONDecoder().decode(NotificationEnvelope.self, from: responseData).notifications
    }

    func fetchPolicy(settings: AgentSettings) async throws -> RemoteAgentPolicy {
        guard let deviceID = settings.deviceID, let agentToken = settings.agentToken else { return RemoteAgentPolicy() }
        guard var components = URLComponents(string: settings.apiURL + "/agent/policy") else { throw APIError.invalidURL }
        components.queryItems = [URLQueryItem(name: "device_id", value: deviceID)]
        guard let url = components.url else { throw APIError.invalidURL }
        var request = URLRequest(url: url)
        request.setValue("Bearer \(agentToken)", forHTTPHeaderField: "Authorization")
        return try JSONDecoder().decode(RemoteAgentPolicy.self, from: try await perform(request))
    }

    func acknowledgeNotification(_ notificationID: String, settings: AgentSettings) async throws {
        guard let deviceID = settings.deviceID, let agentToken = settings.agentToken else { return }
        let payload = ["device_id": deviceID, "notification_id": notificationID]
        _ = try await sendRaw(path: "/agent/notifications/ack", data: try JSONSerialization.data(withJSONObject: payload), settings: settings, authorization: "Bearer \(agentToken)")
    }

    func recordNotification(action: String, notificationID: String = "macos-agent-lab", settings: AgentSettings) async throws {
        let payload: [String: String] = [
            "action_id": UUID().uuidString,
            "notification_id": notificationID,
            "device_id": settings.deviceID ?? "lab-macos",
            "platform": "macos",
            "action": action
        ]
        _ = try await sendRaw(path: "/notifications/actions", data: try JSONSerialization.data(withJSONObject: payload), settings: settings, authorization: settings.agentToken.map { "Bearer \($0)" })
    }

    private func send<T: Decodable>(path: String, data: Data, settings: AgentSettings, authorization: String? = nil) async throws -> T {
        let response = try await sendRaw(path: path, data: data, settings: settings, authorization: authorization)
        return try JSONDecoder().decode(T.self, from: response)
    }

    private func sendRaw(path: String, data: Data, settings: AgentSettings, authorization: String? = nil) async throws -> Data {
        guard let url = URL(string: settings.apiURL + path) else { throw APIError.invalidURL }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let authorization { request.setValue(authorization, forHTTPHeaderField: "Authorization") }
        request.httpBody = data
        return try await perform(request)
    }

    private func perform(_ request: URLRequest) async throws -> Data {
        let (responseData, response) = try await URLSession(configuration: .ephemeral).data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else { throw APIError.rejected(status, String(data: responseData, encoding: .utf8) ?? "Unknown error") }
        return responseData
    }
}

private struct InventoryUpload: Encodable {
    let deviceID: String
    let capturedAt: String
    let os: OSInventory
    let software: [SoftwareItem]

    enum CodingKeys: String, CodingKey {
        case os, software
        case deviceID = "device_id"
        case capturedAt = "captured_at"
    }
}
