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
            "enrollment_token": settings.enrollmentToken,
            "hostname": snapshot.hostname,
            "platform": "macos",
            "serial_number": snapshot.serialNumber,
            "agent_version": "0.2.0"
        ]
        let data = try JSONSerialization.data(withJSONObject: body)
        return try await send(path: "/agent/enroll", data: data, settings: settings)
    }

    func upload(snapshot: DeviceSnapshot, enrollment: EnrollmentResponse, settings: AgentSettings) async throws {
        var heartbeat: [String: Any] = [
            "device_id": enrollment.deviceId,
            "agent_token": enrollment.agentToken,
            "seen_at": snapshot.capturedAt,
            "uptime_seconds": snapshot.uptimeSeconds,
            "last_reboot_at": snapshot.lastRebootAt,
            "reboot_pending": false,
            "online": true
        ]
        heartbeat["battery_percent"] = snapshot.batteryPercent ?? NSNull()
        _ = try await sendRaw(path: "/agent/heartbeat", data: try JSONSerialization.data(withJSONObject: heartbeat), settings: settings)

        let inventory = InventoryUpload(deviceID: enrollment.deviceId, capturedAt: snapshot.capturedAt, os: snapshot.os, software: snapshot.software)
        _ = try await sendRaw(path: "/agent/inventory", data: try encoder.encode(inventory), settings: settings)
    }

    func recordNotification(action: String, settings: AgentSettings) async throws {
        let payload: [String: String] = [
            "action_id": UUID().uuidString,
            "notification_id": "macos-agent-lab",
            "device_id": settings.deviceID ?? "lab-macos",
            "platform": "macos",
            "action": action
        ]
        _ = try await sendRaw(path: "/notifications/actions", data: try JSONSerialization.data(withJSONObject: payload), settings: settings)
    }

    private func send<T: Decodable>(path: String, data: Data, settings: AgentSettings) async throws -> T {
        let response = try await sendRaw(path: path, data: data, settings: settings)
        return try JSONDecoder().decode(T.self, from: response)
    }

    private func sendRaw(path: String, data: Data, settings: AgentSettings) async throws -> Data {
        guard let url = URL(string: settings.apiURL + path) else { throw APIError.invalidURL }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = data
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
