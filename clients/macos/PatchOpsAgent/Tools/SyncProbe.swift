import Foundation

@main
struct SyncProbe {
    static func main() async throws {
        let environment = ProcessInfo.processInfo.environment
        var settings = AgentSettings()
        settings.apiURL = environment["PATCHOPS_API_URL"] ?? settings.apiURL
        settings.tenantID = environment["PATCHOPS_TENANT_ID"] ?? settings.tenantID
        settings.enrollmentToken = environment["PATCHOPS_ENROLLMENT_TOKEN"] ?? settings.enrollmentToken

        let snapshot = InventoryCollector().collect()
        let client = APIClient()
        let enrollment = try await client.enroll(snapshot: snapshot, settings: settings)
        try await client.upload(snapshot: snapshot, enrollment: enrollment, settings: settings)
        print("Synced \(snapshot.hostname) as \(enrollment.deviceId) with \(snapshot.software.count) applications")
    }
}
