import Foundation

struct InventoryCollector {
    func collect() -> DeviceSnapshot {
        let process = ProcessInfo.processInfo
        let version = process.operatingSystemVersion
        let osVersion = "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
        let uptime = Int(process.systemUptime)
        let reboot = Date().addingTimeInterval(-process.systemUptime)

        return DeviceSnapshot(
            capturedAt: ISO8601DateFormatter().string(from: Date()),
            hostname: process.hostName,
            serialNumber: command("/usr/sbin/ioreg", ["-rd1", "-c", "IOPlatformExpertDevice"])
                .split(separator: "\n")
                .first(where: { $0.contains("IOPlatformSerialNumber") })?
                .split(separator: "=").last?
                .trimmingCharacters(in: CharacterSet(charactersIn: " \"") ) ?? "unknown",
            model: command("/usr/sbin/sysctl", ["-n", "hw.model"]).trimmingCharacters(in: .whitespacesAndNewlines),
            architecture: command("/usr/bin/uname", ["-m"]).trimmingCharacters(in: .whitespacesAndNewlines),
            os: OSInventory(name: "macOS", version: osVersion, build: command("/usr/bin/sw_vers", ["-buildVersion"]).trimmingCharacters(in: .whitespacesAndNewlines)),
            uptimeSeconds: uptime,
            lastRebootAt: ISO8601DateFormatter().string(from: reboot),
            batteryPercent: batteryPercentage(),
            software: applications()
        )
    }

    private func applications() -> [SoftwareItem] {
        let roots = [URL(fileURLWithPath: "/Applications"), URL(fileURLWithPath: "/System/Applications"), FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications")]
        var seen = Set<String>()
        var items: [SoftwareItem] = []

        for root in roots {
            guard let urls = try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]) else { continue }
            for url in urls where url.pathExtension == "app" {
                guard let bundle = Bundle(url: url) else { continue }
                let identifier = bundle.bundleIdentifier ?? url.deletingPathExtension().lastPathComponent
                guard seen.insert(identifier).inserted else { continue }
                items.append(SoftwareItem(
                    name: (bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String) ?? (bundle.object(forInfoDictionaryKey: "CFBundleName") as? String) ?? url.deletingPathExtension().lastPathComponent,
                    publisher: identifier.split(separator: ".").dropLast().joined(separator: "."),
                    version: (bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String) ?? (bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String) ?? "unknown",
                    installSource: "application_bundle",
                    bundleIdentifier: identifier
                ))
            }
        }
        return items.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    private func batteryPercentage() -> Int? {
        let output = command("/usr/bin/pmset", ["-g", "batt"])
        guard let percent = output.range(of: #"\d+%"#, options: .regularExpression) else { return nil }
        return Int(output[percent].dropLast())
    }

    private func command(_ executable: String, _ arguments: [String]) -> String {
        let task = Process()
        let pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: executable)
        task.arguments = arguments
        task.standardOutput = pipe
        task.standardError = Pipe()
        do {
            try task.run()
            task.waitUntilExit()
            return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        } catch {
            return ""
        }
    }
}
