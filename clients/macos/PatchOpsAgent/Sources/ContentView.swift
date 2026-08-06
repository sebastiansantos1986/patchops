import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var model: AgentModel

    var body: some View {
        NavigationSplitView {
            sidebar
                .navigationSplitViewColumnWidth(min: 210, ideal: 230, max: 260)
        } detail: {
            ZStack {
                Color(nsColor: .windowBackgroundColor).ignoresSafeArea()
                detail.padding(26)
            }
        }
        .tint(.blue)
        .task {
            if model.snapshot == nil { model.scan() }
        }
    }

    private var sidebar: some View {
        ZStack {
            LinearGradient(colors: [Color(red: 0.025, green: 0.08, blue: 0.15), Color(red: 0.03, green: 0.16, blue: 0.25)], startPoint: .top, endPoint: .bottom).ignoresSafeArea()
            VStack(alignment: .leading, spacing: 20) {
                HStack(spacing: 12) {
                    Image(systemName: "shield.lefthalf.filled")
                        .font(.system(size: 22, weight: .bold)).foregroundStyle(.white)
                        .frame(width: 42, height: 42).background(LinearGradient(colors: [.blue, .teal], startPoint: .topLeading, endPoint: .bottomTrailing)).clipShape(RoundedRectangle(cornerRadius: 12))
                    VStack(alignment: .leading, spacing: 2) {
                        Text("PatchOps").font(.headline).foregroundStyle(.white)
                        Text("macOS Agent · Lab").font(.caption).foregroundStyle(.white.opacity(0.62))
                    }
                }
                .padding(.horizontal, 16).padding(.top, 12)

                ForEach(SidebarSection.allCases) { section in
                    Button {
                        model.selectedSection = section
                    } label: {
                        Label(section.rawValue, systemImage: section.icon)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 13).padding(.vertical, 10)
                            .background(model.selectedSection == section ? Color.blue.opacity(0.28) : Color.clear)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    .buttonStyle(.plain).foregroundStyle(model.selectedSection == section ? .white : .white.opacity(0.7)).padding(.horizontal, 10)
                }
                Spacer()
                HStack(spacing: 9) {
                    Circle().fill(model.state == .failed ? .red : .green).frame(width: 9, height: 9)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(model.state.rawValue).font(.caption.bold()).foregroundStyle(.white)
                        Text(model.statusMessage).font(.caption2).foregroundStyle(.white.opacity(0.6)).lineLimit(2)
                    }
                }
                .padding(14).background(.white.opacity(0.06)).clipShape(RoundedRectangle(cornerRadius: 12)).padding(12)
            }
        }
    }

    @ViewBuilder private var detail: some View {
        switch model.selectedSection ?? .overview {
        case .overview: OverviewView()
        case .inventory: InventoryView()
        case .notifications: NotificationsView()
        case .settings: SettingsView()
        }
    }
}

private struct PageHeader: View {
    let title: String
    let subtitle: String
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.system(size: 28, weight: .bold, design: .rounded))
            Text(subtitle).foregroundStyle(.secondary)
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct MetricCard: View {
    let icon: String
    let label: String
    let value: String
    let color: Color
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Image(systemName: icon).font(.title2).foregroundStyle(color).frame(width: 38, height: 38).background(color.opacity(0.1)).clipShape(RoundedRectangle(cornerRadius: 10))
            Text(value).font(.system(size: 25, weight: .bold, design: .rounded))
            Text(label).font(.caption).foregroundStyle(.secondary)
        }.frame(maxWidth: .infinity, alignment: .leading).padding(18).background(.background).clipShape(RoundedRectangle(cornerRadius: 16)).shadow(color: .black.opacity(0.06), radius: 12, y: 5)
    }
}

private struct OverviewView: View {
    @EnvironmentObject private var model: AgentModel
    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                HStack {
                    PageHeader(title: "This Mac", subtitle: "Read-only inventory and PatchOps connectivity")
                    Button("Scan now", systemImage: "arrow.clockwise") { model.scan() }
                    Button("Sync to PatchOps", systemImage: "arrow.up.circle.fill") { model.sync() }.buttonStyle(.borderedProminent)
                }
                HStack(spacing: 14) {
                    MetricCard(icon: "desktopcomputer", label: "Device", value: model.snapshot?.model ?? "Scanning…", color: .blue)
                    MetricCard(icon: "apple.logo", label: "Operating system", value: model.snapshot.map { "macOS \($0.os.version)" } ?? "—", color: .purple)
                    MetricCard(icon: "shippingbox.fill", label: "Applications discovered", value: "\(model.snapshot?.software.count ?? 0)", color: .teal)
                }
                VStack(alignment: .leading, spacing: 16) {
                    Text("Agent activity").font(.title3.bold())
                    activityRow("Inventory collection", detail: model.snapshot == nil ? "Waiting" : "Complete", icon: "checkmark.circle.fill", color: .green)
                    activityRow("PatchOps enrollment", detail: model.settings.deviceID ?? "Not enrolled", icon: "person.badge.key.fill", color: model.settings.deviceID == nil ? .orange : .green)
                    activityRow("Last control-plane sync", detail: model.lastSync?.formatted(date: .abbreviated, time: .standard) ?? "Not synced this session", icon: "network", color: .blue)
                }.cardStyle()
                safetyBanner
            }
        }
    }

    private func activityRow(_ title: String, detail: String, icon: String, color: Color) -> some View {
        HStack { Image(systemName: icon).foregroundStyle(color); Text(title).fontWeight(.semibold); Spacer(); Text(detail).foregroundStyle(.secondary) }.padding(.vertical, 4)
    }

    private var safetyBanner: some View {
        HStack(spacing: 14) {
            Image(systemName: "lock.shield.fill").font(.title).foregroundStyle(.green)
            VStack(alignment: .leading, spacing: 3) { Text("Safe lab mode is locked on").font(.headline); Text("This build can collect inventory and record notification actions. It cannot install software, close apps, or restart this Mac.").foregroundStyle(.secondary) }
            Spacer()
            Text("SIMULATION").font(.caption.bold()).foregroundStyle(.green).padding(.horizontal, 10).padding(.vertical, 6).background(.green.opacity(0.1)).clipShape(Capsule())
        }.padding(18).background(.green.opacity(0.05)).overlay(RoundedRectangle(cornerRadius: 16).stroke(.green.opacity(0.25))).clipShape(RoundedRectangle(cornerRadius: 16))
    }
}

private struct InventoryView: View {
    @EnvironmentObject private var model: AgentModel
    @State private var search = ""
    var apps: [SoftwareItem] { (model.snapshot?.software ?? []).filter { search.isEmpty || $0.name.localizedCaseInsensitiveContains(search) || $0.bundleIdentifier.localizedCaseInsensitiveContains(search) } }
    var body: some View {
        VStack(spacing: 18) {
            HStack { PageHeader(title: "Application inventory", subtitle: "Apps discovered in system and user Applications folders"); Button("Rescan", systemImage: "arrow.clockwise") { model.scan() } }
            TextField("Search applications or bundle identifiers", text: $search).textFieldStyle(.roundedBorder)
            Table(apps) {
                TableColumn("Application", value: \.name)
                TableColumn("Version", value: \.version).width(min: 100, ideal: 130)
                TableColumn("Bundle identifier", value: \.bundleIdentifier)
                TableColumn("Source", value: \.installSource).width(min: 120, ideal: 150)
            }.clipShape(RoundedRectangle(cornerRadius: 14))
        }
    }
}

private struct NotificationsView: View {
    @EnvironmentObject private var model: AgentModel
    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                HStack { PageHeader(title: "Notification lab", subtitle: "Native macOS banners with verified action callbacks"); Button("Request permission") { Task { await model.notifications.requestPermission() } }; Button("Send test notification", systemImage: "bell.badge.fill") { Task { await model.notifications.sendUpdateNotification() } }.buttonStyle(.borderedProminent) }
                VStack(alignment: .leading, spacing: 16) {
                    HStack { Image(systemName: "bell.and.waves.left.and.right.fill").font(.title).foregroundStyle(.blue); VStack(alignment: .leading) { Text("Security updates are ready").font(.title3.bold()); Text("Google Chrome and Zoom").foregroundStyle(.secondary) }; Spacer(); Text("LAB MODE").font(.caption.bold()).foregroundStyle(.blue) }
                    Text("Two verified updates are ready. Choose an action from the native Notification Center banner. Your selection is recorded in PatchOps without changing this Mac.").foregroundStyle(.secondary)
                    HStack { actionChip("Install now", icon: "arrow.down.circle.fill", color: .blue); actionChip("Later", icon: "clock.fill", color: .orange); actionChip("Details", icon: "info.circle.fill", color: .teal) }
                }.padding(22).background(LinearGradient(colors: [.blue.opacity(0.1), .teal.opacity(0.06)], startPoint: .topLeading, endPoint: .bottomTrailing)).overlay(RoundedRectangle(cornerRadius: 18).stroke(.blue.opacity(0.2))).clipShape(RoundedRectangle(cornerRadius: 18))
                VStack(alignment: .leading, spacing: 8) { Text("Latest result").font(.headline); Text(model.notifications.lastAction).foregroundStyle(.secondary); Divider(); Label(model.notifications.authorizationGranted ? "Notification permission granted" : "Permission not granted yet", systemImage: model.notifications.authorizationGranted ? "checkmark.circle.fill" : "exclamationmark.circle.fill").foregroundStyle(model.notifications.authorizationGranted ? .green : .orange) }.cardStyle()
            }
        }
    }
    private func actionChip(_ text: String, icon: String, color: Color) -> some View { Label(text, systemImage: icon).font(.caption.bold()).foregroundStyle(color).padding(.horizontal, 12).padding(.vertical, 8).background(color.opacity(0.1)).clipShape(Capsule()) }
}

private struct SettingsView: View {
    @EnvironmentObject private var model: AgentModel
    var body: some View {
        Form {
            PageHeader(title: "Agent settings", subtitle: "Local POC connection settings")
            Section("Control plane") {
                TextField("API URL", text: $model.settings.apiURL)
                TextField("Tenant", text: $model.settings.tenantID)
                SecureField("Enrollment token", text: $model.settings.enrollmentToken)
                Button("Use hosted development API") { model.settings.apiURL = "https://patchops-api-sebastiansantos1986.onrender.com/api" }
            }
            Section("Identity") { LabeledContent("Device ID", value: model.settings.deviceID ?? "Not enrolled"); LabeledContent("Credentials", value: "Protected by macOS Keychain") }
            HStack { Spacer(); Button("Save settings") { model.saveSettings() }.buttonStyle(.borderedProminent) }
        }.formStyle(.grouped)
    }
}

private extension View {
    func cardStyle() -> some View { self.padding(20).background(.background).clipShape(RoundedRectangle(cornerRadius: 16)).shadow(color: .black.opacity(0.06), radius: 12, y: 5) }
}
