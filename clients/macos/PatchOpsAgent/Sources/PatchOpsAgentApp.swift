import SwiftUI

@main
struct PatchOpsAgentApp: App {
    @StateObject private var model = AgentModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 940, minHeight: 620)
                .task {
                    if model.snapshot == nil { model.scan() }
                }
        }
        .windowStyle(.hiddenTitleBar)

        MenuBarExtra("PatchOps", systemImage: model.state == .failed ? "exclamationmark.shield" : "checkmark.shield") {
            Text(model.statusMessage)
            Divider()
            Button("Collect inventory") { model.scan() }
            Button("Sync now") { model.sync() }
            Button("Test notification") { Task { await model.notifications.sendUpdateNotification() } }
            Divider()
            Button("Open PatchOps") { NSApplication.shared.activate(ignoringOtherApps: true) }
            Button("Quit") { NSApplication.shared.terminate(nil) }
        }
    }
}
