import AppKit
import SwiftUI

@MainActor
final class PatchOpsAgentDelegate: NSObject, NSApplicationDelegate {
    let model = AgentModel()

    func applicationDidFinishLaunching(_ notification: Notification) {
        model.startManagedOperation()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
}

@main
struct PatchOpsAgentApp: App {
    @NSApplicationDelegateAdaptor(PatchOpsAgentDelegate.self) private var delegate

    var body: some Scene {
        Settings {
            EmptyView()
        }
    }
}
