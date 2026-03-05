import Foundation
import ServiceManagement

final class LoginItemManager {
    static let shared = LoginItemManager()
    private let launchAgentLabel = "com.iroh.webproxy"

    private init() {}

    var isEnabled: Bool {
        get {
            if #available(macOS 13.0, *) {
                return SMAppService.mainApp.status == .enabled
            } else {
                return launchAgentExists()
            }
        }
    }

    func setEnabled(_ enabled: Bool) {
        if #available(macOS 13.0, *) {
            do {
                if enabled {
                    try SMAppService.mainApp.register()
                } else {
                    try SMAppService.mainApp.unregister()
                }
            } catch {
                NSLog("Login item error: \(error)")
            }
        } else {
            if enabled {
                installLaunchAgent()
            } else {
                removeLaunchAgent()
            }
        }
        Settings.shared.startAtLogin = enabled
    }

    // MARK: - LaunchAgent fallback (macOS 11-12)

    private var launchAgentURL: URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return home.appendingPathComponent("Library/LaunchAgents/\(launchAgentLabel).plist")
    }

    private func launchAgentExists() -> Bool {
        FileManager.default.fileExists(atPath: launchAgentURL.path)
    }

    private func installLaunchAgent() {
        guard let appPath = Bundle.main.bundleURL.path as String? else { return }
        let plist: [String: Any] = [
            "Label": launchAgentLabel,
            "ProgramArguments": ["\(appPath)/Contents/MacOS/irohWebProxy"],
            "RunAtLoad": true,
            "KeepAlive": false,
        ]
        let data = try? PropertyListSerialization.data(
            fromPropertyList: plist, format: .xml, options: 0)
        if let data = data {
            try? data.write(to: launchAgentURL)
        }
    }

    private func removeLaunchAgent() {
        try? FileManager.default.removeItem(at: launchAgentURL)
    }
}
