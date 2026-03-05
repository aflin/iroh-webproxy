import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate, ProxyManagerDelegate {
    private var statusItem: NSStatusItem!
    private let proxyManager = ProxyManager()
    private var preferencesWindow: PreferencesWindow?

    func applicationDidFinishLaunching(_ notification: Notification) {
        proxyManager.delegate = self
        setupStatusItem()
        rebuildMenu()

        // Restore previous running state (or start if login item)
        proxyManager.restoreIfNeeded()
    }

    func applicationWillTerminate(_ notification: Notification) {
        // Don't stop daemons on quit — they survive independently.
        // The running state is persisted so they'll be detected on next launch.
    }

    // MARK: - Status Item

    private func setupStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        updateIcon()
    }

    private func updateIcon() {
        guard let button = statusItem.button else { return }
        if proxyManager.isRunning {
            if #available(macOS 12.0, *) {
                let config = NSImage.SymbolConfiguration(paletteColors: [.systemGreen])
                let image = NSImage(
                    systemSymbolName: "globe",
                    accessibilityDescription: "iroh Web Proxy — Running"
                )?.withSymbolConfiguration(config)
                image?.isTemplate = false
                button.image = image
            } else if #available(macOS 11.0, *) {
                let image = NSImage(
                    systemSymbolName: "globe",
                    accessibilityDescription: "iroh Web Proxy — Running")
                button.image = image
                button.contentTintColor = .systemGreen
            } else {
                button.title = "iWP"
                button.contentTintColor = .systemGreen
            }
        } else {
            if #available(macOS 11.0, *) {
                let image = NSImage(
                    systemSymbolName: "globe",
                    accessibilityDescription: "iroh Web Proxy — Stopped")
                image?.isTemplate = true
                button.image = image
                button.contentTintColor = nil
            } else {
                button.title = "iWP"
                button.contentTintColor = nil
            }
        }
    }

    // MARK: - Menu

    func rebuildMenu() {
        let menu = NSMenu()

        // Status line
        let statusText: String
        if proxyManager.isRunning {
            switch Settings.shared.mode {
            case .client: statusText = "Status: Running (Client)"
            case .server: statusText = "Status: Running (Server)"
            case .both:   statusText = "Status: Running (Both)"
            }
        } else {
            statusText = "Status: Stopped"
        }
        let statusItem = NSMenuItem(title: statusText, action: nil, keyEquivalent: "")
        statusItem.isEnabled = false
        menu.addItem(statusItem)

        // Node ID (server mode — click to copy)
        if let nodeId = proxyManager.serverNodeId {
            let nodeItem = NSMenuItem(
                title: "Node ID: \(nodeId.prefix(16))...",
                action: #selector(copyNodeId),
                keyEquivalent: "")
            nodeItem.target = self
            nodeItem.toolTip = nodeId
            menu.addItem(nodeItem)
        }

        menu.addItem(.separator())

        // Start / Stop
        if proxyManager.isRunning {
            let stop = NSMenuItem(title: "Stop Proxy", action: #selector(stopProxy), keyEquivalent: "")
            stop.target = self
            menu.addItem(stop)
        } else {
            let start = NSMenuItem(title: "Start Proxy", action: #selector(startProxy), keyEquivalent: "")
            start.target = self
            menu.addItem(start)
        }

        menu.addItem(.separator())

        // Preferences
        let prefs = NSMenuItem(title: "Preferences...", action: #selector(showPreferences), keyEquivalent: ",")
        prefs.target = self
        menu.addItem(prefs)

        // Start at Login
        let loginItem = NSMenuItem(
            title: "Start at Login",
            action: #selector(toggleLoginItem),
            keyEquivalent: "")
        loginItem.target = self
        loginItem.state = LoginItemManager.shared.isEnabled ? .on : .off
        menu.addItem(loginItem)

        menu.addItem(.separator())

        let quit = NSMenuItem(title: "Quit", action: #selector(quitApp), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)

        self.statusItem.menu = menu
    }

    // MARK: - Actions

    @objc private func startProxy() {
        proxyManager.start()
    }

    @objc private func stopProxy() {
        proxyManager.stop()
    }

    @objc private func copyNodeId() {
        if let nodeId = proxyManager.serverNodeId {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(nodeId, forType: .string)
        }
    }

    @objc private func showPreferences() {
        if preferencesWindow == nil {
            preferencesWindow = PreferencesWindow(proxyManager: proxyManager)
        }
        preferencesWindow?.showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc private func toggleLoginItem() {
        let newState = !LoginItemManager.shared.isEnabled
        LoginItemManager.shared.setEnabled(newState)
        rebuildMenu()
    }

    @objc private func quitApp() {
        NSApp.terminate(nil)
    }

    // MARK: - ProxyManagerDelegate

    func proxyManagerDidUpdateState(_ manager: ProxyManager) {
        updateIcon()
        rebuildMenu()
    }
}
