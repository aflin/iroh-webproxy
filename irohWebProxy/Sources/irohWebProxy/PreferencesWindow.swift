import AppKit

final class PreferencesWindow: NSWindowController {
    private let settings = Settings.shared
    private weak var proxyManager: ProxyManager?

    // Controls
    private var modePopup: NSPopUpButton!
    private var httpPortField: NSTextField!
    private var httpsPortField: NSTextField!
    private var selfSignCheck: NSButton!
    private var ipAddressField: NSTextField!
    private var hostSuffixField: NSTextField!
    private var targetAddressField: NSTextField!
    private var keyFileField: NSTextField!
    private var targetTlsCheck: NSButton!
    private var insecureCheck: NSButton!
    private var binaryPathField: NSTextField!

    // Section containers
    private var clientSection: NSStackView!
    private var serverSection: NSStackView!

    init(proxyManager: ProxyManager) {
        self.proxyManager = proxyManager
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 420, height: 450),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false)
        window.title = "Iroh Proxy Preferences"
        window.center()
        window.isReleasedWhenClosed = false
        super.init(window: window)
        setupUI()
        loadSettings()
    }

    required init?(coder: NSCoder) { fatalError() }

    // MARK: - UI Setup

    private func setupUI() {
        guard let contentView = window?.contentView else { return }
        contentView.wantsLayer = true

        let root = NSStackView()
        root.orientation = .vertical
        root.alignment = .leading
        root.spacing = 12
        root.edgeInsets = NSEdgeInsets(top: 16, left: 20, bottom: 16, right: 20)
        root.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(root)
        NSLayoutConstraint.activate([
            root.topAnchor.constraint(equalTo: contentView.topAnchor),
            root.leadingAnchor.constraint(equalTo: contentView.leadingAnchor),
            root.trailingAnchor.constraint(equalTo: contentView.trailingAnchor),
        ])

        // Mode
        root.addArrangedSubview(makeLabel("Mode"))
        modePopup = NSPopUpButton(frame: .zero, pullsDown: false)
        modePopup.addItems(withTitles: ["Client", "Server", "Both"])
        modePopup.target = self
        modePopup.action = #selector(modeChanged)
        root.addArrangedSubview(modePopup)

        // Client section
        root.addArrangedSubview(makeSectionLabel("Client Settings"))
        clientSection = NSStackView()
        clientSection.orientation = .vertical
        clientSection.alignment = .leading
        clientSection.spacing = 8

        httpPortField = makeTextField(width: 80)
        clientSection.addArrangedSubview(makeRow("HTTP Port:", httpPortField))

        httpsPortField = makeTextField(width: 80)
        clientSection.addArrangedSubview(makeRow("HTTPS Port:", httpsPortField))

        selfSignCheck = NSButton(checkboxWithTitle: "Self-signed HTTPS", target: nil, action: nil)
        clientSection.addArrangedSubview(selfSignCheck)

        ipAddressField = makeTextField(width: 160)
        clientSection.addArrangedSubview(makeRow("Bind Address:", ipAddressField))

        hostSuffixField = makeTextField(width: 200)
        hostSuffixField.placeholderString = "localhost"
        clientSection.addArrangedSubview(makeRow("Host Suffix:", hostSuffixField))

        root.addArrangedSubview(clientSection)

        // Server section
        root.addArrangedSubview(makeSectionLabel("Server Settings"))
        serverSection = NSStackView()
        serverSection.orientation = .vertical
        serverSection.alignment = .leading
        serverSection.spacing = 8

        targetAddressField = makeTextField(width: 200)
        serverSection.addArrangedSubview(makeRow("Target Address:", targetAddressField))

        targetTlsCheck = NSButton(checkboxWithTitle: "Connect to secure server (HTTPS)", target: self, action: #selector(tlsChanged))
        serverSection.addArrangedSubview(targetTlsCheck)

        insecureCheck = NSButton(checkboxWithTitle: "Skip TLS certificate verification", target: nil, action: nil)
        serverSection.addArrangedSubview(insecureCheck)

        keyFileField = makeTextField(width: 200)
        let keyRow = makeRow("Key File:", keyFileField)
        let browseBtn = NSButton(title: "Browse...", target: self, action: #selector(browseKeyFile))
        browseBtn.bezelStyle = .rounded
        keyRow.addArrangedSubview(browseBtn)
        serverSection.addArrangedSubview(keyRow)

        root.addArrangedSubview(serverSection)

        // Advanced
        root.addArrangedSubview(makeSectionLabel("Advanced"))

        binaryPathField = makeTextField(width: 200)
        binaryPathField.placeholderString = "Bundled (default)"
        let binRow = makeRow("Binary Path:", binaryPathField)
        let binBrowse = NSButton(title: "Browse...", target: self, action: #selector(browseBinary))
        binBrowse.bezelStyle = .rounded
        binRow.addArrangedSubview(binBrowse)
        root.addArrangedSubview(binRow)

        // Buttons
        root.addArrangedSubview(NSBox.separator())

        let buttonRow = NSStackView()
        buttonRow.orientation = .horizontal
        buttonRow.spacing = 8
        let saveBtn = NSButton(title: "Save", target: self, action: #selector(saveSettings))
        saveBtn.bezelStyle = .rounded
        saveBtn.keyEquivalent = "\r"
        let cancelBtn = NSButton(title: "Cancel", target: self, action: #selector(cancelSettings))
        cancelBtn.bezelStyle = .rounded
        cancelBtn.keyEquivalent = "\u{1b}"
        buttonRow.addArrangedSubview(cancelBtn)
        buttonRow.addArrangedSubview(saveBtn)
        root.addArrangedSubview(buttonRow)
    }

    // MARK: - Load / Save

    private func loadSettings() {
        switch settings.mode {
        case .client: modePopup.selectItem(at: 0)
        case .server: modePopup.selectItem(at: 1)
        case .both:   modePopup.selectItem(at: 2)
        }
        httpPortField.stringValue = "\(settings.httpPort)"
        httpsPortField.stringValue = "\(settings.httpsPort)"
        selfSignCheck.state = settings.selfSign ? .on : .off
        ipAddressField.stringValue = settings.ipAddress
        hostSuffixField.stringValue = settings.hostSuffix
        targetAddressField.stringValue = settings.targetAddress
        targetTlsCheck.state = settings.targetTls ? .on : .off
        insecureCheck.state = settings.insecure ? .on : .off
        insecureCheck.isEnabled = settings.targetTls
        keyFileField.stringValue = settings.keyFilePath
        binaryPathField.stringValue = settings.binaryPath

        updateSectionVisibility()
    }

    @objc private func saveSettings() {
        let modes: [ProxyMode] = [.client, .server, .both]
        settings.mode = modes[modePopup.indexOfSelectedItem]
        settings.httpPort = Int(httpPortField.stringValue) ?? 8080
        settings.httpsPort = Int(httpsPortField.stringValue) ?? 8443
        settings.selfSign = selfSignCheck.state == .on
        settings.ipAddress = ipAddressField.stringValue
        settings.hostSuffix = hostSuffixField.stringValue.isEmpty ? "localhost" : hostSuffixField.stringValue
        settings.targetAddress = targetAddressField.stringValue
        settings.targetTls = targetTlsCheck.state == .on
        settings.insecure = insecureCheck.state == .on
        settings.keyFilePath = keyFileField.stringValue
        settings.binaryPath = binaryPathField.stringValue

        // Restart proxy if it was running
        if let pm = proxyManager, pm.isRunning {
            pm.stop()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                pm.start()
            }
        }
        window?.close()
    }

    @objc private func cancelSettings() {
        window?.close()
    }

    @objc private func modeChanged() {
        updateSectionVisibility()
    }

    @objc private func tlsChanged() {
        let tlsOn = targetTlsCheck.state == .on
        insecureCheck.isEnabled = tlsOn
        if !tlsOn {
            insecureCheck.state = .off
        }
    }

    private func updateSectionVisibility() {
        let idx = modePopup.indexOfSelectedItem
        clientSection.isHidden = (idx == 1) // hidden when server-only
        serverSection.isHidden = (idx == 0) // hidden when client-only
    }

    // MARK: - File Browsers

    @objc private func browseKeyFile() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url {
            keyFileField.stringValue = url.path
        }
    }

    @objc private func browseBinary() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url {
            binaryPathField.stringValue = url.path
        }
    }

    // MARK: - UI Helpers

    private func makeLabel(_ text: String) -> NSTextField {
        let label = NSTextField(labelWithString: text)
        label.font = .systemFont(ofSize: 13, weight: .medium)
        return label
    }

    private func makeSectionLabel(_ text: String) -> NSTextField {
        let label = NSTextField(labelWithString: text)
        label.font = .systemFont(ofSize: 12, weight: .bold)
        label.textColor = .secondaryLabelColor
        return label
    }

    private func makeTextField(width: CGFloat) -> NSTextField {
        let field = NSTextField()
        field.widthAnchor.constraint(equalToConstant: width).isActive = true
        field.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        return field
    }

    private func makeRow(_ label: String, _ control: NSView) -> NSStackView {
        let row = NSStackView()
        row.orientation = .horizontal
        row.spacing = 8
        let l = NSTextField(labelWithString: label)
        l.font = .systemFont(ofSize: 12)
        l.widthAnchor.constraint(equalToConstant: 100).isActive = true
        l.alignment = .right
        row.addArrangedSubview(l)
        row.addArrangedSubview(control)
        return row
    }

}

private extension NSBox {
    static func separator() -> NSBox {
        let box = NSBox()
        box.boxType = .separator
        return box
    }
}
