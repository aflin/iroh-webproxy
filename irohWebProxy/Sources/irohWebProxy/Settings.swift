import Foundation

enum ProxyMode: String {
    case client
    case server
    case both
}

final class Settings {
    static let shared = Settings()

    private let defaults = UserDefaults.standard

    private enum Key: String {
        case mode
        case httpPort
        case httpsPort
        case selfSign
        case ipAddress
        case targetAddress
        case keyFilePath
        case targetTls
        case insecure
        case startAtLogin
        case binaryPath
        case proxyWasRunning
        case savedServerNodeId
    }

    private init() {
        defaults.register(defaults: [
            Key.mode.rawValue: ProxyMode.client.rawValue,
            Key.httpPort.rawValue: 8080,
            Key.httpsPort.rawValue: 8443,
            Key.selfSign.rawValue: true,
            Key.ipAddress.rawValue: "127.0.0.1",
            Key.targetAddress.rawValue: "127.0.0.1:8088",
            Key.keyFilePath.rawValue: "",
            Key.targetTls.rawValue: false,
            Key.insecure.rawValue: false,
            Key.startAtLogin.rawValue: false,
            Key.binaryPath.rawValue: "",
            Key.proxyWasRunning.rawValue: false,
            Key.savedServerNodeId.rawValue: "",
        ])
    }

    var mode: ProxyMode {
        get { ProxyMode(rawValue: defaults.string(forKey: Key.mode.rawValue) ?? "client") ?? .client }
        set { defaults.set(newValue.rawValue, forKey: Key.mode.rawValue) }
    }

    var httpPort: Int {
        get { defaults.integer(forKey: Key.httpPort.rawValue) }
        set { defaults.set(newValue, forKey: Key.httpPort.rawValue) }
    }

    var httpsPort: Int {
        get { defaults.integer(forKey: Key.httpsPort.rawValue) }
        set { defaults.set(newValue, forKey: Key.httpsPort.rawValue) }
    }

    var selfSign: Bool {
        get { defaults.bool(forKey: Key.selfSign.rawValue) }
        set { defaults.set(newValue, forKey: Key.selfSign.rawValue) }
    }

    var ipAddress: String {
        get { defaults.string(forKey: Key.ipAddress.rawValue) ?? "127.0.0.1" }
        set { defaults.set(newValue, forKey: Key.ipAddress.rawValue) }
    }

    var targetAddress: String {
        get { defaults.string(forKey: Key.targetAddress.rawValue) ?? "127.0.0.1:8088" }
        set { defaults.set(newValue, forKey: Key.targetAddress.rawValue) }
    }

    var keyFilePath: String {
        get { defaults.string(forKey: Key.keyFilePath.rawValue) ?? "" }
        set { defaults.set(newValue, forKey: Key.keyFilePath.rawValue) }
    }

    var targetTls: Bool {
        get { defaults.bool(forKey: Key.targetTls.rawValue) }
        set { defaults.set(newValue, forKey: Key.targetTls.rawValue) }
    }

    var insecure: Bool {
        get { defaults.bool(forKey: Key.insecure.rawValue) }
        set { defaults.set(newValue, forKey: Key.insecure.rawValue) }
    }

    var startAtLogin: Bool {
        get { defaults.bool(forKey: Key.startAtLogin.rawValue) }
        set { defaults.set(newValue, forKey: Key.startAtLogin.rawValue) }
    }

    var binaryPath: String {
        get { defaults.string(forKey: Key.binaryPath.rawValue) ?? "" }
        set { defaults.set(newValue, forKey: Key.binaryPath.rawValue) }
    }

    var proxyWasRunning: Bool {
        get { defaults.bool(forKey: Key.proxyWasRunning.rawValue) }
        set { defaults.set(newValue, forKey: Key.proxyWasRunning.rawValue) }
    }

    var savedServerNodeId: String {
        get { defaults.string(forKey: Key.savedServerNodeId.rawValue) ?? "" }
        set { defaults.set(newValue, forKey: Key.savedServerNodeId.rawValue) }
    }

    /// Whether current client settings require a privileged port (< 1024).
    var needsPrivilegedPort: Bool {
        let mode = self.mode
        if mode == .client || mode == .both {
            if httpPort < 1024 { return true }
            if selfSign && httpsPort < 1024 { return true }
        }
        return false
    }

    /// Resolved path to the iroh-webproxy binary.
    var resolvedBinaryPath: String {
        if !binaryPath.isEmpty {
            return binaryPath
        }
        if let bundled = Bundle.main.url(forResource: "iroh-webproxy", withExtension: nil) {
            return bundled.path
        }
        return "/usr/local/bin/iroh-webproxy"
    }

    /// Build command-line arguments for client mode.
    func clientArguments() -> [String] {
        var args = ["client"]
        args += ["--http-port", "\(httpPort)"]
        args += ["--ip-address", ipAddress]
        if selfSign {
            args += ["--self-sign"]
            args += ["--https-port", "\(httpsPort)"]
        }
        return args
    }

    /// Build command-line arguments for server mode.
    func serverArguments() -> [String] {
        var args = ["server"]
        args += ["--target", targetAddress]
        if targetTls {
            args += ["--tls"]
            if insecure {
                args += ["--insecure"]
            }
        }
        if !keyFilePath.isEmpty {
            args += ["--key-file", keyFilePath]
        }
        return args
    }
}
