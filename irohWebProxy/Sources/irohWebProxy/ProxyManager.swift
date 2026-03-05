import Foundation

protocol ProxyManagerDelegate: AnyObject {
    func proxyManagerDidUpdateState(_ manager: ProxyManager)
}

final class ProxyManager {
    weak var delegate: ProxyManagerDelegate?

    private(set) var clientRunning = false
    private(set) var serverRunning = false
    private(set) var serverNodeId: String?

    var isRunning: Bool { clientRunning || serverRunning }

    private let clientPidFile: String
    private let serverPidFile: String

    /// Whether the current daemons were started with elevated privileges.
    private var launchedPrivileged = false

    init() {
        let dir = ProxyManager.pidDirectory()
        clientPidFile = (dir as NSString).appendingPathComponent("client.pid")
        serverPidFile = (dir as NSString).appendingPathComponent("server.pid")

        // Detect already-running daemons from a previous app session
        clientRunning = ProxyManager.processAlive(pidFile: clientPidFile)
        serverRunning = ProxyManager.processAlive(pidFile: serverPidFile)

        // If a daemon is running but we can't signal it, it was likely started as root
        if clientRunning, let pid = ProxyManager.readPid(clientPidFile) {
            if kill(pid, 0) == 0 {
                // We can signal it — check if it's owned by root
                launchedPrivileged = processOwnedByRoot(pid)
            }
        }
        if serverRunning, let pid = ProxyManager.readPid(serverPidFile) {
            if kill(pid, 0) == 0 {
                launchedPrivileged = launchedPrivileged || processOwnedByRoot(pid)
            }
        }

        // Restore persisted server node ID if daemon is still alive
        if serverRunning {
            let saved = Settings.shared.savedServerNodeId
            if !saved.isEmpty {
                serverNodeId = saved
            }
        }
    }

    /// Restore proxy state from a previous session.
    /// Call after setting the delegate so it receives state updates.
    func restoreIfNeeded() {
        // If daemons are already alive (detected in init), just update state
        if isRunning {
            Settings.shared.proxyWasRunning = true
            delegate?.proxyManagerDidUpdateState(self)
            return
        }
        // If proxy was previously running but daemons died, restart
        if Settings.shared.proxyWasRunning {
            start()
        }
    }

    func start() {
        let mode = Settings.shared.mode
        let privileged = Settings.shared.needsPrivilegedPort

        if privileged {
            startPrivileged()
        } else {
            if mode == .client || mode == .both {
                startClient(sudo: false)
            }
            if mode == .server || mode == .both {
                startServer(sudo: false)
            }
        }
        Settings.shared.proxyWasRunning = true
    }

    func stop() {
        stopClient()
        stopServer()
        launchedPrivileged = false
        Settings.shared.proxyWasRunning = false
    }

    // MARK: - Privileged Launch

    /// Start daemons that need privileged ports.
    /// Tries sudo -n first (NOPASSWD), then falls back to AppleScript password dialog.
    private func startPrivileged() {
        let mode = Settings.shared.mode
        let binary = Settings.shared.resolvedBinaryPath

        // Build the full commands we need to run
        var commands: [String] = []
        if mode == .client || mode == .both {
            var args = Settings.shared.clientArguments()
            args += ["--daemon", "--pidfile", clientPidFile]
            let cmd = ([binary] + args).map { shellEscape($0) }.joined(separator: " ")
            commands.append(cmd)
        }
        if mode == .server || mode == .both {
            var args = Settings.shared.serverArguments()
            args += ["--daemon", "--pidfile", serverPidFile]
            let cmd = ([binary] + args).map { shellEscape($0) }.joined(separator: " ")
            commands.append(cmd)
        }

        let fullCommand = commands.joined(separator: " && ")

        // Try sudo -n first (non-interactive, succeeds if NOPASSWD)
        let (success, output) = runShell("sudo -n sh -c \(shellEscape(fullCommand))")
        if success {
            launchedPrivileged = true
            parsePrivilegedOutput(output, mode: mode)
            return
        }

        // Fall back to AppleScript password dialog with custom prompt
        let escaped = fullCommand.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let portList = privilegedPortDescription()
        let script = """
            set thePassword to text returned of (display dialog \
            "iroh Web Proxy needs administrator privileges to bind to \(portList).\\n\\nPlease enter your password." \
            default answer "" with hidden answer \
            buttons {"Cancel", "OK"} default button "OK" with icon caution)
            do shell script "\(escaped)" password thePassword with administrator privileges
            """
        var error: NSDictionary?
        let appleScript = NSAppleScript(source: script)
        let result = appleScript?.executeAndReturnError(&error)

        if let error = error {
            let errorNum = error[NSAppleScript.errorNumber] as? Int
            // -128 = user cancelled
            if errorNum != -128 {
                NSLog("Privileged launch failed: \(error)")
            }
            return
        }

        launchedPrivileged = true
        let output2 = result?.stringValue ?? ""
        parsePrivilegedOutput(output2, mode: mode)
    }

    /// Parse stdout from privileged launch (may contain node IDs).
    private func parsePrivilegedOutput(_ output: String, mode: ProxyMode) {
        let lines = output.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }

        if mode == .client || mode == .both {
            clientRunning = true
        }
        if mode == .server || mode == .both {
            serverRunning = true
            // The last line of output should be the server node ID
            // (client prints first if both are started)
            if let nodeId = lines.last, !nodeId.isEmpty {
                serverNodeId = String(nodeId)
                Settings.shared.savedServerNodeId = String(nodeId)
            }
        }
        delegate?.proxyManagerDidUpdateState(self)

        // Poll to confirm daemons are alive
        if clientRunning {
            pollForPid(pidFile: clientPidFile) { [weak self] alive in
                guard let self = self else { return }
                if !alive { self.clientRunning = false }
                self.delegate?.proxyManagerDidUpdateState(self)
            }
        }
        if serverRunning {
            pollForPid(pidFile: serverPidFile) { [weak self] alive in
                guard let self = self else { return }
                if !alive {
                    self.serverRunning = false
                    self.serverNodeId = nil
                    Settings.shared.savedServerNodeId = ""
                }
                self.delegate?.proxyManagerDidUpdateState(self)
            }
        }
    }

    // MARK: - Client

    private func startClient(sudo: Bool) {
        guard !clientRunning else { return }
        var args = Settings.shared.clientArguments()
        args += ["--daemon", "--pidfile", clientPidFile]

        guard let nodeId = launchAndCaptureNodeId(arguments: args) else { return }
        _ = nodeId
        clientRunning = true
        delegate?.proxyManagerDidUpdateState(self)

        pollForPid(pidFile: clientPidFile) { [weak self] alive in
            guard let self = self else { return }
            if !alive { self.clientRunning = false }
            self.delegate?.proxyManagerDidUpdateState(self)
        }
    }

    private func stopClient() {
        killFromPidFile(clientPidFile)
        clientRunning = false
        delegate?.proxyManagerDidUpdateState(self)
    }

    // MARK: - Server

    private func startServer(sudo: Bool) {
        guard !serverRunning else { return }
        var args = Settings.shared.serverArguments()
        args += ["--daemon", "--pidfile", serverPidFile]

        guard let nodeId = launchAndCaptureNodeId(arguments: args) else { return }
        serverNodeId = nodeId
        Settings.shared.savedServerNodeId = nodeId
        serverRunning = true
        delegate?.proxyManagerDidUpdateState(self)

        pollForPid(pidFile: serverPidFile) { [weak self] alive in
            guard let self = self else { return }
            if !alive {
                self.serverRunning = false
                self.serverNodeId = nil
                Settings.shared.savedServerNodeId = ""
            }
            self.delegate?.proxyManagerDidUpdateState(self)
        }
    }

    private func stopServer() {
        killFromPidFile(serverPidFile)
        serverRunning = false
        serverNodeId = nil
        Settings.shared.savedServerNodeId = ""
        delegate?.proxyManagerDidUpdateState(self)
    }

    // MARK: - Process Helpers

    /// Launch the binary directly (non-privileged), capture stdout.
    private func launchAndCaptureNodeId(arguments: [String]) -> String? {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: Settings.shared.resolvedBinaryPath)
        proc.arguments = arguments
        proc.standardError = FileHandle.nullDevice

        let pipe = Pipe()
        proc.standardOutput = pipe

        do {
            try proc.run()
        } catch {
            NSLog("Failed to launch iroh-webproxy: \(error)")
            return nil
        }

        proc.waitUntilExit()

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return output.isEmpty ? nil : output
    }

    /// Send SIGTERM to the PID in a pidfile. Uses sudo kill if the process
    /// was started with elevated privileges.
    private func killFromPidFile(_ path: String) {
        guard let pid = ProxyManager.readPid(path) else { return }

        if launchedPrivileged && processOwnedByRoot(pid) {
            // Try sudo -n first, then AppleScript
            let (success, _) = runShell("sudo -n kill \(pid)")
            if !success {
                let script = """
                    set thePassword to text returned of (display dialog \
                    "iroh Web Proxy needs administrator privileges to stop the proxy running on a privileged port.\\n\\nPlease enter your password." \
                    default answer "" with hidden answer \
                    buttons {"Cancel", "OK"} default button "OK" with icon caution)
                    do shell script "kill \(pid)" password thePassword with administrator privileges
                    """
                var error: NSDictionary?
                let appleScript = NSAppleScript(source: script)
                appleScript?.executeAndReturnError(&error)
                if let error = error {
                    let errorNum = error[NSAppleScript.errorNumber] as? Int
                    if errorNum != -128 {
                        NSLog("Privileged kill failed: \(error)")
                    }
                }
            }
        } else {
            kill(pid, SIGTERM)
        }
        try? FileManager.default.removeItem(atPath: path)
    }

    /// Read PID from a pidfile.
    static func readPid(_ path: String) -> pid_t? {
        guard let contents = try? String(contentsOfFile: path, encoding: .utf8) else {
            return nil
        }
        return pid_t(contents.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// Check if the PID in a pidfile corresponds to a live process.
    private static func processAlive(pidFile: String) -> Bool {
        guard let pid = readPid(pidFile) else { return false }
        if kill(pid, 0) == 0 { return true }
        // EPERM means the process exists but is owned by another user (root)
        return errno == EPERM
    }

    /// Poll for the daemon pidfile to appear and confirm the process is alive.
    private func pollForPid(pidFile: String, completion: @escaping (Bool) -> Void) {
        DispatchQueue.global(qos: .utility).async {
            var alive = false
            for _ in 0..<10 {
                if ProxyManager.processAlive(pidFile: pidFile) {
                    alive = true
                    break
                }
                Thread.sleep(forTimeInterval: 0.2)
            }
            DispatchQueue.main.async {
                completion(alive)
            }
        }
    }

    /// Directory for pidfiles, inside Application Support.
    private static func pidDirectory() -> String {
        let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first!.appendingPathComponent("irohWebProxy").path

        if !FileManager.default.fileExists(atPath: appSupport) {
            try? FileManager.default.createDirectory(
                atPath: appSupport, withIntermediateDirectories: true)
        }
        return appSupport
    }

    /// Describe which configured ports are privileged, for the password dialog.
    private func privilegedPortDescription() -> String {
        var ports: [String] = []
        let s = Settings.shared
        if (s.mode == .client || s.mode == .both) {
            if s.httpPort < 1024 { ports.append("port \(s.httpPort) (HTTP)") }
            if s.selfSign && s.httpsPort < 1024 { ports.append("port \(s.httpsPort) (HTTPS)") }
        }
        if ports.isEmpty { return "a privileged port" }
        return ports.joined(separator: " and ")
    }

    // MARK: - Shell Helpers

    /// Run a shell command, return (success, stdout).
    private func runShell(_ command: String) -> (Bool, String) {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/sh")
        proc.arguments = ["-c", command]
        proc.standardError = FileHandle.nullDevice

        let pipe = Pipe()
        proc.standardOutput = pipe

        do {
            try proc.run()
        } catch {
            return (false, "")
        }

        proc.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return (proc.terminationStatus == 0, output)
    }

    /// Shell-escape a string for use in sh -c.
    private func shellEscape(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// Check if a process is owned by root (uid 0).
    private func processOwnedByRoot(_ pid: pid_t) -> Bool {
        let (success, output) = runShell("ps -o uid= -p \(pid)")
        guard success else { return false }
        return output.trimmingCharacters(in: .whitespaces) == "0"
    }
}
