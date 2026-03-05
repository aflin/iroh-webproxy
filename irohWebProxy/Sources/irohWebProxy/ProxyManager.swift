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

    init() {
        let dir = ProxyManager.pidDirectory()
        clientPidFile = (dir as NSString).appendingPathComponent("client.pid")
        serverPidFile = (dir as NSString).appendingPathComponent("server.pid")

        // Detect already-running daemons from a previous app session
        clientRunning = ProxyManager.processAlive(pidFile: clientPidFile)
        serverRunning = ProxyManager.processAlive(pidFile: serverPidFile)

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
        if mode == .client || mode == .both {
            startClient()
        }
        if mode == .server || mode == .both {
            startServer()
        }
        Settings.shared.proxyWasRunning = true
    }

    func stop() {
        stopClient()
        stopServer()
        Settings.shared.proxyWasRunning = false
    }

    // MARK: - Client

    private func startClient() {
        guard !clientRunning else { return }
        var args = Settings.shared.clientArguments()
        args += ["--daemon", "--pidfile", clientPidFile]

        guard let nodeId = launchAndCaptureNodeId(arguments: args) else { return }
        _ = nodeId // client node ID not displayed, but captured
        clientRunning = true
        delegate?.proxyManagerDidUpdateState(self)

        // Poll briefly for the pidfile to confirm the daemon is up
        pollForPid(pidFile: clientPidFile) { [weak self] alive in
            guard let self = self else { return }
            if !alive {
                self.clientRunning = false
            }
            self.delegate?.proxyManagerDidUpdateState(self)
        }
    }

    private func stopClient() {
        killFromPidFile(clientPidFile)
        clientRunning = false
        delegate?.proxyManagerDidUpdateState(self)
    }

    // MARK: - Server

    private func startServer() {
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

    /// Launch the binary, capture its stdout (node ID), then it daemonizes and the
    /// Process exits. Returns the node ID string, or nil on failure.
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

        // The binary prints the node ID then daemonizes (parent exits quickly)
        proc.waitUntilExit()

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return output.isEmpty ? nil : output
    }

    /// Send SIGTERM to the PID recorded in a pidfile, then remove it.
    private func killFromPidFile(_ path: String) {
        guard let pid = ProxyManager.readPid(path) else { return }
        kill(pid, SIGTERM)
        try? FileManager.default.removeItem(atPath: path)
    }

    /// Read PID from a pidfile.
    private static func readPid(_ path: String) -> pid_t? {
        guard let contents = try? String(contentsOfFile: path, encoding: .utf8) else {
            return nil
        }
        return pid_t(contents.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    /// Check if the PID in a pidfile corresponds to a live process.
    private static func processAlive(pidFile: String) -> Bool {
        guard let pid = readPid(pidFile) else { return false }
        // kill with signal 0 checks existence without sending a signal
        return kill(pid, 0) == 0
    }

    /// Poll briefly for the daemon pidfile to appear and confirm the process is alive.
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
}
