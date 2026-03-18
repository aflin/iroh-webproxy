use crate::settings::Settings;
use std::io::BufRead;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub struct ProxyManager {
    pub client_pid: Option<u32>,
    pub server_pid: Option<u32>,
    pub server_node_id: Option<String>,
}

impl ProxyManager {
    pub fn new() -> Self {
        Self {
            client_pid: None,
            server_pid: None,
            server_node_id: None,
        }
    }

    pub fn is_running(&self) -> bool {
        self.client_pid.is_some() || self.server_pid.is_some()
    }

    /// Detect processes from previous tray session via PID files.
    pub fn detect_existing(&mut self, settings: &Settings) {
        let client_pid_path = Settings::app_data_dir().join("client.pid");
        if let Some(pid) = read_pid_file(&client_pid_path) {
            if is_process_alive(pid) {
                self.client_pid = Some(pid);
            } else {
                let _ = std::fs::remove_file(&client_pid_path);
            }
        }

        let server_pid_path = Settings::app_data_dir().join("server.pid");
        if let Some(pid) = read_pid_file(&server_pid_path) {
            if is_process_alive(pid) {
                self.server_pid = Some(pid);
                if !settings.saved_server_node_id.is_empty() {
                    self.server_node_id = Some(settings.saved_server_node_id.clone());
                }
            } else {
                let _ = std::fs::remove_file(&server_pid_path);
            }
        }
    }

    pub fn start(&mut self, settings: &Settings) -> Result<(), String> {
        // Ensure app data directory exists for PID files
        let dir = Settings::app_data_dir();
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create data dir: {}", e))?;

        let binary = settings.resolved_binary_path();
        let mode = &settings.mode;

        if mode == "client" || mode == "both" {
            self.start_process(&binary, &settings.client_arguments(), false)?;
        }
        if mode == "server" || mode == "both" {
            self.start_process(&binary, &settings.server_arguments(), true)?;
        }
        Ok(())
    }

    fn start_process(
        &mut self,
        binary: &PathBuf,
        args: &[String],
        is_server: bool,
    ) -> Result<(), String> {
        let (pid, node_id) = launch_process(binary, args)?;
        if is_server {
            self.server_pid = Some(pid);
            self.server_node_id = node_id;
        } else {
            self.client_pid = Some(pid);
        }
        Ok(())
    }

    pub fn stop_all(&mut self) {
        self.stop_client();
        self.stop_server();
    }

    pub fn stop_client(&mut self) {
        if let Some(pid) = self.client_pid.take() {
            terminate_process(pid);
            let pidfile = Settings::app_data_dir().join("client.pid");
            let _ = std::fs::remove_file(pidfile);
        }
    }

    pub fn stop_server(&mut self) {
        if let Some(pid) = self.server_pid.take() {
            terminate_process(pid);
            let pidfile = Settings::app_data_dir().join("server.pid");
            let _ = std::fs::remove_file(pidfile);
        }
        self.server_node_id = None;
    }

    /// Check if tracked processes are still alive. Returns true if state changed.
    pub fn check_alive(&mut self) -> bool {
        let mut changed = false;

        if let Some(pid) = self.client_pid {
            if !is_process_alive(pid) {
                self.client_pid = None;
                let pidfile = Settings::app_data_dir().join("client.pid");
                let _ = std::fs::remove_file(pidfile);
                changed = true;
            }
        }

        if let Some(pid) = self.server_pid {
            if !is_process_alive(pid) {
                self.server_pid = None;
                self.server_node_id = None;
                let pidfile = Settings::app_data_dir().join("server.pid");
                let _ = std::fs::remove_file(pidfile);
                changed = true;
            }
        }

        changed
    }
}

fn launch_process(binary: &PathBuf, args: &[String]) -> Result<(u32, Option<String>), String> {
    use std::os::windows::process::CommandExt;

    let mut child = Command::new(binary)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("Failed to launch {}: {}", binary.display(), e))?;

    let pid = child.id();

    // Read node ID from first line of stdout (with timeout)
    let node_id = if let Some(stdout) = child.stdout.take() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let reader = std::io::BufReader::new(stdout);
            let mut lines = reader.lines();
            if let Some(Ok(line)) = lines.next() {
                let _ = tx.send(line.trim().to_string());
            }
        });
        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(id) if !id.is_empty() => Some(id),
            _ => None,
        }
    } else {
        None
    };

    Ok((pid, node_id))
}

fn read_pid_file(path: &PathBuf) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn is_process_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, OpenProcess};

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const STILL_ACTIVE: u32 = 259;

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return false;
        }
        let mut exit_code: u32 = 0;
        let result = GetExitCodeProcess(handle, &mut exit_code);
        CloseHandle(handle);
        result != 0 && exit_code == STILL_ACTIVE
    }
}

fn terminate_process(pid: u32) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess};

    const PROCESS_TERMINATE: u32 = 0x0001;

    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if !handle.is_null() {
            TerminateProcess(handle, 1);
            CloseHandle(handle);
        }
    }
}
