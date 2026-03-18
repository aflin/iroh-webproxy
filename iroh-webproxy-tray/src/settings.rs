use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_http_port")]
    pub http_port: u16,
    #[serde(default = "default_https_port")]
    pub https_port: u16,
    #[serde(default = "default_true")]
    pub self_sign: bool,
    #[serde(default = "default_ip")]
    pub ip_address: String,
    #[serde(default = "default_host_suffix")]
    pub host_suffix: String,
    #[serde(default = "default_target_host")]
    pub target_host: String,
    #[serde(default = "default_target_port")]
    pub target_port: u16,
    #[serde(default)]
    pub target_tls: bool,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub key_file_path: String,
    #[serde(default)]
    pub binary_path: String,
    #[serde(default)]
    pub proxy_was_running: bool,
    #[serde(default)]
    pub saved_server_node_id: String,
}

fn default_mode() -> String {
    "client".into()
}
fn default_http_port() -> u16 {
    8080
}
fn default_https_port() -> u16 {
    8443
}
fn default_true() -> bool {
    true
}
fn default_ip() -> String {
    "127.0.0.1".into()
}
fn default_host_suffix() -> String {
    "localhost".into()
}
fn default_target_host() -> String {
    "127.0.0.1".into()
}
fn default_target_port() -> u16 {
    8088
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            http_port: default_http_port(),
            https_port: default_https_port(),
            self_sign: default_true(),
            ip_address: default_ip(),
            host_suffix: default_host_suffix(),
            target_host: default_target_host(),
            target_port: default_target_port(),
            target_tls: false,
            insecure: false,
            key_file_path: String::new(),
            binary_path: String::new(),
            proxy_was_running: false,
            saved_server_node_id: String::new(),
        }
    }
}

impl Settings {
    pub fn app_data_dir() -> PathBuf {
        let appdata = std::env::var("APPDATA").unwrap_or_else(|_| ".".into());
        PathBuf::from(appdata).join("irohWebProxy")
    }

    pub fn settings_path() -> PathBuf {
        Self::app_data_dir().join("settings.json")
    }

    pub fn load() -> Self {
        let path = Self::settings_path();
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(settings) = serde_json::from_str(&content) {
                    return settings;
                }
            }
        }
        Settings::default()
    }

    pub fn save(&self) {
        let dir = Self::app_data_dir();
        let _ = std::fs::create_dir_all(&dir);
        let path = Self::settings_path();
        if let Ok(content) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(&path, content);
        }
    }

    pub fn resolved_binary_path(&self) -> PathBuf {
        if !self.binary_path.is_empty() {
            return PathBuf::from(&self.binary_path);
        }
        // Check same directory as tray exe
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let candidate = dir.join("iroh-webproxy.exe");
                if candidate.exists() {
                    return candidate;
                }
            }
        }
        // Fall back to PATH lookup
        PathBuf::from("iroh-webproxy.exe")
    }

    pub fn client_arguments(&self) -> Vec<String> {
        let mut args = vec![
            "client".into(),
            "--http-port".into(),
            self.http_port.to_string(),
            "--https-port".into(),
            self.https_port.to_string(),
            "--ip-address".into(),
            self.ip_address.clone(),
            "--host-suffix".into(),
            self.host_suffix.clone(),
            "--log-level".into(),
            "none".into(),
        ];
        if self.self_sign {
            args.push("--self-sign".into());
        }
        let pidfile = Self::app_data_dir().join("client.pid");
        args.push("--pidfile".into());
        args.push(pidfile.to_string_lossy().into_owned());
        args
    }

    pub fn server_arguments(&self) -> Vec<String> {
        let mut args = vec![
            "server".into(),
            "--target".into(),
            format!("{}:{}", self.target_host, self.target_port),
            "--log-level".into(),
            "none".into(),
        ];
        if self.target_tls {
            args.push("--tls".into());
        }
        if self.insecure {
            args.push("--insecure".into());
        }
        if !self.key_file_path.is_empty() {
            args.push("--key-file".into());
            args.push(self.key_file_path.clone());
        }
        let pidfile = Self::app_data_dir().join("server.pid");
        args.push("--pidfile".into());
        args.push(pidfile.to_string_lossy().into_owned());
        args
    }
}
