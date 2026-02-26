mod client;
mod server;
mod tls;
mod transport;

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use iroh::Endpoint;

use transport::ALPN;

#[derive(Clone, ValueEnum)]
enum LogLevel {
    Info,
    Warn,
    Error,
    None,
}

#[derive(Parser)]
#[command(name = "iroh-webproxy", about = "HTTP proxy over iroh QUIC tunnels")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run as client proxy: accept local HTTP/HTTPS, tunnel over iroh.
    ///
    /// Listens for HTTP requests and tunnels them to an iroh-webproxy server
    /// identified by its node ID. Two URL formats are supported:
    ///
    ///   Subdomain:  http://<nodeId>.localhost:8080/path  (browsers)
    ///
    /// The subdomain format preserves absolute paths in HTML pages.
    /// HTTPS is enabled by providing one of --self-sign, --letsencrypt,
    /// or --tls-cert/--tls-key.
    ///
    /// The node ID is printed to stdout on startup.
    Client {
        /// HTTP listen port
        #[arg(long, default_value = "8080")]
        http_port: u16,

        /// HTTPS listen port (only used when TLS is enabled)
        #[arg(long, default_value = "8443")]
        https_port: u16,

        /// Generate a self-signed TLS certificate for HTTPS
        #[arg(long)]
        self_sign: bool,

        /// Load TLS certs from /etc/letsencrypt/live/<DOMAIN>/
        #[arg(long, value_name = "DOMAIN")]
        letsencrypt: Option<String>,

        /// Path to TLS certificate PEM file (requires --tls-key)
        #[arg(long, value_name = "PATH")]
        tls_cert: Option<String>,

        /// Path to TLS private key PEM file (requires --tls-cert)
        #[arg(long, value_name = "PATH")]
        tls_key: Option<String>,

        /// Listen on all interfaces (0.0.0.0 and ::)
        #[arg(long)]
        bind_all: bool,

        /// IPv4 bind address
        #[arg(long, default_value = "127.0.0.1")]
        ip_address: Ipv4Addr,

        /// IPv6 bind address
        #[arg(long, default_value = "::1")]
        ipv6_address: Ipv6Addr,

        /// Secret key (hex string or path to key file)
        #[arg(short = 'k', long)]
        secret_key: Option<String>,

        /// Log verbosity [default: warn]
        #[arg(long, value_enum)]
        log_level: Option<LogLevel>,

        /// Detach from terminal and run in the background (implies --log-level none)
        #[arg(long)]
        daemon: bool,
    },

    /// Run as server proxy: accept iroh connections, forward to local HTTP.
    ///
    /// Accepts connections from iroh-webproxy clients and forwards HTTP
    /// requests to a local web server.
    ///
    /// The node ID is printed to stdout on startup. Clients use this
    /// node ID to connect.
    ///
    /// By default the server saves its secret key to .iroh-webproxy-secret-key
    /// in the current directory and reloads it on subsequent runs so the
    /// node ID stays stable across restarts.
    Server {
        /// Local web server address to forward requests to
        #[arg(short, long, default_value = "127.0.0.1:8088")]
        target: SocketAddr,

        /// Secret key as a hex string, overrides any key file
        #[arg(short = 'k', long)]
        secret_key: Option<String>,

        /// Path to the secret key file [default: .iroh-webproxy-secret-key]
        #[arg(long, value_name = "PATH")]
        key_file: Option<String>,

        /// Do not write the secret key to disk
        #[arg(long)]
        no_key_save: bool,

        /// Do not auto-load .iroh-webproxy-secret-key on startup
        #[arg(long)]
        no_key_load: bool,

        /// Log verbosity [default: warn]
        #[arg(long, value_enum)]
        log_level: Option<LogLevel>,

        /// Detach from terminal and run in the background (implies --log-level none)
        #[arg(long)]
        daemon: bool,
    },
}

/// All pre-fork work happens here (parse CLI, load keys, print node ID,
/// daemonize). Then we start the tokio runtime for async work.
fn main() -> Result<()> {
    // Install rustls crypto provider before any TLS operations
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();

    match cli.command {
        Command::Client {
            http_port,
            https_port,
            self_sign,
            letsencrypt,
            tls_cert,
            tls_key,
            bind_all,
            ip_address,
            ipv6_address,
            secret_key,
            log_level,
            daemon,
        } => {
            let sk = transport::load_secret_key(secret_key.as_deref())?;
            println!("{}", sk.public());
            std::io::stdout().flush()?;

            if daemon {
                daemonize()?;
            }

            init_tracing(resolve_log_level(log_level, daemon));

            // Validate TLS options
            let tls_count = self_sign as u8
                + letsencrypt.is_some() as u8
                + (tls_cert.is_some() || tls_key.is_some()) as u8;
            if tls_count > 1 {
                bail!("specify at most one of --self-sign, --letsencrypt, or --tls-cert/--tls-key");
            }
            if tls_cert.is_some() != tls_key.is_some() {
                bail!("--tls-cert and --tls-key must be specified together");
            }

            let tls_mode = if self_sign {
                Some(tls::TlsMode::SelfSigned)
            } else if let Some(domain) = letsencrypt {
                Some(tls::TlsMode::LetsEncrypt(domain))
            } else if let (Some(cert), Some(key)) = (tls_cert, tls_key) {
                Some(tls::TlsMode::Manual { cert, key })
            } else {
                None
            };

            let tls_config = match &tls_mode {
                Some(mode) => Some(tls::build_tls_config(mode)?),
                None => None,
            };

            let (ipv4, ipv6): (IpAddr, IpAddr) = if bind_all {
                (
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                )
            } else {
                (IpAddr::V4(ip_address), IpAddr::V6(ipv6_address))
            };

            let http_addrs = vec![
                SocketAddr::new(ipv4, http_port),
                SocketAddr::new(ipv6, http_port),
            ];

            let https_addrs = vec![
                SocketAddr::new(ipv4, https_port),
                SocketAddr::new(ipv6, https_port),
            ];

            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(async {
                    let endpoint = Endpoint::builder().secret_key(sk).bind().await?;
                    client::run(endpoint, http_addrs, https_addrs, tls_config).await
                })?;
        }

        Command::Server {
            target,
            secret_key,
            key_file,
            no_key_save,
            no_key_load,
            log_level,
            daemon,
        } => {
            let key_path = key_file
                .as_deref()
                .unwrap_or(transport::DEFAULT_KEY_FILE);

            let sk = if let Some(ref key_arg) = secret_key {
                transport::load_secret_key(Some(key_arg))?
            } else if !no_key_load && std::path::Path::new(key_path).exists() {
                transport::load_secret_key_file(key_path)?
            } else {
                iroh::SecretKey::generate(&mut rand::rng())
            };

            if !no_key_save {
                transport::save_secret_key(&sk, key_path)?;
            }

            println!("{}", sk.public());
            std::io::stdout().flush()?;

            if daemon {
                daemonize()?;
            }

            init_tracing(resolve_log_level(log_level, daemon));

            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(async {
                    let endpoint = Endpoint::builder()
                        .secret_key(sk)
                        .alpns(vec![ALPN.to_vec()])
                        .bind()
                        .await?;
                    server::run(endpoint, target).await
                })?;
        }
    }

    Ok(())
}

/// Double-fork to detach from terminal and become a proper daemon.
#[cfg(unix)]
fn daemonize() -> Result<()> {
    unsafe {
        // First fork — parent exits, child continues
        match libc::fork() {
            -1 => bail!("fork failed: {}", std::io::Error::last_os_error()),
            0 => {}
            _ => std::process::exit(0),
        }

        // New session — detach from controlling terminal
        if libc::setsid() == -1 {
            bail!("setsid failed: {}", std::io::Error::last_os_error());
        }

        // Second fork — prevent reacquiring a controlling terminal
        match libc::fork() {
            -1 => bail!("fork failed: {}", std::io::Error::last_os_error()),
            0 => {}
            _ => std::process::exit(0),
        }

        // Redirect stdin/stdout/stderr to /dev/null
        let devnull = libc::open(b"/dev/null\0".as_ptr() as *const _, libc::O_RDWR);
        if devnull >= 0 {
            libc::dup2(devnull, libc::STDIN_FILENO);
            libc::dup2(devnull, libc::STDOUT_FILENO);
            libc::dup2(devnull, libc::STDERR_FILENO);
            if devnull > 2 {
                libc::close(devnull);
            }
        }
    }
    Ok(())
}

/// Re-launch as a detached process without --daemon, then exit the parent.
#[cfg(windows)]
fn daemonize() -> Result<()> {
    use std::os::windows::process::CommandExt;

    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let exe = std::env::current_exe()?;
    let args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| a != "--daemon")
        .collect();

    std::process::Command::new(exe)
        .args(&args)
        .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW)
        .spawn()?;

    std::process::exit(0);
}

fn resolve_log_level(explicit: Option<LogLevel>, daemon: bool) -> &'static str {
    match explicit {
        Some(LogLevel::Info) => "info",
        Some(LogLevel::Warn) => "warn",
        Some(LogLevel::Error) => "error",
        Some(LogLevel::None) => "off",
        None if daemon => "off",
        None => "warn",
    }
}

fn init_tracing(filter: &str) {
    if filter == "off" {
        return;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .init();
}
