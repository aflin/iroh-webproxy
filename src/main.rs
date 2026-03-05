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
    /// identified by its node ID. The URL format is:
    ///
    ///   http://<nodeId>.<host-suffix>:8080/path
    ///
    /// The default host suffix is "localhost". With a wildcard DNS record
    /// (e.g. *.iroh.example.com) and --host-suffix iroh.example.com, clients
    /// can use http://<nodeId>.iroh.example.com:8080/path instead.
    ///
    /// HTTPS is enabled by providing one of --self-sign, --letsencrypt,
    /// or --tls-cert/--tls-key.
    ///
    /// The node ID is printed to stdout on startup.
    Client {
        /// Host suffix for routing (the domain after the node ID subdomain)
        #[arg(long, default_value = "localhost")]
        host_suffix: String,

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

        /// Write the process ID to a file (the post-fork PID when combined with --daemon)
        #[arg(long, value_name = "PATH")]
        pidfile: Option<String>,
    },

    /// Run as server proxy: accept iroh connections, forward to a local web server.
    ///
    /// Accepts connections from iroh-webproxy clients and forwards requests
    /// to a local HTTP or HTTPS web server.
    ///
    /// The target can be specified as:
    ///
    ///   ip:port              plain HTTP (use --tls for HTTPS)
    ///   http://ip:port       plain HTTP (error if --tls given)
    ///   https://ip:port      HTTPS, --insecure implied (no hostname to verify)
    ///   https://host:port    HTTPS, verifies certificate against hostname
    ///   ip:port --tls        HTTPS, --insecure implied (no hostname to verify)
    ///   host:port --tls      HTTPS, verifies certificate against hostname
    ///
    /// When the target is an IP address with TLS, --insecure is implied because
    /// there is no hostname to verify the certificate against. Use
    /// --target-hostname to supply one and enable verification.
    ///
    /// The node ID is printed to stdout on startup. Clients use this
    /// node ID to connect.
    ///
    /// By default the server saves its secret key to .iroh-webproxy-secret-key
    /// in the current directory and reloads it on subsequent runs so the
    /// node ID stays stable across restarts.
    Server {
        /// Target web server (ip:port, host:port, http://host:port, or https://host:port)
        #[arg(short, long, default_value = "127.0.0.1:8088")]
        target: String,

        /// Connect to target over TLS (implied by https:// target)
        #[arg(long)]
        tls: bool,

        /// Skip TLS certificate verification (implied when target is an IP address)
        #[arg(long)]
        insecure: bool,

        /// Hostname for TLS SNI and certificate verification (enables verification
        /// when target is an IP address)
        #[arg(long, value_name = "HOST")]
        target_hostname: Option<String>,

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

        /// Write the process ID to a file (the post-fork PID when combined with --daemon)
        #[arg(long, value_name = "PATH")]
        pidfile: Option<String>,
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
            host_suffix,
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
            pidfile,
        } => {
            let sk = transport::load_secret_key(secret_key.as_deref())?;
            println!("{}", sk.public());
            std::io::stdout().flush()?;

            if daemon {
                daemonize()?;
            }

            if let Some(ref path) = pidfile {
                write_pidfile(path)?;
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
                Some(tls::TlsMode::SelfSigned { host_suffix: host_suffix.clone() })
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
                    client::run(endpoint, http_addrs, https_addrs, tls_config, host_suffix).await
                })?;
        }

        Command::Server {
            target,
            tls,
            insecure,
            target_hostname,
            secret_key,
            key_file,
            no_key_save,
            no_key_load,
            log_level,
            daemon,
            pidfile,
        } => {
            let parsed = parse_target(&target, tls, insecure, target_hostname.as_deref())?;

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

            if let Some(ref path) = pidfile {
                write_pidfile(path)?;
            }

            init_tracing(resolve_log_level(log_level, daemon));

            let tls_connector = match parsed.tls_config {
                Some((config, server_name)) => {
                    Some((tokio_rustls::TlsConnector::from(config), server_name))
                }
                None => None,
            };

            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(async {
                    let endpoint = Endpoint::builder()
                        .secret_key(sk)
                        .alpns(vec![ALPN.to_vec()])
                        .bind()
                        .await?;
                    server::run(endpoint, parsed.addr, tls_connector).await
                })?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Target parsing
// ---------------------------------------------------------------------------

struct ParsedTarget {
    addr: SocketAddr,
    tls_config: Option<(std::sync::Arc<rustls::ClientConfig>, rustls_pki_types::ServerName<'static>)>,
}

/// Parse the --target value along with --tls, --insecure, and --target-hostname
/// into a resolved SocketAddr and optional TLS client config.
fn parse_target(
    target: &str,
    tls_flag: bool,
    insecure_flag: bool,
    target_hostname: Option<&str>,
) -> Result<ParsedTarget> {
    // Strip scheme if present
    let (scheme, host_port) = if let Some(rest) = target.strip_prefix("https://") {
        (Some("https"), rest)
    } else if let Some(rest) = target.strip_prefix("http://") {
        (Some("http"), rest)
    } else {
        (None, target)
    };

    // Strip trailing slash from URL-style targets
    let host_port = host_port.trim_end_matches('/');

    // Determine if TLS should be used
    let use_tls = match scheme {
        Some("https") => {
            if tls_flag {
                eprintln!("note: --tls is redundant with https:// target");
            }
            true
        }
        Some("http") => {
            if tls_flag {
                bail!("--tls conflicts with http:// target; use https:// or remove the scheme");
            }
            false
        }
        _ => tls_flag,
    };

    if insecure_flag && !use_tls {
        bail!("--insecure requires TLS (use --tls or an https:// target)");
    }
    if target_hostname.is_some() && !use_tls {
        bail!("--target-hostname requires TLS (use --tls or an https:// target)");
    }

    // Parse host and port from the host_port string
    let (host, port) = parse_host_port(host_port, scheme)?;

    // Determine if the host is an IP address or a hostname
    let is_ip = host.parse::<IpAddr>().is_ok();

    // Resolve to SocketAddr
    let addr = if is_ip {
        SocketAddr::new(host.parse::<IpAddr>()?, port)
    } else {
        use std::net::ToSocketAddrs;
        let addr_str = format!("{}:{}", host, port);
        addr_str
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow::anyhow!("cannot resolve hostname: {}", host))?
    };

    if !use_tls {
        return Ok(ParsedTarget {
            addr,
            tls_config: None,
        });
    }

    // Determine the TLS hostname for SNI and verification
    let tls_hostname: Option<String> = if let Some(h) = target_hostname {
        Some(h.to_string())
    } else if !is_ip {
        Some(host.clone())
    } else {
        None
    };

    // If we have no hostname and --insecure wasn't explicitly given,
    // default to insecure (can't verify a cert against an IP address)
    let effective_insecure = insecure_flag || tls_hostname.is_none();

    if effective_insecure && !insecure_flag && tls_hostname.is_none() {
        eprintln!(
            "note: no hostname for TLS verification, using insecure mode. \
             Use --target-hostname to enable verification."
        );
    }

    let client_config = if effective_insecure {
        tls::build_tls_client_config_insecure()?
    } else {
        tls::build_tls_client_config_verified()?
    };

    // Build the ServerName for SNI
    let server_name = match &tls_hostname {
        Some(name) => rustls_pki_types::ServerName::try_from(name.clone())
            .map_err(|e| anyhow::anyhow!("invalid TLS hostname '{}': {}", name, e))?,
        None => rustls_pki_types::ServerName::try_from("localhost".to_string())
            .expect("localhost is a valid server name"),
    };

    Ok(ParsedTarget {
        addr,
        tls_config: Some((client_config, server_name)),
    })
}

/// Parse "host:port" handling IPv6 brackets and default ports.
fn parse_host_port(s: &str, scheme: Option<&str>) -> Result<(String, u16)> {
    if s.starts_with('[') {
        // IPv6: [::1]:port
        let bracket_end = s
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("invalid IPv6 address in target: {}", s))?;
        let ip_part = &s[1..bracket_end];
        let rest = &s[bracket_end + 1..];
        let port = if let Some(port_str) = rest.strip_prefix(':') {
            port_str
                .parse::<u16>()
                .map_err(|_| anyhow::anyhow!("invalid port in target: {}", port_str))?
        } else {
            default_port(scheme)?
        };
        Ok((ip_part.to_string(), port))
    } else if let Some(colon_pos) = s.rfind(':') {
        let host_part = &s[..colon_pos];
        let port_part = &s[colon_pos + 1..];
        match port_part.parse::<u16>() {
            Ok(port) => Ok((host_part.to_string(), port)),
            Err(_) => bail!("invalid port in target: {}", port_part),
        }
    } else {
        // No port — use default based on scheme
        let port = default_port(scheme)?;
        Ok((s.to_string(), port))
    }
}

fn default_port(scheme: Option<&str>) -> Result<u16> {
    match scheme {
        Some("https") => Ok(443),
        Some("http") => Ok(80),
        _ => bail!("port required for target (e.g., host:8088)"),
    }
}

/// Write the current process ID to a file (no trailing newline).
fn write_pidfile(path: &str) -> Result<()> {
    let mut f = std::fs::File::create(path)?;
    write!(f, "{}", std::process::id())?;
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
