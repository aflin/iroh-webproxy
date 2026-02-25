use std::pin::Pin;
use std::task::{Context, Poll};

use iroh::endpoint::{RecvStream, SendStream};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};

/// ALPN protocol identifier for the iroh HTTP proxy.
pub const ALPN: &[u8] = b"iroh-proxy/http/1";

/// Combines an iroh QUIC `SendStream` and `RecvStream` into a single
/// `AsyncRead + AsyncWrite` type that hyper can use as a transport.
pub struct QuicIo {
    send: SendStream,
    recv: RecvStream,
}

impl QuicIo {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for QuicIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Use fully-qualified syntax to call the tokio AsyncRead trait impl
        // (RecvStream also has an inherent poll_read that returns ReadError)
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for QuicIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Use fully-qualified syntax to call the tokio AsyncWrite trait impl
        // (SendStream also has an inherent poll_write that returns WriteError)
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

/// Default filename for persisted server secret key.
pub const DEFAULT_KEY_FILE: &str = ".iroh-webproxy-secret-key";

/// Load a secret key from a hex string or file path. If `None`, generate a new one.
pub fn load_secret_key(key_arg: Option<&str>) -> anyhow::Result<iroh::SecretKey> {
    match key_arg {
        None => Ok(iroh::SecretKey::generate(&mut rand::rng())),
        Some(s) => {
            // Try as hex first (64 hex chars = 32 bytes)
            if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
                let bytes = hex_to_bytes(s)?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("secret key must be 32 bytes"))?;
                return Ok(iroh::SecretKey::from(arr));
            }
            // Try as file path
            load_secret_key_file(s)
        }
    }
}

/// Load a secret key from a file containing hex.
pub fn load_secret_key_file(path: &str) -> anyhow::Result<iroh::SecretKey> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read key file '{}': {}", path, e))?;
    let hex = contents.trim();
    let bytes = hex_to_bytes(hex)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("key file must contain 32 bytes (64 hex chars)"))?;
    Ok(iroh::SecretKey::from(arr))
}

/// Save a secret key to a file as hex.
pub fn save_secret_key(key: &iroh::SecretKey, path: &str) -> anyhow::Result<()> {
    let hex = bytes_to_hex(&key.to_bytes());
    std::fs::write(path, format!("{}\n", hex))
        .map_err(|e| anyhow::anyhow!("cannot write key file '{}': {}", path, e))?;
    // Try to restrict permissions (best-effort, non-fatal on failure)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_to_bytes(hex: &str) -> anyhow::Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        anyhow::bail!("hex string has odd length");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("invalid hex: {}", e))
        })
        .collect()
}
