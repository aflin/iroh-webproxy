use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use hickory_resolver::Resolver;
use iroh::endpoint::Connection;
use iroh::{Endpoint, PublicKey};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::transport::{QuicIo, ALPN};

type ConnPool = Arc<Mutex<HashMap<PublicKey, Connection>>>;

const MAX_HEADER_SIZE: usize = 64 * 1024;

/// Run the client proxy with HTTP and optional HTTPS listeners.
pub async fn run(
    endpoint: Endpoint,
    http_addrs: Vec<SocketAddr>,
    https_addrs: Vec<SocketAddr>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let pool: ConnPool = Arc::new(Mutex::new(HashMap::new()));
    let mut handles = Vec::new();

    for addr in http_addrs {
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                warn!("client: cannot bind http://{}: {}", addr, e);
                continue;
            }
        };
        info!("client: listening on http://{}", addr);

        let ep = endpoint.clone();
        let pool = pool.clone();
        handles.push(tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        error!("client: http accept error: {}", e);
                        continue;
                    }
                };
                info!("client: http connection from {}", peer);
                let ep = ep.clone();
                let pool = pool.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, ep, pool).await {
                        warn!("client: connection error: {}", e);
                    }
                });
            }
        }));
    }

    if let Some(tls_cfg) = tls_config {
        let acceptor = TlsAcceptor::from(tls_cfg);

        for addr in https_addrs {
            let listener = match TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    warn!("client: cannot bind https://{}: {}", addr, e);
                    continue;
                }
            };
            info!("client: listening on https://{}", addr);

            let ep = endpoint.clone();
            let pool = pool.clone();
            let acceptor = acceptor.clone();
            handles.push(tokio::spawn(async move {
                loop {
                    let (stream, peer) = match listener.accept().await {
                        Ok(pair) => pair,
                        Err(e) => {
                            error!("client: https accept error: {}", e);
                            continue;
                        }
                    };
                    info!("client: https connection from {}", peer);
                    let acceptor = acceptor.clone();
                    let ep = ep.clone();
                    let pool = pool.clone();
                    tokio::spawn(async move {
                        let tls_stream = match acceptor.accept(stream).await {
                            Ok(s) => s,
                            Err(e) => {
                                warn!("client: tls handshake failed: {}", e);
                                return;
                            }
                        };
                        if let Err(e) = handle_connection(tls_stream, ep, pool).await {
                            warn!("client: connection error: {}", e);
                        }
                    });
                }
            }));
        }
    }

    if handles.is_empty() {
        anyhow::bail!("no listeners could be started");
    }

    for h in handles {
        let _ = h.await;
    }

    Ok(())
}

/// Handle a single browser connection: read HTTP headers to determine the
/// target node, then tunnel all bytes verbatim through a QUIC bidi stream.
async fn handle_connection<S>(mut stream: S, endpoint: Endpoint, pool: ConnPool) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Read bytes until we see the end-of-headers marker (\r\n\r\n).
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let header_end;

    loop {
        let n = tokio::io::AsyncReadExt::read(&mut stream, &mut tmp).await?;
        if n == 0 {
            return Ok(()); // client closed before sending headers
        }
        buf.extend_from_slice(&tmp[..n]);

        if let Some(pos) = find_header_end(&buf) {
            header_end = pos;
            break;
        }
        if buf.len() > MAX_HEADER_SIZE {
            send_error(&mut stream, 400, "Request headers too large").await;
            return Ok(());
        }
    }

    // Parse the Host header to determine the target iroh node.
    let node_id = match parse_node_id(&buf[..header_end]).await {
        Some(id) => id,
        None => {
            send_error(
                &mut stream,
                400,
                "Bad Request: use http://<nodeId>.localhost:<port>/path\n",
            )
            .await;
            return Ok(());
        }
    };

    info!("client: routing to node {}", node_id.fmt_short());

    // Get or create a QUIC connection to the target node.
    let conn = match get_connection(&endpoint, &pool, node_id).await {
        Ok(c) => c,
        Err(e) => {
            error!("client: connect to {} failed: {}", node_id.fmt_short(), e);
            send_error(&mut stream, 502, &format!("Bad Gateway: {}\n", e)).await;
            return Ok(());
        }
    };

    // Open a bidi stream (with one retry on stale connections).
    let (send, recv) = match conn.open_bi().await {
        Ok(pair) => pair,
        Err(e) => {
            {
                let mut map = pool.lock().await;
                map.remove(&node_id);
            }
            warn!("client: open_bi failed (retrying): {}", e);
            let conn = match get_connection(&endpoint, &pool, node_id).await {
                Ok(c) => c,
                Err(e2) => {
                    error!("client: reconnect failed: {}", e2);
                    send_error(&mut stream, 502, &format!("Bad Gateway: {}\n", e2)).await;
                    return Ok(());
                }
            };
            match conn.open_bi().await {
                Ok(pair) => pair,
                Err(e2) => {
                    error!("client: open_bi retry failed: {}", e2);
                    send_error(&mut stream, 502, &format!("Bad Gateway: {}\n", e2)).await;
                    return Ok(());
                }
            }
        }
    };

    let mut quic = QuicIo::new(send, recv);

    // Forward the buffered bytes (headers + any body bytes already read)
    // to the QUIC stream verbatim — zero modification.
    tokio::io::AsyncWriteExt::write_all(&mut quic, &buf).await?;

    // Bidirectional tunnel for the rest of the connection.
    match tokio::io::copy_bidirectional(&mut stream, &mut quic).await {
        Ok((to_server, to_client)) => {
            info!(
                "client: tunnel closed ({} sent, {} received)",
                to_server, to_client
            );
        }
        Err(e) => {
            info!("client: tunnel closed: {}", e);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Find the position of `\r\n\r\n` (end-of-headers). Returns the byte offset
/// just past the `\r\n\r\n` (i.e. the start of the body).
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

/// Extract the node ID from the HTTP Host header.
///
/// Supports:
///   - `<64-char-hex>.localhost[:port]`            (Firefox, curl)
///   - `<first32hex>.<last32hex>.localhost[:port]`  (Chrome — 63-char DNS label limit)
///   - `<domain>.localhost[:port]`                  (DNS TXT lookup for `iroh-nodeId=<hex>`)
async fn parse_node_id(headers: &[u8]) -> Option<PublicKey> {
    let host = get_host_header(headers)?;
    // Strip port if present
    let host_name = host.split(':').next().unwrap_or(host);
    let node_part = host_name.strip_suffix(".localhost")?;

    if node_part.len() == 65 && node_part.contains('.') {
        // Chrome split-hex: two labels totalling 64 hex chars + 1 dot
        let joined: String = node_part.chars().filter(|c| *c != '.').collect();
        if joined.len() == 64 && joined.chars().all(|c| c.is_ascii_alphanumeric()) {
            return joined.parse::<PublicKey>().ok();
        }
    } else if node_part.len() == 64 && node_part.chars().all(|c| c.is_ascii_alphanumeric()) {
        return node_part.parse::<PublicKey>().ok();
    }

    // Fallback: treat node_part as a domain name and look up TXT records
    // for an `iroh-nodeId=<nodeId>` entry.
    resolve_node_id_from_dns(node_part).await
}

/// Look up DNS TXT records for `domain` and find the last record matching
/// `iroh-nodeId=<hex>` (case-insensitive key). Returns the parsed PublicKey.
async fn resolve_node_id_from_dns(domain: &str) -> Option<PublicKey> {
    let resolver = Resolver::builder_tokio().ok()?.build();

    let lookup = match resolver.txt_lookup(domain).await {
        Ok(l) => l,
        Err(e) => {
            warn!("client: DNS TXT lookup for '{}' failed: {}", domain, e);
            return None;
        }
    };

    let mut result: Option<PublicKey> = None;

    for record in lookup.iter() {
        // TXT records can have multiple character-strings; join them
        let txt: String = record.txt_data()
            .iter()
            .map(|data| String::from_utf8_lossy(data))
            .collect::<Vec<_>>()
            .join("");

        // Look for iroh-nodeId=<value> (case-insensitive key)
        if let Some(eq_pos) = txt.find('=') {
            let key = &txt[..eq_pos];
            if key.eq_ignore_ascii_case("iroh-nodeid") {
                let value = txt[eq_pos + 1..].trim();
                if let Ok(pk) = value.parse::<PublicKey>() {
                    info!("client: resolved '{}' via DNS TXT to {}", domain, pk.fmt_short());
                    result = Some(pk);
                    // Keep going — use the last matching record
                }
            }
        }
    }

    result
}

/// Find the value of the `Host` header in raw HTTP header bytes.
fn get_host_header(headers: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(headers).ok()?;
    for line in text.split("\r\n") {
        if let Some(value) = line.strip_prefix("Host:").or_else(|| line.strip_prefix("host:")) {
            return Some(value.trim());
        }
        // Case-insensitive fallback
        if line.len() > 5 && line.as_bytes()[4] == b':' {
            let name = &line[..4];
            if name.eq_ignore_ascii_case("host") {
                return Some(line[5..].trim());
            }
        }
    }
    None
}

/// Write a minimal HTTP error response directly to the stream.
async fn send_error<S: AsyncWrite + Unpin>(stream: &mut S, status: u16, msg: &str) {
    let reason = match status {
        400 => "Bad Request",
        502 => "Bad Gateway",
        _ => "Error",
    };
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        reason,
        msg.len(),
        msg,
    );
    let _ = stream.write_all(resp.as_bytes()).await;
}

async fn get_connection(
    endpoint: &Endpoint,
    pool: &ConnPool,
    node_id: PublicKey,
) -> Result<Connection> {
    {
        let map = pool.lock().await;
        if let Some(conn) = map.get(&node_id) {
            if conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
        }
    }

    info!("client: connecting to node {}...", node_id.fmt_short());
    let conn = endpoint.connect(node_id, ALPN).await?;
    info!("client: connected to {}", node_id.fmt_short());

    let mut map = pool.lock().await;
    map.insert(node_id, conn.clone());
    Ok(conn)
}
