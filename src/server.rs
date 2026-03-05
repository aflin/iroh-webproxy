use std::net::SocketAddr;

use anyhow::Result;
use iroh::Endpoint;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{error, info, warn};

use crate::transport::QuicIo;

/// Run the server proxy: accept iroh QUIC connections and forward raw bytes
/// to a local web server (HTTP or HTTPS). No HTTP parsing — just a
/// bidirectional byte tunnel.
pub async fn run(
    endpoint: Endpoint,
    target: SocketAddr,
    tls: Option<(TlsConnector, ServerName<'static>)>,
) -> Result<()> {
    if tls.is_some() {
        info!("server: accepting connections, forwarding to {} (TLS)", target);
    } else {
        info!("server: accepting connections, forwarding to {}", target);
    }

    loop {
        let incoming = match endpoint.accept().await {
            Some(inc) => inc,
            None => {
                info!("server: endpoint closed");
                break;
            }
        };

        let target = target;
        let tls = tls.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    let remote = conn.remote_id();
                    info!("server: connection from {}", remote);
                    handle_connection(conn, target, tls).await;
                }
                Err(e) => {
                    warn!("server: failed to accept connection: {}", e);
                }
            }
        });
    }

    Ok(())
}

async fn handle_connection(
    conn: iroh::endpoint::Connection,
    target: SocketAddr,
    tls: Option<(TlsConnector, ServerName<'static>)>,
) {
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                let msg = format!("{}", e);
                if msg.contains("closed") || msg.contains("Closed") {
                    info!("server: connection closed");
                } else {
                    warn!("server: accept_bi error: {}", e);
                }
                break;
            }
        };

        let target = target;
        let tls = tls.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, target, tls).await {
                error!("server: stream error: {}", e);
            }
        });
    }
}

async fn handle_stream(
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    target: SocketAddr,
    tls: Option<(TlsConnector, ServerName<'static>)>,
) -> Result<()> {
    let mut quic = QuicIo::new(send, recv);

    let tcp = TcpStream::connect(target).await.map_err(|e| {
        anyhow::anyhow!("cannot connect to target {}: {}", target, e)
    })?;

    match tls {
        Some((connector, server_name)) => {
            let mut tls_stream = connector.connect(server_name, tcp).await.map_err(|e| {
                anyhow::anyhow!("TLS handshake with target {} failed: {}", target, e)
            })?;

            let (to_backend, to_quic) =
                tokio::io::copy_bidirectional(&mut quic, &mut tls_stream).await?;

            info!(
                "server: stream closed ({} to backend, {} to client)",
                to_backend, to_quic
            );
        }
        None => {
            let mut tcp = tcp;

            let (to_backend, to_quic) =
                tokio::io::copy_bidirectional(&mut quic, &mut tcp).await?;

            info!(
                "server: stream closed ({} to backend, {} to client)",
                to_backend, to_quic
            );
        }
    }

    Ok(())
}
