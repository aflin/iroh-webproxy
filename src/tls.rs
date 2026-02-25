use std::fs;
use std::io::BufReader;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tracing::warn;

pub enum TlsMode {
    SelfSigned,
    LetsEncrypt(String),
    Manual { cert: String, key: String },
}

pub fn build_tls_config(mode: &TlsMode) -> Result<Arc<rustls::ServerConfig>> {
    let (certs, key) = match mode {
        TlsMode::SelfSigned => build_self_signed()?,
        TlsMode::LetsEncrypt(domain) => load_letsencrypt(domain)?,
        TlsMode::Manual { cert, key } => load_pem_files(cert, key)?,
    };

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to build TLS server config")?;

    Ok(Arc::new(config))
}

fn build_self_signed() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    warn!("using self-signed certificate — clients will need to skip verification (-k with curl)");

    let subject_alt_names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];

    let certified_key = rcgen::generate_simple_self_signed(subject_alt_names)
        .context("failed to generate self-signed certificate")?;

    let cert_der = CertificateDer::from(certified_key.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(certified_key.signing_key.serialize_der())
        .map_err(|e| anyhow::anyhow!("failed to serialize private key: {}", e))?;

    Ok((vec![cert_der], key_der))
}

fn load_letsencrypt(
    domain: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let base = format!("/etc/letsencrypt/live/{}", domain);
    let cert_path = format!("{}/fullchain.pem", base);
    let key_path = format!("{}/privkey.pem", base);

    load_pem_files(&cert_path, &key_path)
        .with_context(|| format!("failed to load Let's Encrypt certs from {}", base))
}

fn load_pem_files(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_file =
        fs::File::open(cert_path).with_context(|| format!("cannot open cert: {}", cert_path))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse certs from {}", cert_path))?;

    if certs.is_empty() {
        bail!("no certificates found in {}", cert_path);
    }

    let key_file =
        fs::File::open(key_path).with_context(|| format!("cannot open key: {}", key_path))?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .with_context(|| format!("failed to parse private key from {}", key_path))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path))?;

    Ok((certs, key))
}
