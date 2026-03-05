use std::fs;
use std::io::BufReader;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use tracing::warn;

pub enum TlsMode {
    SelfSigned { host_suffix: String },
    LetsEncrypt(String),
    Manual { cert: String, key: String },
}

pub fn build_tls_config(mode: &TlsMode) -> Result<Arc<rustls::ServerConfig>> {
    let (certs, key) = match mode {
        TlsMode::SelfSigned { host_suffix } => build_self_signed(host_suffix)?,
        TlsMode::LetsEncrypt(domain) => load_letsencrypt(domain)?,
        TlsMode::Manual { cert, key } => load_pem_files(cert, key)?,
    };

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to build TLS server config")?;

    Ok(Arc::new(config))
}

fn build_self_signed(host_suffix: &str) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    warn!("using self-signed certificate — clients will need to skip verification (-k with curl)");

    let mut subject_alt_names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];

    if host_suffix != "localhost" {
        // Add wildcard and bare domain for custom host suffixes
        subject_alt_names.push(format!("*.{}", host_suffix));
        subject_alt_names.push(host_suffix.to_string());
    }

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

// ---------------------------------------------------------------------------
// TLS client config (for server → backend HTTPS connections)
// ---------------------------------------------------------------------------

/// Build a TLS client config that verifies certificates against well-known roots.
pub fn build_tls_client_config_verified() -> Result<Arc<rustls::ClientConfig>> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Build a TLS client config that skips all certificate verification.
pub fn build_tls_client_config_insecure() -> Result<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("failed to set TLS protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureVerifier(provider)))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct InsecureVerifier(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
