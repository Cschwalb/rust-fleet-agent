//! TLS setup. On first run the agent generates a self-signed certificate and
//! stores it next to its config. The controller pins that certificate's
//! SHA-256 fingerprint, which the agent prints on generation.

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

pub struct CertPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl CertPaths {
    pub fn next_to(config_path: &Path) -> Self {
        let dir = config_path.parent().unwrap_or_else(|| Path::new("."));
        Self {
            cert: dir.join("cert.pem"),
            key: dir.join("key.pem"),
        }
    }
}

/// Ensure a cert/key pair exists, generating a self-signed one if not.
/// Returns the SHA-256 fingerprint (hex, colon-separated) of the certificate.
pub fn ensure_cert(paths: &CertPaths, hostname: &str) -> Result<String> {
    if !paths.cert.exists() || !paths.key.exists() {
        if let Some(parent) = paths.cert.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let mut names = vec![hostname.to_string()];
        if !names.iter().any(|n| n == "localhost") {
            names.push("localhost".to_string());
        }
        let cert = rcgen::generate_simple_self_signed(names)
            .context("generating self-signed certificate")?;
        std::fs::write(&paths.cert, cert.cert.pem()).context("writing cert.pem")?;
        std::fs::write(&paths.key, cert.key_pair.serialize_pem())
            .context("writing key.pem")?;
    }
    fingerprint(&paths.cert)
}

/// SHA-256 fingerprint of the first certificate in a PEM file, hex with colons.
pub fn fingerprint(cert_path: &Path) -> Result<String> {
    let data = std::fs::read(cert_path)
        .with_context(|| format!("reading {}", cert_path.display()))?;
    let mut reader = BufReader::new(&data[..]);
    let first = rustls_pemfile::certs(&mut reader)
        .next()
        .context("no certificate found in PEM file")??;
    let digest = Sha256::digest(&first);
    let hex: Vec<String> = digest.iter().map(|b| format!("{b:02X}")).collect();
    Ok(hex.join(":"))
}

pub fn build_acceptor(paths: &CertPaths) -> Result<TlsAcceptor> {
    let cert_data = std::fs::read(&paths.cert)
        .with_context(|| format!("reading {}", paths.cert.display()))?;
    let key_data = std::fs::read(&paths.key)
        .with_context(|| format!("reading {}", paths.key.display()))?;

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(&cert_data[..]))
            .collect::<Result<_, _>>()
            .context("parsing certificate chain")?;

    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut BufReader::new(&key_data[..]))
            .context("parsing private key")?
            .context("no private key found")?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building rustls server config")?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}
