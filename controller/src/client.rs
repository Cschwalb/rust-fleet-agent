//! Controller-side TLS client with certificate pinning.
//!
//! The agent uses a self-signed certificate, so instead of a CA we pin the
//! certificate's SHA-256 fingerprint: the controller refuses to talk to any
//! server whose certificate does not match the expected fingerprint. This
//! defeats a man-in-the-middle even without a public CA.

use anyhow::{anyhow, Context, Result};
use fleet_common::{read_frame, write_frame, Command, Request, Response};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[derive(Debug)]
struct PinnedVerifier {
    /// Expected fingerprint as raw 32 bytes.
    expected: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let actual = Sha256::digest(end_entity.as_ref());
        // Constant-time compare of the fingerprint.
        let mut diff = 0u8;
        for (a, b) in actual.iter().zip(self.expected.iter()) {
            diff |= a ^ b;
        }
        if diff == 0 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server certificate fingerprint does not match the pinned value".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Parse a "AA:BB:CC..." or "aabbcc..." hex fingerprint into 32 bytes.
pub fn parse_fingerprint(s: &str) -> Result<[u8; 32]> {
    let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.len() != 64 {
        return Err(anyhow!(
            "fingerprint must be 32 bytes (64 hex digits); got {} hex digits",
            cleaned.len()
        ));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16)
            .context("invalid hex in fingerprint")?;
    }
    Ok(out)
}

/// Open a pinned TLS connection, send one request, return the response.
pub async fn send(
    host: &str,
    port: u16,
    fingerprint: [u8; 32],
    token: &str,
    command: Command,
) -> Result<Response> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let verifier = Arc::new(PinnedVerifier {
        expected: fingerprint,
        provider: provider.clone(),
    });

    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("configuring TLS versions")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("connecting to {host}:{port}"))?;

    // The pinned verifier ignores the name, but rustls still needs one.
    let server_name = ServerName::try_from(host.to_string())
        .unwrap_or_else(|_| ServerName::try_from("localhost").unwrap());

    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake failed (check the fingerprint and that the agent is running)")?;

    let request = Request::new(token, command);
    write_frame(&mut tls, &request)
        .await
        .context("sending request")?;
    let response: Response = read_frame(&mut tls).await.context("reading response")?;
    Ok(response)
}
