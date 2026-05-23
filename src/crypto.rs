use crate::config::TlsConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, PrivatePkcs1KeyDer, PrivateSec1KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::fs;
use std::sync::Arc;

pub fn build_tls_config(tls_cfg: &TlsConfig) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    // 1. Load Client CA (mTLS Requirement)
    let mut ca_roots = RootCertStore::empty();
    let ca_bytes = fs::read(&tls_cfg.client_ca_path)?;
    for p in pem::parse_many(&ca_bytes)? {
        if p.tag() == "CERTIFICATE" {
            ca_roots.add(CertificateDer::from(p.contents().to_vec()))?;
        }
    }
    
    // Require valid client certificates (mTLS)
    let client_auth = WebPkiClientVerifier::builder(Arc::new(ca_roots)).build()?;

    let provider = rustls::crypto::aws_lc_rs::default_provider();

    let builder = ServerConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(client_auth);

    // 2. Load Server Certs
    let cert_bytes = fs::read(&tls_cfg.server_cert_path)?;
    let certs: Vec<CertificateDer<'static>> = pem::parse_many(&cert_bytes)?
        .into_iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| CertificateDer::from(p.contents().to_vec()))
        .collect();

    if certs.is_empty() {
        return Err("No valid certificates found in server_cert_path".into());
    }

    // 3. Load Private Key
    let key_bytes = fs::read(&tls_cfg.private_key_path)?;
    let key_pem = pem::parse(&key_bytes)?;
    
    // Map the PEM tag to the strict PKI types required by Rustls
    let key = match key_pem.tag() {
        "PRIVATE KEY" => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pem.contents().to_vec())),
        "RSA PRIVATE KEY" => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(key_pem.contents().to_vec())),
        "EC PRIVATE KEY" => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(key_pem.contents().to_vec())),
        _ => return Err(format!("Unsupported private key format: {}", key_pem.tag()).into()),
    };

    // 4. Finalize the configuration
    let mut server_config = builder.with_single_cert(certs, key)?;
    
    // 5. Append RadSec ALPN to the finalized config
    server_config.alpn_protocols.push(b"radius".to_vec());

    Ok(server_config)
}
