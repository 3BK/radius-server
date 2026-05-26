use crate::config::{PeerPolicyConfig, TlsConfig};
use pem::{parse, parse_many};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use std::fs;
use std::sync::Arc;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::*;
use zeroize::Zeroize;

#[derive(Debug, Clone)]
pub struct PeerIdentity {
    pub fingerprint_sha256_hex: String,
    pub subject_cn: Option<String>,
    pub san_uris: Vec<String>,
    pub san_dns: Vec<String>,
}

pub fn build_tls_config(
    tls_cfg: &TlsConfig,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let mut ca_roots = RootCertStore::empty();

    let ca_bytes = fs::read(&tls_cfg.client_ca_path)?;
    for p in parse_many(&ca_bytes)? {
        if p.tag() == "CERTIFICATE" {
            ca_roots.add(CertificateDer::from(p.contents().to_vec()))?;
        }
    }

    let client_auth = WebPkiClientVerifier::builder(Arc::new(ca_roots)).build()?;

    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![aws_lc_rs::kx_group::SECP384R1];

    let builder = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(client_auth);

    let cert_bytes = fs::read(&tls_cfg.server_cert_path)?;
    let certs: Vec<CertificateDer<'static>> = parse_many(&cert_bytes)?
        .into_iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| CertificateDer::from(p.contents().to_vec()))
        .collect();

    if certs.is_empty() {
        return Err("No valid certificates found in server_cert_path".into());
    }

    let mut key_bytes = fs::read(&tls_cfg.private_key_path)?;
    let key_pem = parse(&key_bytes)?;
    let key = match key_pem.tag() {
        "PRIVATE KEY" => {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pem.contents().to_vec()))
        }
        "RSA PRIVATE KEY" => {
            PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(key_pem.contents().to_vec()))
        }
        "EC PRIVATE KEY" => {
            PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(key_pem.contents().to_vec()))
        }
        _ => return Err(format!("Unsupported private key format: {}", key_pem.tag()).into()),
    };
    key_bytes.zeroize();

    let mut server_config = builder.with_single_cert(certs, key)?;

    if tls_cfg.require_alpn_radius {
        server_config.alpn_protocols = vec![b"radius".to_vec()];
    }

    Ok(server_config)
}

pub fn extract_peer_identity(
    cert_der: &CertificateDer<'_>,
) -> Result<PeerIdentity, Box<dyn std::error::Error>> {
    let mut hasher = Sha256::new();
    hasher.update(cert_der.as_ref());
    let fingerprint_sha256_hex = hex::encode(hasher.finalize());

    let (_, cert) = X509Certificate::from_der(cert_der.as_ref())?;

    let subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string());

    let mut san_uris = Vec::new();
    let mut san_dns = Vec::new();

    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                GeneralName::URI(uri) => san_uris.push(uri.to_string()),
                GeneralName::DNSName(dns) => san_dns.push(dns.to_string()),
                _ => {}
            }
        }
    }

    Ok(PeerIdentity {
        fingerprint_sha256_hex,
        subject_cn,
        san_uris,
        san_dns,
    })
}

pub fn verify_peer_identity(
    peer: &PeerIdentity,
    policy: &PeerPolicyConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    if !policy.allowed_sha256_fingerprints.is_empty() {
        let allowed = policy
            .allowed_sha256_fingerprints
            .iter()
            .any(|fp| fp.eq_ignore_ascii_case(&peer.fingerprint_sha256_hex));
        if !allowed {
            return Err(format!(
                "Peer fingerprint {} is not in allowed set",
                peer.fingerprint_sha256_hex
            )
            .into());
        }
    }

    if let Some(prefix) = &policy.require_san_uri_prefix {
        let matched = peer.san_uris.iter().any(|u| u.starts_with(prefix));
        if !matched {
            return Err(format!(
                "Peer SAN URI does not match required prefix '{}'",
                prefix
            )
            .into());
        }
    }

    if let Some(suffix) = &policy.require_san_dns_suffix {
        let matched = peer.san_dns.iter().any(|d| d.ends_with(suffix));
        if !matched {
            return Err(format!(
                "Peer SAN DNS does not match required suffix '{}'",
                suffix
            )
            .into());
        }
    }

    if !policy.allow_subject_cn_fallback
        && policy.require_san_uri_prefix.is_none()
        && policy.require_san_dns_suffix.is_none()
        && peer.san_uris.is_empty()
        && peer.san_dns.is_empty()
    {
        return Err("Peer certificate has no SAN and CN fallback is disabled".into());
    }

    Ok(())
}
