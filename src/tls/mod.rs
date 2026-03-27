use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls_pemfile::{certs, private_key};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tracing::{info, warn};

use crate::config::EnvConfig;

/// TLS hardening policy parsed from environment variables.
#[derive(Debug, Clone)]
pub struct TlsPolicy {
    pub protocol_versions: Vec<&'static rustls::SupportedProtocolVersion>,
    pub crypto_provider: Arc<CryptoProvider>,
    pub prefer_server_cipher_order: bool,
}

impl TlsPolicy {
    /// Build a TLS policy from environment configuration.
    pub fn from_env_config(env_config: &EnvConfig) -> Result<Self, anyhow::Error> {
        // Determine protocol versions
        let mut versions: Vec<&'static rustls::SupportedProtocolVersion> = Vec::new();
        let min = &env_config.tls_min_version;
        let max = &env_config.tls_max_version;

        if min == "1.2" && (max == "1.2" || max == "1.3") {
            versions.push(&rustls::version::TLS12);
        }
        if max == "1.3" {
            versions.push(&rustls::version::TLS13);
        }
        // Edge case: min=1.3, max=1.3 → TLS 1.3 only
        if min == "1.3" && max == "1.3" {
            versions.clear();
            versions.push(&rustls::version::TLS13);
        }

        if versions.is_empty() {
            return Err(anyhow::anyhow!(
                "No valid TLS versions selected (min={}, max={})",
                min,
                max
            ));
        }

        // Build cipher suites
        let cipher_suites = if let Some(ref suites_str) = env_config.tls_cipher_suites {
            parse_cipher_suites(suites_str)?
        } else {
            default_cipher_suites()
        };

        // Build key exchange groups
        let kx_groups = if let Some(ref curves_str) = env_config.tls_curves {
            parse_kx_groups(curves_str)?
        } else {
            default_kx_groups()
        };

        // Log the TLS policy
        let version_names: Vec<&str> = versions
            .iter()
            .map(|v| {
                if std::ptr::eq(*v, &rustls::version::TLS12) {
                    "TLS 1.2"
                } else {
                    "TLS 1.3"
                }
            })
            .collect();
        let suite_names: Vec<String> = cipher_suites
            .iter()
            .map(|s| format!("{:?}", s.suite()))
            .collect();
        let group_names: Vec<String> = kx_groups
            .iter()
            .map(|g: &&'static dyn rustls::crypto::SupportedKxGroup| format!("{:?}", g.name()))
            .collect();

        info!(
            "TLS policy: versions={:?}, cipher_suites={:?}, curves={:?}, prefer_server_order={}",
            version_names, suite_names, group_names, env_config.tls_prefer_server_cipher_order
        );

        // Build custom CryptoProvider
        let base_provider = rustls::crypto::ring::default_provider();
        let provider = CryptoProvider {
            cipher_suites,
            kx_groups,
            ..base_provider
        };

        Ok(Self {
            protocol_versions: versions,
            crypto_provider: Arc::new(provider),
            prefer_server_cipher_order: env_config.tls_prefer_server_cipher_order,
        })
    }
}

/// Default secure cipher suites (TLS 1.3 + TLS 1.2 AEAD-only).
fn default_cipher_suites() -> Vec<rustls::SupportedCipherSuite> {
    vec![
        // TLS 1.3
        rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
        rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
        rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        // TLS 1.2
        rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ]
}

/// Default key exchange groups.
fn default_kx_groups() -> Vec<&'static dyn rustls::crypto::SupportedKxGroup> {
    vec![
        rustls::crypto::ring::kx_group::X25519,
        rustls::crypto::ring::kx_group::SECP256R1,
    ]
}

/// Parse comma-separated cipher suite names (OpenSSL naming convention) into rustls suites.
fn parse_cipher_suites(input: &str) -> Result<Vec<rustls::SupportedCipherSuite>, anyhow::Error> {
    let mut suites = Vec::new();
    for name in input.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let suite = match name {
            // TLS 1.3
            "TLS_AES_256_GCM_SHA384" => {
                rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384
            }
            "TLS_AES_128_GCM_SHA256" => {
                rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
            }
            "TLS_CHACHA20_POLY1305_SHA256" => {
                rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256
            }
            // TLS 1.2 (OpenSSL naming)
            "ECDHE-ECDSA-AES256-GCM-SHA384" => {
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            }
            "ECDHE-RSA-AES256-GCM-SHA384" => {
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            }
            "ECDHE-ECDSA-AES128-GCM-SHA256" => {
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            }
            "ECDHE-RSA-AES128-GCM-SHA256" => {
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            }
            "ECDHE-ECDSA-CHACHA20-POLY1305" => {
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            }
            "ECDHE-RSA-CHACHA20-POLY1305" => {
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            }
            unknown => {
                return Err(anyhow::anyhow!(
                    "Unknown cipher suite '{}'. Supported TLS 1.3: TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256. \
                 Supported TLS 1.2: ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-RSA-AES256-GCM-SHA384, \
                 ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES128-GCM-SHA256, \
                 ECDHE-ECDSA-CHACHA20-POLY1305, ECDHE-RSA-CHACHA20-POLY1305",
                    unknown
                ));
            }
        };
        suites.push(suite);
    }
    if suites.is_empty() {
        return Err(anyhow::anyhow!("No cipher suites specified"));
    }
    Ok(suites)
}

/// Parse comma-separated curve/key-exchange group names.
fn parse_kx_groups(
    input: &str,
) -> Result<Vec<&'static dyn rustls::crypto::SupportedKxGroup>, anyhow::Error> {
    let mut groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup> = Vec::new();
    for name in input.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let group: &'static dyn rustls::crypto::SupportedKxGroup = match name
            .to_lowercase()
            .as_str()
        {
            "x25519" => rustls::crypto::ring::kx_group::X25519,
            "secp256r1" | "p-256" | "p256" => rustls::crypto::ring::kx_group::SECP256R1,
            "secp384r1" | "p-384" | "p384" => rustls::crypto::ring::kx_group::SECP384R1,
            unknown => {
                return Err(anyhow::anyhow!(
                    "Unknown curve/group '{}'. Supported: X25519, secp256r1 (P-256), secp384r1 (P-384)",
                    unknown
                ));
            }
        };
        groups.push(group);
    }
    if groups.is_empty() {
        return Err(anyhow::anyhow!("No curves/groups specified"));
    }
    Ok(groups)
}

/// Load TLS server configuration with optional client certificate verification
/// and TLS hardening policy.
pub fn load_tls_config_with_client_auth(
    cert_path: &str,
    key_path: &str,
    client_ca_bundle_path: Option<&str>,
    no_verify: bool,
    tls_policy: &TlsPolicy,
) -> Result<Arc<ServerConfig>, anyhow::Error> {
    let cert_file = File::open(cert_path)?;
    let key_file = File::open(key_path)?;

    let cert_chain: Vec<_> = certs(&mut BufReader::new(cert_file))
        .filter_map(|r| r.ok())
        .collect();

    let key = private_key(&mut BufReader::new(key_file))?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {}", key_path))?;

    let builder = ServerConfig::builder_with_provider(tls_policy.crypto_provider.clone())
        .with_protocol_versions(&tls_policy.protocol_versions)
        .map_err(|e| anyhow::anyhow!("Failed to set TLS protocol versions: {}", e))?;

    let mut config = if no_verify {
        // No verification mode (for testing only)
        warn!(
            "TLS configuration loaded with certificate verification DISABLED (testing mode) from cert: {}, key: {}",
            cert_path, key_path
        );

        builder
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?
    } else if let Some(ca_bundle_path) = client_ca_bundle_path {
        // Load client CA bundle for client certificate verification
        let ca_file = File::open(ca_bundle_path)?;
        let ca_certs: Vec<_> = certs(&mut BufReader::new(ca_file))
            .filter_map(|r| r.ok())
            .collect();

        let mut client_auth_roots = rustls::RootCertStore::empty();
        let (added, ignored) = client_auth_roots.add_parsable_certificates(ca_certs);

        if added == 0 {
            return Err(anyhow::anyhow!(
                "No valid client CA certificates found in {}",
                ca_bundle_path
            ));
        }

        info!(
            "TLS configuration loaded with client certificate verification from cert: {}, key: {}, client CA: {} (added: {}, ignored: {})",
            cert_path, key_path, ca_bundle_path, added, ignored
        );

        let client_cert_verifier =
            rustls::server::WebPkiClientVerifier::builder(Arc::new(client_auth_roots))
                .build()
                .map_err(|e| {
                    anyhow::anyhow!("Failed to build client certificate verifier: {}", e)
                })?;

        builder
            .with_client_cert_verifier(client_cert_verifier)
            .with_single_cert(cert_chain, key)?
    } else {
        // No client certificate verification
        info!(
            "TLS configuration loaded without client certificate verification from cert: {}, key: {}",
            cert_path, key_path
        );

        builder
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?
    };

    // Prefer server cipher order for TLS 1.2 negotiation
    config.ignore_client_order = tls_policy.prefer_server_cipher_order;

    // Advertise HTTP/2 and HTTP/1.1 via ALPN so clients can negotiate HTTP/2 over TLS
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

/// A certificate verifier that accepts any server certificate.
///
/// Used when `backend_tls_verify_server_cert: false` or `FERRUM_TLS_NO_VERIFY=true`.
/// Shared across WebSocket, TCP, gRPC, and HTTP/2 proxy paths to avoid duplication.
#[derive(Debug)]
pub struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a client certificate verifier from a CA bundle file.
/// Used by the HTTP/3 listener to carry forward mTLS from the main TLS config.
pub fn build_client_cert_verifier(
    ca_bundle_path: &str,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>, anyhow::Error> {
    let ca_file = File::open(ca_bundle_path)?;
    let ca_certs: Vec<_> = certs(&mut BufReader::new(ca_file))
        .filter_map(|r| r.ok())
        .collect();

    let mut client_auth_roots = rustls::RootCertStore::empty();
    let (added, _ignored) = client_auth_roots.add_parsable_certificates(ca_certs);

    if added == 0 {
        return Err(anyhow::anyhow!(
            "No valid client CA certificates found in {}",
            ca_bundle_path
        ));
    }

    rustls::server::WebPkiClientVerifier::builder(Arc::new(client_auth_roots))
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build client certificate verifier: {}", e))
}
