//! TLS/mTLS configuration for all gateway surfaces (frontend, backend, admin, gRPC).
//!
//! **CA trust chain resolution** (all 8 backend protocol paths follow this):
//! 1. Proxy-specific CA (`backend_tls_server_ca_cert_path`) → sole trust anchor
//! 2. Global CA bundle (`FERRUM_TLS_CA_BUNDLE_PATH`) → sole trust anchor
//! 3. Neither set → webpki/system roots (secure default)
//! 4. Explicit opt-out → `backend_tls_verify_server_cert: false` skips verification
//!
//! **CA exclusivity**: When a custom CA is configured, it is the **sole** trust
//! anchor — webpki/system roots are NOT added. This prevents internal backends
//! from being MITMed via any public CA.
//!
//! **TLS policy**: Optional hardening via `FERRUM_TLS_CIPHER_SUITES`,
//! `FERRUM_TLS_MIN_VERSION`, `FERRUM_TLS_KEY_EXCHANGE_GROUPS`. Applied to
//! both inbound listeners and outbound backend connections.

pub mod backend;

use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls_pemfile::{certs, private_key};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tracing::{info, warn};
use x509_parser::prelude::*;

use crate::config::EnvConfig;
use rustls::pki_types::CertificateRevocationListDer;

/// Loaded CRL data shared across all TLS surfaces. Empty when no CRL file is configured.
pub type CrlList = Arc<Vec<CertificateRevocationListDer<'static>>>;

/// Load Certificate Revocation Lists from a PEM file.
///
/// The file may contain multiple `-----BEGIN X509 CRL-----` blocks.
/// Returns an empty Vec if `path` is `None`.
pub fn load_crls(path: Option<&str>) -> Result<CrlList, anyhow::Error> {
    let Some(crl_path) = path else {
        return Ok(Arc::new(Vec::new()));
    };

    let file = File::open(crl_path)
        .map_err(|e| anyhow::anyhow!("Failed to open CRL file '{}': {}", crl_path, e))?;
    let mut reader = BufReader::new(file);

    let crls: Vec<CertificateRevocationListDer<'static>> = rustls_pemfile::crls(&mut reader)
        .filter_map(|r| r.ok())
        .collect();

    if crls.is_empty() {
        return Err(anyhow::anyhow!(
            "No valid CRL entries found in '{}'. Expected PEM blocks with '-----BEGIN X509 CRL-----'",
            crl_path
        ));
    }

    info!(
        "Loaded {} CRL(s) from {} for certificate revocation checking",
        crls.len(),
        crl_path
    );
    Ok(Arc::new(crls))
}

/// Default number of days before expiration to emit a warning.
pub const DEFAULT_CERT_EXPIRY_WARNING_DAYS: u64 = 30;

/// TLS hardening policy parsed from environment variables.
#[derive(Debug, Clone)]
pub struct TlsPolicy {
    pub protocol_versions: Vec<&'static rustls::SupportedProtocolVersion>,
    pub crypto_provider: Arc<CryptoProvider>,
    pub prefer_server_cipher_order: bool,
    pub session_cache_size: usize,
    /// Maximum 0-RTT early data size in bytes. 0 = disabled (default).
    /// When non-zero, the server advertises 0-RTT support in TLS 1.3 session tickets.
    pub early_data_max_size: u32,
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

        // 0-RTT early data: when methods are configured, enable with a 16 KiB limit
        // (matches typical HTTP request size). 0 = disabled (the secure default).
        let early_data_max_size = if env_config.tls_early_data_methods.is_empty() {
            0
        } else {
            16_384 // 16 KiB — large enough for typical GET/HEAD requests
        };

        Ok(Self {
            protocol_versions: versions,
            crypto_provider: Arc::new(provider),
            prefer_server_cipher_order: env_config.tls_prefer_server_cipher_order,
            session_cache_size: env_config.tls_session_cache_size,
            early_data_max_size,
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
///
/// Checks certificate expiration: expired certs are rejected, certs expiring
/// within `cert_expiry_warning_days` emit a warning log.
pub fn load_tls_config_with_client_auth(
    cert_path: &str,
    key_path: &str,
    client_ca_bundle_path: Option<&str>,
    no_verify: bool,
    tls_policy: &TlsPolicy,
    cert_expiry_warning_days: u64,
    crls: &[CertificateRevocationListDer<'static>],
) -> Result<Arc<ServerConfig>, anyhow::Error> {
    // Check certificate expiration before loading
    check_cert_expiry(cert_path, "server TLS cert", cert_expiry_warning_days)?;
    if let Some(ca_path) = client_ca_bundle_path {
        check_cert_expiry(ca_path, "client CA bundle", cert_expiry_warning_days)?;
    }

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

        let mut verifier_builder =
            rustls::server::WebPkiClientVerifier::builder(Arc::new(client_auth_roots));
        if !crls.is_empty() {
            verifier_builder = verifier_builder
                .with_crls(crls.iter().cloned())
                .allow_unknown_revocation_status()
                .only_check_end_entity_revocation();
            info!(
                "Client certificate CRL checking enabled ({} CRL(s))",
                crls.len()
            );
        }
        let client_cert_verifier = verifier_builder
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build client certificate verifier: {}", e))?;

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

    // Enable TLS session resumption for reduced handshake latency on reconnections.
    // Stateless tickets (TLS 1.3): server encrypts session state into the ticket,
    // no server-side storage needed. Tickets rotate keys every 6 hours automatically.
    // Stateful cache (TLS 1.2 fallback): configurable LRU for session ID resumption.
    match rustls::crypto::ring::Ticketer::new() {
        Ok(ticketer) => {
            config.ticketer = ticketer;
        }
        Err(e) => {
            warn!(
                "Failed to create TLS session ticket rotator, resumption will use stateful cache only: {}",
                e
            );
        }
    }
    config.session_storage =
        rustls::server::ServerSessionMemoryCache::new(tls_policy.session_cache_size);

    // TLS 1.3 0-RTT early data: explicitly disabled in this shared function.
    // This function is used for both proxy frontend and admin HTTPS listeners.
    // 0-RTT must NOT be enabled on admin listeners (no 425 guard there), so we
    // always set 0 here. Proxy-specific call sites apply early_data_max_size
    // via Arc::get_mut() after this returns — see modes/*.rs.
    config.max_early_data_size = 0;

    Ok(Arc::new(config))
}

/// Enable kTLS session-secret extraction on a `ServerConfig` returned by
/// [`load_tls_config_with_client_auth`].
///
/// Rustls refuses to hand out session secrets via `dangerous_extract_secrets()`
/// unless `ServerConfig::enable_secret_extraction` is set to `true`. Rustls
/// leaves this off by default because extracting secrets into userspace is a
/// potential exfiltration footgun; it must ONLY be enabled on ServerConfigs
/// used by the proxy frontend (never admin), and only when operator has
/// explicitly opted into kTLS via `FERRUM_KTLS_ENABLED`.
///
/// Must be called immediately after `load_tls_config_with_client_auth` while
/// the `Arc` has a single owner (ref count = 1).
pub fn enable_secret_extraction_for_ktls(config: &mut Arc<ServerConfig>) {
    if let Some(cfg) = Arc::get_mut(config) {
        cfg.enable_secret_extraction = true;
    } else {
        tracing::warn!(
            "Could not enable kTLS secret extraction: Arc<ServerConfig> has multiple owners"
        );
    }
}

/// Enable TLS 1.3 0-RTT early data on a `ServerConfig` returned by
/// [`load_tls_config_with_client_auth`].
///
/// Must be called immediately after `load_tls_config_with_client_auth` while
/// the `Arc` has a single owner (ref count = 1). Only apply to **proxy
/// frontend** configs — never to admin listeners (which lack the 425 guard).
pub fn enable_early_data(config: &mut Arc<ServerConfig>, tls_policy: &TlsPolicy) {
    if tls_policy.early_data_max_size > 0 {
        if let Some(cfg) = Arc::get_mut(config) {
            cfg.max_early_data_size = tls_policy.early_data_max_size;
        } else {
            // Should never happen — called right after construction.
            tracing::warn!(
                "Could not enable 0-RTT early data: Arc<ServerConfig> has multiple owners"
            );
        }
    }
}

/// Enable TLS session resumption on an outbound `ClientConfig` using the shared
/// `FERRUM_TLS_SESSION_CACHE_SIZE` knob; falls back to 4096 when no policy is set.
pub fn apply_client_session_resumption(
    config: &mut rustls::ClientConfig,
    tls_policy: Option<&TlsPolicy>,
) {
    let cache_size = tls_policy.map(|p| p.session_cache_size).unwrap_or(4096);
    config.resumption = rustls::client::Resumption::in_memory_sessions(cache_size);
}

/// Validate that the backend TLS policy can be converted into a QUIC-capable
/// rustls client config for HTTP/3 backends.
pub fn validate_backend_tls_policy_for_quic(policy: &TlsPolicy) -> Result<(), anyhow::Error> {
    if !policy
        .protocol_versions
        .iter()
        .any(|version| std::ptr::eq(*version, &rustls::version::TLS13))
    {
        return Err(anyhow::anyhow!("QUIC requires TLS 1.3 support"));
    }

    if !policy.crypto_provider.cipher_suites.iter().any(|suite| {
        matches!(
            suite.suite(),
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
                | rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
                | rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        )
    }) {
        return Err(anyhow::anyhow!(
            "QUIC requires at least one TLS 1.3 cipher suite"
        ));
    }

    let config = backend_client_config_builder(Some(policy))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    quinn::crypto::rustls::QuicClientConfig::try_from(config)
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("Failed to create QUIC client config: {}", e))
}

/// Build a rustls `ClientConfig` builder for backend/outbound connections
/// using the TLS policy's cipher suites, key exchange groups, and protocol versions.
///
/// This ensures outbound connections enforce the same TLS settings (cipher suites,
/// min/max protocol versions, key exchange groups) as inbound listeners.
///
/// Falls back to `ClientConfig::builder()` (using the installed global default
/// `CryptoProvider`) when no `TlsPolicy` is available — e.g., in unit tests.
pub fn backend_client_config_builder(
    tls_policy: Option<&TlsPolicy>,
) -> Result<rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>, anyhow::Error> {
    match tls_policy {
        Some(policy) => rustls::ClientConfig::builder_with_provider(policy.crypto_provider.clone())
            .with_protocol_versions(&policy.protocol_versions)
            .map_err(|e| anyhow::anyhow!("Failed to set TLS protocol versions for backend: {}", e)),
        None => {
            // Use the ring default provider explicitly so this works even when
            // no global CryptoProvider is installed (e.g., in unit tests).
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| anyhow::anyhow!("Failed to set default TLS protocol versions: {}", e))
        }
    }
}

/// Build a `WebPkiServerVerifier` with optional CRL checking.
///
/// When CRLs are provided, the verifier rejects certificates that appear in any CRL.
/// Uses `allow_unknown_revocation_status()` so certificates not covered by any CRL
/// (e.g., from public CAs without matching CRLs) are still accepted.
pub fn build_server_verifier_with_crls(
    root_store: rustls::RootCertStore,
    crls: &[CertificateRevocationListDer<'static>],
) -> Result<Arc<rustls::client::WebPkiServerVerifier>, anyhow::Error> {
    // Use ring provider explicitly so this works even when no global CryptoProvider
    // is installed (e.g., in unit/integration tests).
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut builder =
        rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(root_store), provider);
    if !crls.is_empty() {
        builder = builder
            .with_crls(crls.iter().cloned())
            .allow_unknown_revocation_status()
            .only_check_end_entity_revocation();
    }
    builder
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build server certificate verifier: {}", e))
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

/// Check X.509 certificate expiration for a PEM certificate file.
///
/// - Returns `Err` if any certificate in the file is expired (notAfter < now)
///   or not yet valid (notBefore > now).
/// - Logs a warning if any certificate expires within `warning_days`.
/// - `label` is used in log/error messages to identify the cert surface
///   (e.g. "frontend TLS cert", "backend_tls_client_cert_path").
pub fn check_cert_expiry(
    pem_path: &str,
    label: &str,
    warning_days: u64,
) -> Result<(), anyhow::Error> {
    let pem_data = std::fs::read(pem_path)
        .map_err(|e| anyhow::anyhow!("{}: failed to read '{}': {}", label, pem_path, e))?;

    let der_certs: Vec<_> = rustls_pemfile::certs(&mut &pem_data[..])
        .filter_map(|r| r.ok())
        .collect();

    if der_certs.is_empty() {
        return Err(anyhow::anyhow!(
            "{}: no valid PEM certificates found in '{}'",
            label,
            pem_path
        ));
    }

    for (i, der) in der_certs.iter().enumerate() {
        let (_, cert) = X509Certificate::from_der(der.as_ref()).map_err(|e| {
            anyhow::anyhow!(
                "{}: failed to parse certificate #{} in '{}': {}",
                label,
                i + 1,
                pem_path,
                e
            )
        })?;

        let subject = cert.subject().to_string();
        let validity = cert.validity();

        // is_valid() checks both notBefore and notAfter against the current time
        if !validity.is_valid() {
            // Determine which end of the validity window we're outside
            let now_ts = ASN1Time::now().timestamp();
            let not_before_ts = validity.not_before.timestamp();

            if now_ts < not_before_ts {
                return Err(anyhow::anyhow!(
                    "{}: certificate #{} (subject: {}) in '{}' is not yet valid (notBefore: {})",
                    label,
                    i + 1,
                    subject,
                    pem_path,
                    validity.not_before
                ));
            } else {
                return Err(anyhow::anyhow!(
                    "{}: certificate #{} (subject: {}) in '{}' has expired (notAfter: {})",
                    label,
                    i + 1,
                    subject,
                    pem_path,
                    validity.not_after
                ));
            }
        }

        // Check near-expiry warning using UNIX timestamps to avoid time crate dependency
        if warning_days > 0 {
            let now_ts = ASN1Time::now().timestamp();
            let not_after_ts = validity.not_after.timestamp();
            let remaining_secs = not_after_ts - now_ts;
            let remaining_days = remaining_secs / 86400;
            if remaining_days < warning_days as i64 {
                warn!(
                    "{}: certificate #{} (subject: {}) in '{}' expires in {} days (notAfter: {})",
                    label,
                    i + 1,
                    subject,
                    pem_path,
                    remaining_days,
                    validity.not_after
                );
            }
        }
    }

    Ok(())
}

/// Check certificate expiration for a PEM file, returning a `String` error
/// suitable for field validation (used by per-proxy backend TLS validation).
pub fn check_cert_expiry_for_validation(
    pem_path: &str,
    field_name: &str,
    warning_days: u64,
) -> Result<(), String> {
    check_cert_expiry(pem_path, field_name, warning_days).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_test_client_config() -> rustls::ClientConfig {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("default protocol versions")
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth()
    }

    #[test]
    fn apply_client_session_resumption_compiles_and_runs() {
        let mut config = new_test_client_config();
        apply_client_session_resumption(&mut config, None);
    }

    #[test]
    fn apply_client_session_resumption_with_policy() {
        let policy = TlsPolicy {
            protocol_versions: vec![&rustls::version::TLS13],
            crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
            prefer_server_cipher_order: false,
            session_cache_size: 123,
            early_data_max_size: 0,
        };
        let mut config = new_test_client_config();
        apply_client_session_resumption(&mut config, Some(&policy));
    }

    #[test]
    fn validate_backend_tls_policy_for_quic_accepts_tls13_defaults() {
        let policy = TlsPolicy {
            protocol_versions: vec![&rustls::version::TLS13],
            crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
            prefer_server_cipher_order: false,
            session_cache_size: 4096,
            early_data_max_size: 0,
        };

        validate_backend_tls_policy_for_quic(&policy)
            .expect("TLS 1.3 defaults should support QUIC");
    }

    #[test]
    fn validate_backend_tls_policy_for_quic_rejects_tls12_only_policy() {
        let policy = TlsPolicy {
            protocol_versions: vec![&rustls::version::TLS12],
            crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
            prefer_server_cipher_order: false,
            session_cache_size: 4096,
            early_data_max_size: 0,
        };

        let err = validate_backend_tls_policy_for_quic(&policy).unwrap_err();
        assert!(err.to_string().contains("QUIC"));
    }

    #[test]
    fn validate_backend_tls_policy_for_quic_rejects_tls12_only_cipher_suites() {
        let base_provider = rustls::crypto::ring::default_provider();
        let provider = rustls::crypto::CryptoProvider {
            cipher_suites: vec![
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            ],
            kx_groups: base_provider.kx_groups,
            ..base_provider
        };
        let policy = TlsPolicy {
            protocol_versions: vec![&rustls::version::TLS13],
            crypto_provider: Arc::new(provider),
            prefer_server_cipher_order: false,
            session_cache_size: 4096,
            early_data_max_size: 0,
        };

        let err = validate_backend_tls_policy_for_quic(&policy).unwrap_err();
        assert!(err.to_string().contains("TLS 1.3 cipher suite"));
    }
}
