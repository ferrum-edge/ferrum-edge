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
//! `FERRUM_TLS_MIN_VERSION`, and `FERRUM_TLS_KEY_EXCHANGE_GROUPS`
//! (`FERRUM_TLS_CURVES` alias). Applied to both inbound listeners and
//! outbound backend connections.

pub mod acme;
pub mod backend;
pub mod events;
pub mod frontend_reload;
pub mod inventory;
pub mod inventory_cache;
pub mod managed;
#[cfg(feature = "pkcs11")]
pub mod pkcs11;
pub(crate) mod private_file;
pub mod source;
// `spiffe` exposes Phase A scaffolding for Phase C — every public item is
// dead from the binary's perspective until a later phase wires it in.
#[allow(dead_code)]
pub mod spiffe;

pub use frontend_reload::{
    FrontendTlsRebuildFn, FrontendTlsReloadConfig, SharedFrontendTls, empty_frontend_tls_slot,
    frontend_tls_slot_with, spawn_frontend_tls_reload_task,
};

#[allow(unused_imports)]
pub use spiffe::{
    SharedBundleSlot, SpiffeClientCertResolver, SpiffeServerCertResolver, SpiffeTlsError,
    build_spiffe_client_cert_verifier, build_spiffe_inbound_config, build_spiffe_outbound_config,
};

use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls_pemfile::{certs, private_key};
use std::fmt;
use std::io::{self, Cursor};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tracing::{info, warn};
use x509_parser::prelude::*;

use rustls::pki_types::CertificateRevocationListDer;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::config::EnvConfig;
use crate::tls::source::{
    CertSource, CertSourceUri, MaterialKind, SourceScheme, load_material_blocking,
};

/// Loaded CRL data shared across all TLS surfaces. Empty when no CRL file is configured.
pub type CrlList = Arc<Vec<CertificateRevocationListDer<'static>>>;
pub type SharedCrlList = Arc<arc_swap::ArcSwap<Vec<CertificateRevocationListDer<'static>>>>;

pub fn shared_crl_list(crls: CrlList) -> SharedCrlList {
    Arc::new(arc_swap::ArcSwap::new(crls))
}

/// Build a throwaway server config for listeners that must bind before real
/// dynamic TLS material exists. Callers should disable accepting handshakes
/// until the shared frontend TLS slot receives a real certificate.
pub(crate) fn temporary_disabled_listener_tls_config() -> Result<Arc<ServerConfig>, anyhow::Error> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()])?;
    let cert = params.self_signed(&key_pair)?;

    let cert_pem = cert.pem();
    let mut cert_reader = cert_pem.as_bytes();
    let certs: Vec<_> = certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    let key_pem = key_pair.serialize_pem();
    let mut key_reader = key_pem.as_bytes();
    let key = private_key(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!("temporary listener TLS key was not generated"))?;

    Ok(Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|error| anyhow::anyhow!("failed to apply default TLS versions: {error}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| anyhow::anyhow!("temporary listener TLS config is invalid: {error}"))?,
    ))
}

/// Accept a frontend TLS stream, optionally bounding the handshake duration.
///
/// The HTTP header read timeout starts only after TLS negotiation succeeds, so
/// TLS-capable listener surfaces must enforce this earlier deadline separately.
pub async fn accept_with_optional_timeout<S>(
    acceptor: &TlsAcceptor,
    stream: S,
    timeout_secs: u64,
    peer: &SocketAddr,
    record_mesh_mtls_metric: bool,
) -> io::Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let accept_fut = acceptor.accept(stream);
    let result = if timeout_secs > 0 {
        match tokio::time::timeout(Duration::from_secs(timeout_secs), accept_fut).await {
            Ok(result) => result,
            Err(_) => {
                if record_mesh_mtls_metric {
                    crate::plugins::mesh::prometheus_helpers::increment_mesh_mtls_handshake_failure(
                        "timeout",
                    );
                }
                warn!(
                    "Frontend TLS handshake timed out from {} after {}s",
                    peer.ip(),
                    timeout_secs
                );
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "frontend TLS handshake timed out",
                ));
            }
        }
    } else {
        accept_fut.await
    };

    match result {
        Ok(stream) => Ok(stream),
        Err(e) => {
            if record_mesh_mtls_metric {
                crate::plugins::mesh::prometheus_helpers::increment_mesh_mtls_handshake_failure(
                    "error",
                );
            }
            warn!("Frontend TLS handshake failed from {}: {}", peer.ip(), e);
            Err(e)
        }
    }
}

/// Load Certificate Revocation Lists from a PEM file.
///
/// The file may contain multiple `-----BEGIN X509 CRL-----` blocks.
/// Returns an empty Vec if `path` is `None`.
pub fn load_crls(path: Option<&str>) -> Result<CrlList, anyhow::Error> {
    let Some(crl_source_raw) = path else {
        return Ok(Arc::new(Vec::new()));
    };

    let crl_source = CertSource::parse(crl_source_raw, MaterialKind::Crl);
    let material = load_material_blocking(&crl_source, MaterialKind::Crl).map_err(|e| {
        anyhow::anyhow!(
            "Failed to load CRL source '{}': {}",
            crl_source.redacted_source_id(),
            e
        )
    })?;

    let crls: Vec<CertificateRevocationListDer<'static>> =
        rustls_pemfile::crls(&mut Cursor::new(material.bytes.expose_secret()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to parse CRL PEM blocks from '{}': {}",
                    material.display_source_id,
                    e
                )
            })?;

    if crls.is_empty() {
        return Err(anyhow::anyhow!(
            "No valid CRL entries found in '{}'. Expected PEM blocks with '-----BEGIN X509 CRL-----'",
            material.display_source_id
        ));
    }

    info!(
        "Loaded {} CRL(s) from {} for certificate revocation checking",
        crls.len(),
        material.display_source_id
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
///
/// Prefer AES-128-GCM before AES-256-GCM. AES-128-GCM, AES-256-GCM, and
/// ChaCha20-Poly1305 are modern AEAD suites; the default order favors cheaper
/// record processing while keeping AES-256 available for peers/operators that
/// require it.
fn default_cipher_suites() -> Vec<rustls::SupportedCipherSuite> {
    vec![
        // TLS 1.3
        rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
        rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
        rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        // TLS 1.2
        rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
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
                    "Unknown cipher suite '{}'. Supported TLS 1.3: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256. \
                 Supported TLS 1.2: ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES128-GCM-SHA256, \
                 ECDHE-ECDSA-CHACHA20-POLY1305, ECDHE-RSA-CHACHA20-POLY1305, \
                 ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-RSA-AES256-GCM-SHA384",
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
    load_tls_config_with_client_auth_and_ocsp(
        cert_path,
        key_path,
        client_ca_bundle_path,
        None,
        no_verify,
        tls_policy,
        cert_expiry_warning_days,
        crls,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn load_tls_config_with_client_auth_and_ocsp(
    cert_path: &str,
    key_path: &str,
    client_ca_bundle_path: Option<&str>,
    ocsp_response_source: Option<&str>,
    no_verify: bool,
    tls_policy: &TlsPolicy,
    cert_expiry_warning_days: u64,
    crls: &[CertificateRevocationListDer<'static>],
) -> Result<Arc<ServerConfig>, anyhow::Error> {
    let cert_source = CertSource::parse(cert_path, MaterialKind::Cert);
    let key_source = CertSource::parse(key_path, MaterialKind::Key);
    let client_ca_source =
        client_ca_bundle_path.map(|source| CertSource::parse(source, MaterialKind::CaBundle));
    let ocsp_source =
        ocsp_response_source.map(|source| CertSource::parse(source, MaterialKind::Ocsp));

    load_tls_config_with_client_auth_from_sources_and_ocsp(
        &cert_source,
        &key_source,
        client_ca_source.as_ref(),
        ocsp_source.as_ref(),
        no_verify,
        tls_policy,
        cert_expiry_warning_days,
        crls,
    )
}

/// Load TLS server configuration from polymorphic cert/key sources.
///
/// Existing path strings are parsed as [`CertSource::Path`]. Inline PEM is
/// accepted without writing temporary files, and `file://` URIs share the same
/// file loader. Other typed URI schemes parse successfully but are rejected here
/// until their provider loaders are wired in later phases.
#[allow(dead_code)]
pub fn load_tls_config_with_client_auth_from_sources(
    cert_source: &CertSource,
    key_source: &CertSource,
    client_ca_bundle_source: Option<&CertSource>,
    no_verify: bool,
    tls_policy: &TlsPolicy,
    cert_expiry_warning_days: u64,
    crls: &[CertificateRevocationListDer<'static>],
) -> Result<Arc<ServerConfig>, anyhow::Error> {
    load_tls_config_with_client_auth_from_sources_and_ocsp(
        cert_source,
        key_source,
        client_ca_bundle_source,
        None,
        no_verify,
        tls_policy,
        cert_expiry_warning_days,
        crls,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn load_tls_config_with_client_auth_from_sources_and_ocsp(
    cert_source: &CertSource,
    key_source: &CertSource,
    client_ca_bundle_source: Option<&CertSource>,
    ocsp_response_source: Option<&CertSource>,
    no_verify: bool,
    tls_policy: &TlsPolicy,
    cert_expiry_warning_days: u64,
    crls: &[CertificateRevocationListDer<'static>],
) -> Result<Arc<ServerConfig>, anyhow::Error> {
    let cert_material = load_material_blocking(cert_source, MaterialKind::Cert)?;

    check_cert_expiry_from_pem_bytes(
        cert_material.bytes.expose_secret(),
        "server TLS cert",
        &cert_material.display_source_id,
        cert_expiry_warning_days,
    )?;

    let cert_chain: Vec<_> = certs(&mut Cursor::new(cert_material.bytes.expose_secret()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            anyhow::anyhow!(
                "server TLS cert: failed to parse PEM certificates from '{}': {}",
                cert_material.display_source_id,
                e
            )
        })?;
    if cert_chain.is_empty() {
        return Err(anyhow::anyhow!(
            "server TLS cert: no PEM certificates found in '{}'",
            cert_material.display_source_id
        ));
    }

    let ocsp_response = match ocsp_response_source {
        Some(source) => {
            let material = load_material_blocking(source, MaterialKind::Ocsp)?;
            let bytes = material.bytes.expose_secret().to_vec();
            if bytes.is_empty() {
                return Err(anyhow::anyhow!(
                    "OCSP response source '{}' was empty",
                    material.display_source_id
                ));
            }
            info!(
                ocsp_source = %material.display_source_id,
                "Loaded stapled OCSP response for server TLS config"
            );
            bytes
        }
        None => Vec::new(),
    };

    let ServerCertResolverLoad {
        resolver: cert_resolver,
        key_source_id,
    } = load_server_cert_resolver(
        cert_chain,
        key_source,
        ocsp_response,
        tls_policy.crypto_provider.as_ref(),
    )?;

    let builder = ServerConfig::builder_with_provider(tls_policy.crypto_provider.clone())
        .with_protocol_versions(&tls_policy.protocol_versions)
        .map_err(|e| anyhow::anyhow!("Failed to set TLS protocol versions: {}", e))?;

    let mut config = if no_verify {
        // No verification mode (for testing only)
        warn!(
            "TLS configuration loaded with certificate verification DISABLED (testing mode) from cert source: {}, key source: {}",
            cert_material.display_source_id, key_source_id
        );

        builder
            .with_no_client_auth()
            .with_cert_resolver(cert_resolver)
    } else if let Some(ca_bundle_source) = client_ca_bundle_source {
        // Load client CA bundle for client certificate verification
        let ca_material = load_material_blocking(ca_bundle_source, MaterialKind::CaBundle)?;
        check_cert_expiry_from_pem_bytes(
            ca_material.bytes.expose_secret(),
            "client CA bundle",
            &ca_material.display_source_id,
            cert_expiry_warning_days,
        )?;
        let ca_certs: Vec<_> = certs(&mut Cursor::new(ca_material.bytes.expose_secret()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                anyhow::anyhow!(
                    "client CA bundle: failed to parse PEM certificates from '{}': {}",
                    ca_material.display_source_id,
                    e
                )
            })?;

        let mut client_auth_roots = rustls::RootCertStore::empty();
        let (added, ignored) = client_auth_roots.add_parsable_certificates(ca_certs);

        if added == 0 {
            return Err(anyhow::anyhow!(
                "No valid client CA certificates found in {}",
                ca_material.display_source_id
            ));
        }

        info!(
            "TLS configuration loaded with client certificate verification from cert source: {}, key source: {}, client CA source: {} (added: {}, ignored: {})",
            cert_material.display_source_id,
            key_source_id,
            ca_material.display_source_id,
            added,
            ignored
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
            .with_cert_resolver(cert_resolver)
    } else {
        // No client certificate verification
        info!(
            "TLS configuration loaded without client certificate verification from cert source: {}, key source: {}",
            cert_material.display_source_id, key_source_id
        );

        builder
            .with_no_client_auth()
            .with_cert_resolver(cert_resolver)
    };

    // Prefer server cipher order for TLS 1.2 negotiation
    config.ignore_client_order = tls_policy.prefer_server_cipher_order;

    // Advertise HTTP/2 and HTTP/1.1 via ALPN so clients can negotiate HTTP/2
    // over TLS. `acme-tls/1` is last so normal clients that also offer h2/h1
    // do not accidentally negotiate the ACME validation protocol.
    config.alpn_protocols = vec![
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
        crate::tls::acme::TLS_ALPN01_PROTOCOL.to_vec(),
    ];

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

struct ServerCertResolverLoad {
    resolver: Arc<dyn rustls::server::ResolvesServerCert>,
    key_source_id: String,
}

fn load_server_cert_resolver(
    cert_chain: Vec<CertificateDer<'static>>,
    key_source: &CertSource,
    ocsp_response: Vec<u8>,
    crypto_provider: &CryptoProvider,
) -> Result<ServerCertResolverLoad, anyhow::Error> {
    if let Some(uri) = pkcs11_key_uri(key_source) {
        let resolver = acme_tls_alpn_pkcs11_cert_resolver(cert_chain, uri, ocsp_response)?;
        return Ok(ServerCertResolverLoad {
            resolver,
            key_source_id: uri.source_id(),
        });
    }

    let key_material = load_material_blocking(key_source, MaterialKind::Key)?;
    let key =
        private_key(&mut Cursor::new(key_material.bytes.expose_secret()))?.ok_or_else(|| {
            anyhow::anyhow!("No private key found in {}", key_material.display_source_id)
        })?;
    let resolver = acme_tls_alpn_cert_resolver(cert_chain, key, ocsp_response, crypto_provider)?;
    Ok(ServerCertResolverLoad {
        resolver,
        key_source_id: key_material.display_source_id,
    })
}

fn pkcs11_key_uri(source: &CertSource) -> Option<&CertSourceUri> {
    match source {
        CertSource::Uri(uri) if uri.scheme == SourceScheme::Pkcs11 => Some(uri),
        _ => None,
    }
}

fn acme_tls_alpn_cert_resolver(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    ocsp_response: Vec<u8>,
    crypto_provider: &CryptoProvider,
) -> Result<Arc<dyn rustls::server::ResolvesServerCert>, anyhow::Error> {
    let mut certified_key = rustls::sign::CertifiedKey::from_der(cert_chain, key, crypto_provider)
        .map_err(|error| {
            anyhow::anyhow!("server TLS cert and key do not form a valid pair: {error}")
        })?;
    if !ocsp_response.is_empty() {
        certified_key.ocsp = Some(ocsp_response);
    }
    Ok(Arc::new(crate::tls::acme::AcmeTlsAlpnResolver::new(
        Arc::new(certified_key),
    )))
}

#[cfg(feature = "pkcs11")]
fn acme_tls_alpn_pkcs11_cert_resolver(
    cert_chain: Vec<CertificateDer<'static>>,
    uri: &CertSourceUri,
    ocsp_response: Vec<u8>,
) -> Result<Arc<dyn rustls::server::ResolvesServerCert>, anyhow::Error> {
    let mut certified_key = crate::tls::pkcs11::certified_key_from_uri(cert_chain, uri)?;
    if !ocsp_response.is_empty() {
        certified_key.ocsp = Some(ocsp_response);
    }
    Ok(Arc::new(crate::tls::acme::AcmeTlsAlpnResolver::new(
        Arc::new(certified_key),
    )))
}

#[cfg(not(feature = "pkcs11"))]
fn acme_tls_alpn_pkcs11_cert_resolver(
    _cert_chain: Vec<CertificateDer<'static>>,
    uri: &CertSourceUri,
    _ocsp_response: Vec<u8>,
) -> Result<Arc<dyn rustls::server::ResolvesServerCert>, anyhow::Error> {
    Err(anyhow::anyhow!(
        "PKCS#11 TLS key source '{}' requires building ferrum-edge with the 'pkcs11' cargo feature",
        uri.source_id()
    ))
}

/// Client authentication policy for mesh frontend TLS configs.
///
/// Maps from the mesh PeerAuthentication `MtlsMode` to rustls verifier
/// behavior:
/// - `Required`: `WebPkiClientVerifier` without `.allow_unauthenticated()`
///   (TLS handshake fails if no client cert).
/// - `Optional`: `WebPkiClientVerifier` with `.allow_unauthenticated()`
///   (client cert verified when present, TLS clients with no cert accepted).
/// - `None`: `with_no_client_auth()` (no CertificateRequest sent — server
///   TLS only). Used when PeerAuthentication is `Permissive` but no client
///   CA bundle is configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshClientAuth {
    /// Require a valid client certificate (Strict mTLS).
    Required,
    /// Request a client certificate but accept TLS connections without one
    /// (Permissive). When the client presents a cert, it is verified against
    /// the gateway SVID trust-domain verifier when present, otherwise the
    /// operator client CA bundle. A cert-less peer is still admitted.
    Optional,
    /// Do not request client certificates at all. Selected when
    /// PeerAuthentication is Permissive but there is no trust anchor at all —
    /// neither `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` nor gateway SVID
    /// material. The server still terminates TLS, but never asks the client to
    /// authenticate, so no peer identity can be verified or recorded. When
    /// either trust anchor exists, Permissive uses [`MeshClientAuth::Optional`]
    /// instead so an offered cert is verified and its SPIFFE identity recorded.
    None,
}

/// Server certificate source for mesh frontend TLS.
///
/// PeerAuthentication live reload is allowed to rebuild the mTLS mode and
/// client-CA verifier; the server credential is either **static** operator
/// material (parsed once — a later reload never incidentally re-reads changed
/// cert/key files from disk; the operator owns rotation) or the
/// **gateway-SVID-backed** source, which resolves live from the shared
/// rotating SVID slot so a file-based SVID rotation reaches the inbound
/// listener without a restart.
pub struct MeshServerIdentity {
    cert_path: String,
    key_path: String,
    source: MeshServerCertSource,
}

enum MeshServerCertSource {
    /// Operator-supplied static material (explicit `FERRUM_FRONTEND_TLS_*`).
    Static {
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    },
    /// Gateway-SVID-backed: the server cert resolves per handshake from the
    /// same `SharedSvidBundle` slot the SVID file watcher rotates, so the
    /// inbound listener presents the CURRENT leaf, not the startup one.
    SvidRotating {
        bundle: crate::identity::SharedSvidBundle,
    },
}

impl fmt::Debug for MeshServerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source = match &self.source {
            MeshServerCertSource::Static { cert_chain, .. } => {
                format!("Static(cert_chain_len={})", cert_chain.len())
            }
            MeshServerCertSource::SvidRotating { .. } => "SvidRotating".to_string(),
        };
        f.debug_struct("MeshServerIdentity")
            .field("cert_path", &self.cert_path)
            .field("key_path", &self.key_path)
            .field("source", &source)
            .finish()
    }
}

impl MeshServerIdentity {
    pub fn cert_path(&self) -> &str {
        &self.cert_path
    }

    pub fn key_path(&self) -> &str {
        &self.key_path
    }

    /// Whether the server credential rotates live with the gateway SVID slot.
    /// Test-only: production code selects the source at construction and never
    /// needs to re-interrogate it.
    #[cfg(test)]
    pub fn is_svid_rotating(&self) -> bool {
        matches!(&self.source, MeshServerCertSource::SvidRotating { .. })
    }

    /// Build the rustls server-cert resolver for this identity. Static
    /// material resolves to one pair-validated `CertifiedKey` (the same
    /// validation `with_single_cert` performed); the SVID-backed source
    /// resolves live from the shared rotating slot.
    fn server_cert_resolver(
        &self,
        provider: &Arc<CryptoProvider>,
    ) -> Result<Arc<dyn rustls::server::ResolvesServerCert>, anyhow::Error> {
        match &self.source {
            MeshServerCertSource::Static { cert_chain, key } => {
                let certified = rustls::sign::CertifiedKey::from_der(
                    cert_chain.clone(),
                    key.clone_key(),
                    provider,
                )
                .map_err(|error| {
                    anyhow::anyhow!(
                        "mesh server TLS cert and key do not form a valid pair: {error}"
                    )
                })?;
                Ok(Arc::new(FixedServerCert(Arc::new(certified))))
            }
            MeshServerCertSource::SvidRotating { bundle } => Ok(Arc::new(
                SvidServerCertResolver::new(bundle.clone(), Arc::clone(provider)),
            )),
        }
    }
}

/// Trivial resolver serving one pre-validated certified key — the
/// `with_single_cert` equivalent in resolver form, so static and
/// SVID-rotating mesh server credentials share one ServerConfig build path.
#[derive(Debug)]
struct FixedServerCert(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for FixedServerCert {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// A certified key plus the pointer identity of the SVID-slot snapshot it was
/// built from. `key: None` marks a snapshot whose material failed to build —
/// cached so a broken rotation is warned ONCE and then fails handshakes
/// closed, instead of re-attempting (and re-warning) on every handshake.
struct SvidResolvedCert {
    source: Arc<Option<crate::identity::SvidBundle>>,
    key: Option<Arc<rustls::sign::CertifiedKey>>,
}

/// Live server-cert resolver for the gateway-SVID-backed mesh inbound
/// identity. Per handshake (hot path) it does one `ArcSwap` load plus an
/// `Arc::ptr_eq` against the cached snapshot; the `CertifiedKey` is rebuilt
/// only when the SVID file watcher (or a future CA-backend rotation loop)
/// stores a new bundle into the shared slot.
///
/// Failure semantics, fail-closed: an EMPTY slot or a snapshot whose material
/// rustls rejects resolves to `None` — the handshake fails — rather than
/// presenting a stale leaf from a previous snapshot. The previous leaf is
/// already at most one rotation old and presenting it would mask a broken
/// rotation pipeline until that leaf expires mid-traffic; failing immediately
/// makes the breakage visible while the OLD process restart would have, too.
pub struct SvidServerCertResolver {
    bundle: crate::identity::SharedSvidBundle,
    provider: Arc<CryptoProvider>,
    cached: arc_swap::ArcSwap<Option<SvidResolvedCert>>,
}

impl fmt::Debug for SvidServerCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SvidServerCertResolver").finish()
    }
}

impl SvidServerCertResolver {
    pub fn new(bundle: crate::identity::SharedSvidBundle, provider: Arc<CryptoProvider>) -> Self {
        Self {
            bundle,
            provider,
            cached: arc_swap::ArcSwap::new(Arc::new(None)),
        }
    }
}

impl SvidServerCertResolver {
    /// The certified key for the slot's CURRENT snapshot — the whole resolver
    /// behavior; `resolve()` delegates here (rustls `ClientHello` carries no
    /// information this resolver consults, and cannot be constructed in
    /// tests).
    fn resolve_current(&self) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let current = self.bundle.load_full();
        if let Some(cached) = self.cached.load().as_ref()
            && Arc::ptr_eq(&cached.source, &current)
        {
            return cached.key.clone();
        }
        // Cold path: the slot rotated (or first handshake). Rebuild and cache
        // — including the failure case, so one bad rotation warns once.
        let key = match current.as_ref() {
            Some(svid) => match certified_key_from_svid_bundle(svid, &self.provider) {
                Ok(key) => {
                    info!(
                        spiffe_id = %svid.spiffe_id,
                        "Mesh inbound server identity rotated with the gateway SVID"
                    );
                    Some(Arc::new(key))
                }
                Err(error) => {
                    warn!(
                        error = %error,
                        "Rotated gateway SVID material is unusable as the inbound \
                         server certificate; failing inbound TLS handshakes closed \
                         until the next rotation provides usable material"
                    );
                    None
                }
            },
            None => {
                warn!(
                    "Gateway SVID slot is empty; failing inbound TLS handshakes \
                     closed until SVID material is installed"
                );
                None
            }
        };
        self.cached.store(Arc::new(Some(SvidResolvedCert {
            source: current,
            key: key.clone(),
        })));
        key
    }
}

impl rustls::server::ResolvesServerCert for SvidServerCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.resolve_current()
    }
}

/// Build a rustls `CertifiedKey` from an SVID bundle's leaf-first DER chain
/// and PKCS#8 key, validating that the key matches the leaf under `provider`.
fn certified_key_from_svid_bundle(
    bundle: &crate::identity::SvidBundle,
    provider: &Arc<CryptoProvider>,
) -> Result<rustls::sign::CertifiedKey, anyhow::Error> {
    let cert_chain: Vec<CertificateDer<'static>> = bundle
        .cert_chain_der
        .iter()
        .map(|der| CertificateDer::from(der.clone()))
        .collect();
    if cert_chain.is_empty() {
        return Err(anyhow::anyhow!("SVID bundle carries an empty cert chain"));
    }
    let key = PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        bundle.private_key_pkcs8_der.to_vec(),
    ));
    rustls::sign::CertifiedKey::from_der(cert_chain, key, provider).map_err(|error| {
        anyhow::anyhow!("SVID leaf and private key do not form a valid pair: {error}")
    })
}

/// Build the gateway-SVID-backed mesh server identity: the inbound listener's
/// server certificate resolves LIVE from `bundle` (the same shared slot the
/// SVID file watcher rotates), so file-based SVID rotation reaches inbound
/// handshakes without a restart. Fails closed at startup when the slot's
/// current material cannot back a server certificate — a configured-but-broken
/// identity is a real fault, exactly like the static loader's semantics.
pub fn svid_rotating_mesh_server_identity(
    cert_path: &str,
    key_path: &str,
    bundle: crate::identity::SharedSvidBundle,
) -> Result<Arc<MeshServerIdentity>, anyhow::Error> {
    let snapshot = bundle.load_full();
    let svid = snapshot.as_ref().as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "gateway SVID slot holds no material to back the mesh inbound server identity"
        )
    })?;
    certified_key_from_svid_bundle(svid, &default_crypto_provider())?;
    Ok(Arc::new(MeshServerIdentity {
        cert_path: cert_path.to_string(),
        key_path: key_path.to_string(),
        source: MeshServerCertSource::SvidRotating { bundle },
    }))
}

/// The process-default rustls crypto provider (startup installs ring before
/// any TLS work), with a ring fallback for test contexts that skip install.
fn default_crypto_provider() -> Arc<CryptoProvider> {
    CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()))
}

/// Borrowed client CA bundle contents paired with their display path.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClientCaBundleRef<'a> {
    pub path: &'a str,
    pub pem: &'a [u8],
}

/// Load mesh server cert/key material once at startup.
pub fn load_mesh_server_identity(
    cert_path: &str,
    key_path: &str,
    cert_expiry_warning_days: u64,
) -> Result<Arc<MeshServerIdentity>, anyhow::Error> {
    check_cert_expiry(cert_path, "mesh server TLS cert", cert_expiry_warning_days)?;

    let cert_source = CertSource::parse(cert_path, MaterialKind::Cert);
    let key_source = CertSource::parse(key_path, MaterialKind::Key);
    let cert_material = load_material_blocking(&cert_source, MaterialKind::Cert)?;
    let key_material = load_material_blocking(&key_source, MaterialKind::Key)?;

    let cert_chain: Vec<_> = certs(&mut Cursor::new(cert_material.bytes.expose_secret()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            anyhow::anyhow!(
                "mesh server TLS cert: failed to parse PEM certificates from '{}': {}",
                cert_material.display_source_id,
                e
            )
        })?;
    if cert_chain.is_empty() {
        return Err(anyhow::anyhow!(
            "No certificates found in mesh server TLS cert {}",
            cert_material.display_source_id
        ));
    }

    let key =
        private_key(&mut Cursor::new(key_material.bytes.expose_secret()))?.ok_or_else(|| {
            anyhow::anyhow!("No private key found in {}", key_material.display_source_id)
        })?;

    Ok(Arc::new(MeshServerIdentity {
        cert_path: cert_material.display_source_id,
        key_path: key_material.display_source_id,
        source: MeshServerCertSource::Static { cert_chain, key },
    }))
}

/// Build mesh TLS config using startup-cached server cert/key material.
#[allow(clippy::too_many_arguments)]
pub fn load_mesh_tls_config_with_identity(
    identity: &MeshServerIdentity,
    client_ca_bundle_path: Option<&str>,
    client_auth: MeshClientAuth,
    tls_policy: &TlsPolicy,
    cert_expiry_warning_days: u64,
    crls: &[CertificateRevocationListDer<'static>],
    spiffe_client_verifier: Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
) -> Result<Arc<ServerConfig>, anyhow::Error> {
    let client_ca_bundle_material = client_ca_bundle_path
        .map(|path| {
            let source = CertSource::parse(path, MaterialKind::CaBundle);
            load_material_blocking(&source, MaterialKind::CaBundle)
                .map_err(|e| anyhow::anyhow!("mesh client CA bundle: {}", e))
        })
        .transpose()?;
    let client_ca_bundle_ref =
        client_ca_bundle_material
            .as_ref()
            .map(|material| ClientCaBundleRef {
                path: material.display_source_id.as_str(),
                pem: material.bytes.expose_secret(),
            });

    load_mesh_tls_config_with_identity_and_client_ca_bytes(
        identity,
        client_ca_bundle_ref,
        client_auth,
        tls_policy,
        cert_expiry_warning_days,
        crls,
        spiffe_client_verifier,
    )
}

/// Build mesh TLS config using caller-provided client CA bytes.
///
/// PeerAuthentication live reload uses this path so the reload snapshot and
/// rustls verifier are built from the same CA bundle contents.
#[allow(clippy::too_many_arguments)]
pub(crate) fn load_mesh_tls_config_with_identity_and_client_ca_bytes(
    identity: &MeshServerIdentity,
    client_ca_bundle: Option<ClientCaBundleRef<'_>>,
    client_auth: MeshClientAuth,
    tls_policy: &TlsPolicy,
    cert_expiry_warning_days: u64,
    crls: &[CertificateRevocationListDer<'static>],
    spiffe_client_verifier: Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
) -> Result<Arc<ServerConfig>, anyhow::Error> {
    if let Some(bundle) = client_ca_bundle {
        check_cert_expiry_from_pem_bytes(
            bundle.pem,
            "mesh client CA bundle",
            bundle.path,
            cert_expiry_warning_days,
        )?;
    }

    let builder = ServerConfig::builder_with_provider(tls_policy.crypto_provider.clone())
        .with_protocol_versions(&tls_policy.protocol_versions)
        .map_err(|e| anyhow::anyhow!("Failed to set TLS protocol versions: {}", e))?;

    let mut config = match client_auth {
        MeshClientAuth::Required | MeshClientAuth::Optional => {
            // When a SPIFFE verifier is supplied (gateway SVID bundle is
            // available), use it: it validates the peer cert chain against the
            // SVID trust bundle AND the peer SAN's trust domain against
            // local/federated bundles — the actual mesh identity check Istio
            // relies on. It already encodes the STRICT-vs-PERMISSIVE
            // `peer_required` behavior. The caller builds this verifier with the
            // gateway CRLs (see `mesh_inbound_spiffe_verifier`), so inbound mesh
            // peers get the same end-entity revocation enforcement as the
            // operator-CA path below; the `crls` arg here applies only to that
            // operator-CA fallback for deployments without gateway SVID material.
            if let Some(verifier) = spiffe_client_verifier {
                info!(
                    mesh_client_auth = ?client_auth,
                    "Mesh TLS configuration loaded with SPIFFE trust-domain-validating \
                     client verifier from cert: {}, key: {}",
                    identity.cert_path(),
                    identity.key_path(),
                );
                builder
                    .with_client_cert_verifier(verifier)
                    .with_cert_resolver(identity.server_cert_resolver(&tls_policy.crypto_provider)?)
            } else {
                let ca_bundle = client_ca_bundle.ok_or_else(|| {
                    anyhow::anyhow!(
                        "Mesh mTLS {:?} mode requires readable client CA bundle bytes \
                         (FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH)",
                        client_auth
                    )
                })?;

                let ca_certs: Vec<_> = certs(&mut &ca_bundle.pem[..])
                    .filter_map(|r| r.ok())
                    .collect();

                let mut client_auth_roots = rustls::RootCertStore::empty();
                let (added, _ignored) = client_auth_roots.add_parsable_certificates(ca_certs);
                if added == 0 {
                    return Err(anyhow::anyhow!(
                        "No valid client CA certificates found in {}",
                        ca_bundle.path
                    ));
                }

                let mut verifier_builder =
                    rustls::server::WebPkiClientVerifier::builder(Arc::new(client_auth_roots));

                if client_auth == MeshClientAuth::Optional {
                    verifier_builder = verifier_builder.allow_unauthenticated();
                }

                if !crls.is_empty() {
                    verifier_builder = verifier_builder
                        .with_crls(crls.iter().cloned())
                        .allow_unknown_revocation_status()
                        .only_check_end_entity_revocation();
                }

                let verifier = verifier_builder.build().map_err(|e| {
                    anyhow::anyhow!("Failed to build mesh client certificate verifier: {}", e)
                })?;

                info!(
                    mesh_client_auth = ?client_auth,
                    "Mesh TLS configuration loaded with {:?} client auth from cert: {}, key: {}, client CA: {}",
                    client_auth,
                    identity.cert_path(),
                    identity.key_path(),
                    ca_bundle.path,
                );

                builder
                    .with_client_cert_verifier(verifier)
                    .with_cert_resolver(identity.server_cert_resolver(&tls_policy.crypto_provider)?)
            }
        }
        MeshClientAuth::None => {
            info!(
                "Mesh TLS configuration loaded without client auth from cert: {}, key: {}",
                identity.cert_path(),
                identity.key_path(),
            );
            builder
                .with_no_client_auth()
                .with_cert_resolver(identity.server_cert_resolver(&tls_policy.crypto_provider)?)
        }
    };

    config.ignore_client_order = tls_policy.prefer_server_cipher_order;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    match rustls::crypto::ring::Ticketer::new() {
        Ok(ticketer) => {
            config.ticketer = ticketer;
        }
        Err(e) => {
            warn!("Failed to create mesh TLS session ticket rotator: {}", e);
        }
    }
    config.session_storage =
        rustls::server::ServerSessionMemoryCache::new(tls_policy.session_cache_size);
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
/// NOTE: HTTPS/H2 paths currently cannot reliably recover per-request 0-RTT
/// state from tokio-rustls after accept. Until that signal is available, we
/// keep rustls 0-RTT disabled on the TCP/TLS frontend so method allowlists
/// cannot be bypassed by direct clients. Native HTTP/3 0-RTT remains supported
/// through quinn's `into_0rtt()` path.
pub fn enable_early_data(_config: &mut Arc<ServerConfig>, tls_policy: &TlsPolicy) {
    if tls_policy.early_data_max_size > 0 {
        tracing::warn!(
            "Ignoring HTTPS 0-RTT enablement: per-request early-data state is unavailable on tokio-rustls; keeping TLS early data disabled on the HTTPS frontend"
        );
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
///
/// When `crls` is non-empty, CRL revocation checking is enabled with the same
/// policy used by H1/H2 frontend mTLS and DTLS:
/// `allow_unknown_revocation_status` + `only_check_end_entity_revocation`.
pub fn build_client_cert_verifier(
    ca_bundle_path: &str,
    crls: &[CertificateRevocationListDer<'static>],
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>, anyhow::Error> {
    let ca_source = CertSource::parse(ca_bundle_path, MaterialKind::CaBundle);
    let ca_material = load_material_blocking(&ca_source, MaterialKind::CaBundle)?;
    let ca_certs: Vec<_> = certs(&mut Cursor::new(ca_material.bytes.expose_secret()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            anyhow::anyhow!(
                "client CA bundle: failed to parse PEM certificates from '{}': {}",
                ca_material.display_source_id,
                e
            )
        })?;

    let mut client_auth_roots = rustls::RootCertStore::empty();
    let (added, _ignored) = client_auth_roots.add_parsable_certificates(ca_certs);

    if added == 0 {
        return Err(anyhow::anyhow!(
            "No valid client CA certificates found in {}",
            ca_material.display_source_id
        ));
    }

    let mut verifier_builder =
        rustls::server::WebPkiClientVerifier::builder(Arc::new(client_auth_roots));
    if !crls.is_empty() {
        verifier_builder = verifier_builder
            .with_crls(crls.iter().cloned())
            .allow_unknown_revocation_status()
            .only_check_end_entity_revocation();
        info!(
            "HTTP/3 client certificate CRL checking enabled ({} CRL(s))",
            crls.len()
        );
    }

    verifier_builder
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
    pem_source: &str,
    label: &str,
    warning_days: u64,
) -> Result<(), anyhow::Error> {
    let source = CertSource::parse(pem_source, MaterialKind::Cert);
    let material = load_material_blocking(&source, MaterialKind::Cert)
        .map_err(|e| anyhow::anyhow!("{}: {}", label, e))?;
    check_cert_expiry_from_pem_bytes(
        material.bytes.expose_secret(),
        label,
        &material.display_source_id,
        warning_days,
    )
}

pub(crate) fn check_cert_expiry_from_pem_bytes(
    pem_data: &[u8],
    label: &str,
    display_path: &str,
    warning_days: u64,
) -> Result<(), anyhow::Error> {
    let der_certs: Vec<_> = rustls_pemfile::certs(&mut &pem_data[..])
        .filter_map(|r| r.ok())
        .collect();

    if der_certs.is_empty() {
        return Err(anyhow::anyhow!(
            "{}: no valid PEM certificates found in '{}'",
            label,
            display_path
        ));
    }

    for (i, der) in der_certs.iter().enumerate() {
        let (_, cert) = X509Certificate::from_der(der.as_ref()).map_err(|e| {
            anyhow::anyhow!(
                "{}: failed to parse certificate #{} in '{}': {}",
                label,
                i + 1,
                display_path,
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
                    display_path,
                    validity.not_before
                ));
            } else {
                return Err(anyhow::anyhow!(
                    "{}: certificate #{} (subject: {}) in '{}' has expired (notAfter: {})",
                    label,
                    i + 1,
                    subject,
                    display_path,
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
                    display_path,
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
    let source = CertSource::parse(pem_path, MaterialKind::Cert);
    match load_material_blocking(&source, MaterialKind::Cert) {
        Ok(material) => check_cert_expiry_from_pem_bytes(
            material.bytes.expose_secret(),
            field_name,
            &material.display_source_id,
            warning_days,
        )
        .map_err(|e| e.to_string()),
        Err(crate::tls::source::MaterialError::UnsupportedScheme { .. }) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mint a self-signed leaf + key as SVID-bundle material for resolver
    /// tests (chain + key are all the server credential consumes).
    fn test_svid_bundle(cn: &str) -> crate::identity::SvidBundle {
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        let key_pair = rcgen::KeyPair::generate().expect("key pair");
        let cert = params.self_signed(&key_pair).expect("self-signed leaf");
        let trust_domain =
            crate::identity::spiffe::TrustDomain::new("cluster.local").expect("trust domain");
        crate::identity::SvidBundle {
            spiffe_id: crate::identity::SpiffeId::from_parts(&trust_domain, "ns/test/sa/test")
                .expect("spiffe id"),
            cert_chain_der: vec![cert.der().as_ref().to_vec()],
            private_key_pkcs8_der: key_pair.serialize_der().into(),
            trust_bundles: crate::identity::TrustBundleSet::local_only(
                crate::identity::TrustBundle {
                    trust_domain,
                    x509_authorities: vec![],
                    jwt_authorities: vec![],
                    refresh_hint_seconds: None,
                },
            ),
        }
    }

    fn svid_slot(bundle: Option<crate::identity::SvidBundle>) -> crate::identity::SharedSvidBundle {
        Arc::new(arc_swap::ArcSwap::new(Arc::new(bundle)))
    }

    fn ring_provider() -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    /// The resolver serves the slot's CURRENT leaf and follows a rotation:
    /// storing a new bundle swaps the served certificate without any rebuild
    /// of the ServerConfig.
    #[test]
    fn svid_server_cert_resolver_serves_and_rotates_with_the_slot() {
        let bundle_a = test_svid_bundle("leaf-a");
        let leaf_a = bundle_a.cert_chain_der[0].clone();
        let slot = svid_slot(Some(bundle_a));
        let resolver = SvidServerCertResolver::new(slot.clone(), ring_provider());

        let served = resolver.resolve_current().expect("leaf A resolves");
        assert_eq!(served.cert[0].as_ref(), leaf_a.as_slice());
        // Cached fast path returns the same key for an unchanged slot.
        let again = resolver.resolve_current().expect("cached leaf resolves");
        assert!(
            Arc::ptr_eq(&served, &again),
            "unchanged slot must hit the cache"
        );

        let bundle_b = test_svid_bundle("leaf-b");
        let leaf_b = bundle_b.cert_chain_der[0].clone();
        slot.store(Arc::new(Some(bundle_b)));
        let rotated = resolver.resolve_current().expect("leaf B resolves");
        assert_eq!(
            rotated.cert[0].as_ref(),
            leaf_b.as_slice(),
            "a slot rotation must swap the served leaf without a restart"
        );
    }

    /// Fail-closed semantics: an empty slot and a rotated-in snapshot whose
    /// material rustls rejects both resolve to `None` (handshakes fail) —
    /// never a stale leaf from a previous snapshot.
    #[test]
    fn svid_server_cert_resolver_fails_closed_on_empty_or_unusable_material() {
        let slot = svid_slot(None);
        let resolver = SvidServerCertResolver::new(slot.clone(), ring_provider());
        assert!(
            resolver.resolve_current().is_none(),
            "an empty slot must fail the handshake closed"
        );

        let good = test_svid_bundle("good");
        slot.store(Arc::new(Some(good)));
        assert!(
            resolver.resolve_current().is_some(),
            "good material resolves"
        );

        let mut broken = test_svid_bundle("broken");
        broken.private_key_pkcs8_der = vec![0u8; 8].into();
        slot.store(Arc::new(Some(broken)));
        assert!(
            resolver.resolve_current().is_none(),
            "unusable rotated material must fail closed, not serve the previous leaf"
        );
        assert!(
            resolver.resolve_current().is_none(),
            "the poisoned snapshot stays cached (no per-handshake rebuild/warn)"
        );
    }

    /// The SVID-rotating identity constructor validates the slot's CURRENT
    /// material at startup (fail closed on empty/broken).
    #[test]
    fn svid_rotating_identity_validates_startup_material() {
        assert!(
            svid_rotating_mesh_server_identity("c", "k", svid_slot(None)).is_err(),
            "an empty slot must refuse to back the inbound identity"
        );
        let identity =
            svid_rotating_mesh_server_identity("c", "k", svid_slot(Some(test_svid_bundle("ok"))))
                .expect("valid slot material backs the identity");
        assert!(identity.is_svid_rotating());
    }

    fn new_test_client_config() -> rustls::ClientConfig {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("default protocol versions")
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth()
    }

    fn new_test_server_config() -> rustls::ServerConfig {
        let key_pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
        let params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        let cert = params.self_signed(&key_pair).expect("self-sign cert");

        let cert_pem = cert.pem();
        let mut cert_reader = cert_pem.as_bytes();
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
            .filter_map(Result::ok)
            .collect();
        let key_pem = key_pair.serialize_pem();
        let mut key_reader = key_pem.as_bytes();
        let private_key = rustls_pemfile::private_key(&mut key_reader)
            .expect("read private key")
            .expect("private key present");

        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .expect("server cert")
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

    #[tokio::test]
    async fn accept_with_optional_timeout_times_out_idle_peer() {
        use tokio::io::AsyncWriteExt;

        let acceptor = TlsAcceptor::from(Arc::new(new_test_server_config()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");

        let client = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr)
                .await
                .expect("connect to listener");
            tokio::time::sleep(Duration::from_millis(1500)).await;
            let _ = stream.shutdown().await;
        });

        let (stream, peer) = listener.accept().await.expect("accept TCP");
        let err = accept_with_optional_timeout(&acceptor, stream, 1, &peer, false)
            .await
            .expect_err("idle peer should hit TLS handshake timeout");

        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        client.await.expect("client task");
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
