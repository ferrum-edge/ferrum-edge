use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use reqwest::ClientBuilder;
#[cfg(feature = "pkcs11")]
use rustls::client::ResolvesClientCert;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{WantsClientCert, WebPkiServerVerifier};
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName, UnixTime,
};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore};
use thiserror::Error;
use x509_parser::extensions::{GeneralName, ParsedExtension};

use crate::config::types::{BackendTlsConfig, Proxy, validate_backend_tls_san_allow_list_entry};
use crate::tls::source::{
    CertSource, CertSourceUri, MaterialError, MaterialKind, SourceScheme, load_material_blocking,
};
use crate::tls::{
    NoVerifier, TlsPolicy, backend_client_config_builder, build_server_verifier_with_crls,
};

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("Failed to read {kind} from {path}: {source}")]
    Io {
        kind: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("Failed to parse {kind} from {path}: {details}")]
    Pem {
        kind: &'static str,
        path: PathBuf,
        details: String,
    },
    #[error("rustls: {0}")]
    Rustls(String),
}

/// Shared cache for backend rustls client configs keyed by connection identity.
///
/// Reusing the same `Arc<ClientConfig>` lets protocol pools share rustls'
/// in-memory session resumption state across new backend connections instead
/// of resetting it on every reconnect.
///
/// Cache keys MUST be tagged with the backend SVID generation marker (or the
/// `static` sentinel for operator-supplied certs) via
/// [`append_backend_svid_generation_key_field`] before calling
/// [`get_or_try_build`]. Drain operations rely on this contract to scope
/// invalidation to the rotated generation only.
#[derive(Clone, Default)]
pub struct BackendTlsConfigCache {
    configs: Arc<DashMap<String, Arc<ClientConfig>>>,
}

impl BackendTlsConfigCache {
    #[allow(dead_code)] // Used by focused tests with default shard sizing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a cache sized to the pool's shard count.
    ///
    /// The SVID generation is intentionally NOT held on the cache: cache keys
    /// are pre-tagged by callers via `append_backend_svid_generation_key_field`,
    /// and a stale `|svidg=N` entry is evicted by `drain_svid_generation(N)`
    /// when the rotation consumer task observes a revision bump. The cache
    /// itself stays generation-agnostic — see the `BackendTlsConfigCache`
    /// rustdoc for the full contract.
    pub fn with_shards(shards: usize) -> Self {
        Self {
            configs: Arc::new(DashMap::with_shard_amount(shards)),
        }
    }

    pub fn drain_svid_generation(&self, generation: u64) {
        let matcher = SvidGenerationMatcher::new(generation);
        self.configs.retain(|key, _| !matcher.matches(key));
    }

    pub fn clear(&self) {
        self.configs.clear();
    }

    /// Build or retrieve a cached `ClientConfig` for `key`. Callers MUST have
    /// already appended the SVID generation marker to `key` — see the
    /// rustdoc on [`BackendTlsConfigCache`]. A `debug_assert` catches drift
    /// in tests; release builds skip the check.
    pub fn get_or_try_build<E, F>(&self, key: String, build: F) -> Result<Arc<ClientConfig>, E>
    where
        F: FnOnce() -> Result<ClientConfig, E>,
    {
        debug_assert!(
            backend_tls_pool_key_has_svid_field(&key),
            "BackendTlsConfigCache::get_or_try_build requires the key to be tagged with `|svidg=...`; call append_backend_svid_generation_key_field before this entry point"
        );
        if let Some(existing) = self.configs.get(&key) {
            return Ok(existing.clone());
        }

        let config = Arc::new(build()?);

        match self.configs.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(entry) => Ok(entry.get().clone()),
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(config.clone());
                Ok(config)
            }
        }
    }
}

/// Pre-built matcher for SVID generation pool-key drain checks.
///
/// Building the matcher once and reusing it across every key in
/// `force_drain_svid_generation` / `drain_svid_generation` avoids per-key
/// `format!` allocations during a rotation drain pass.
#[derive(Debug, Clone)]
pub struct SvidGenerationMatcher {
    /// `"|svidg=<generation>"` — matches keys whose generation segment is the
    /// final field of the pool key.
    end_segment: String,
    /// `"|svidg=<generation>#"` — matches keys whose generation segment is
    /// followed by a shard separator (`#shard`) at the end.
    mid_segment: String,
}

impl SvidGenerationMatcher {
    pub fn new(generation: u64) -> Self {
        let end_segment = format!("|svidg={generation}");
        let mid_segment = format!("{end_segment}#");
        Self {
            end_segment,
            mid_segment,
        }
    }

    pub fn matches(&self, key: &str) -> bool {
        key.ends_with(&self.end_segment) || key.contains(&self.mid_segment)
    }
}

pub type BackendSvidGeneration = Arc<AtomicU64>;

/// Discriminate workload-SVID-driven client certs from operator-supplied ones.
///
/// Returns `Some(current_generation)` only when the effective backend client
/// cert path is byte-equal to the configured workload SVID cert path
/// (`FERRUM_GATEWAY_SVID_CERT_PATH`). For operator-supplied static material
/// or when no SVID is configured, returns `None` so the caller emits the
/// stable `svidg=static` segment and the pool key never partitions on
/// rotation. The comparison is intentionally byte-equality, not filesystem
/// canonicalization: callers (DestinationRule ISTIO_MUTUAL projection and the
/// `ReqwestPoolManager` / H2 / gRPC / H3 pool managers) copy paths from
/// `EnvConfig` without canonicalization, so both sides see the same string.
/// Operators who symlink the gateway SVID path under a different name on the
/// proxy's `resolved_tls.client_cert_path` will get `svidg=static` and miss
/// the rotation drain — keep both sides pointing at the same path string.
pub fn backend_svid_generation_for_client_cert(
    effective_client_cert_path: Option<&str>,
    workload_svid_cert_path: Option<&str>,
    current_generation: u64,
) -> Option<u64> {
    match (effective_client_cert_path, workload_svid_cert_path) {
        (Some(client_cert_path), Some(svid_cert_path)) if client_cert_path == svid_cert_path => {
            Some(current_generation)
        }
        _ => None,
    }
}

pub fn append_backend_svid_generation_key_field(buf: &mut String, svid_generation: Option<u64>) {
    use std::fmt::Write;
    buf.push_str("|svidg=");
    if let Some(svid_generation) = svid_generation {
        let _ = write!(buf, "{svid_generation}");
    } else {
        buf.push_str("static");
    }
}

pub fn backend_tls_pool_key_has_svid_field(key: &str) -> bool {
    key.contains("|svidg=")
}

/// Convenience wrapper around [`SvidGenerationMatcher`] for one-off matches
/// (tests and ad-hoc inspection). Production hot paths build a single
/// `SvidGenerationMatcher::new(generation)` and pass it into
/// `pool.invalidate_matching` to avoid per-key segment allocation.
#[allow(dead_code)]
pub fn backend_tls_pool_key_has_svid_generation(key: &str, svid_generation: u64) -> bool {
    SvidGenerationMatcher::new(svid_generation).matches(key)
}

/// Append a user/config-controlled pool-key component without letting reserved
/// pool-key separators bleed into adjacent fields or shard suffixes.
///
/// Pool keys are opaque strings, but several hot-path helpers append `|` field
/// separators and `#N` shard suffixes. Escaping `%` as well makes the encoding
/// canonical, so a literal `%7C` cannot collide with a literal `|`.
pub fn append_pool_key_component(buf: &mut String, component: &str) {
    if !component
        .as_bytes()
        .iter()
        .any(|b| matches!(b, b'|' | b'#' | b'%'))
    {
        buf.push_str(component);
        return;
    }

    for ch in component.chars() {
        match ch {
            '|' => buf.push_str("%7C"),
            '#' => buf.push_str("%23"),
            '%' => buf.push_str("%25"),
            _ => buf.push(ch),
        }
    }
}

pub fn append_optional_pool_key_component(buf: &mut String, component: Option<&str>) {
    if let Some(component) = component {
        append_pool_key_component(buf, component);
    }
}

fn append_optional_tls_source_pool_key_component(
    buf: &mut String,
    component: Option<&str>,
    kind: MaterialKind,
) {
    if let Some(component) = component {
        if component.starts_with("-----BEGIN ") {
            let source = CertSource::parse(component, kind);
            append_pool_key_component(buf, &source.pool_key_component());
        } else {
            append_pool_key_component(buf, component);
        }
    }
}

/// Append the backend TLS identity fields that partition runtime client caches.
///
/// Keep this in one place so HTTP, H2, H3, gRPC, and backend capability probes
/// agree on which TLS dimensions can change a reusable backend connection.
pub fn append_backend_tls_pool_key_fields(
    buf: &mut String,
    tls: &BackendTlsConfig,
    client_cert_path: Option<&str>,
    client_key_path: Option<&str>,
    verify_server_cert: bool,
    svid_generation: Option<u64>,
) {
    // The SAN digest is precomputed (see BackendTlsConfig::compute_san_digest) so
    // pool-key emission stays allocation-free. If a caller mutates san_allow_list
    // without calling recompute_san_digest, the digest goes stale and pool keys
    // collide across distinct SAN configs. This assert catches that drift in dev
    // and tests; it compiles out of release builds.
    debug_assert_eq!(
        tls.san_allow_list_key_digest,
        BackendTlsConfig::compute_san_digest(&tls.san_allow_list),
        "BackendTlsConfig.san_allow_list_key_digest is stale; call recompute_san_digest() after mutating san_allow_list"
    );
    append_optional_tls_source_pool_key_component(
        buf,
        tls.server_ca_cert_path.as_deref(),
        MaterialKind::CaBundle,
    );
    buf.push('|');
    append_optional_tls_source_pool_key_component(buf, client_cert_path, MaterialKind::Cert);
    buf.push('|');
    append_optional_tls_source_pool_key_component(buf, client_key_path, MaterialKind::Key);
    buf.push('|');
    append_optional_pool_key_component(buf, tls.sni.as_deref());
    buf.push('|');
    buf.push_str(tls.san_allow_list_key_digest.as_deref().unwrap_or_default());
    buf.push('|');
    buf.push(if verify_server_cert { '1' } else { '0' });
    append_backend_svid_generation_key_field(buf, svid_generation);
}

/// Return the TLS server name used for backend handshakes.
///
/// `backend_tls_sni` intentionally affects the SNI extension and rustls'
/// certificate-name verification while the TCP/QUIC dial target remains the
/// selected backend host.
///
/// GAP-1B wires this helper into H2, gRPC, and native H3 backend dispatch.
/// TCP+TLS, backend WebSocket, DTLS, and active health probes still use their
/// protocol-specific server-name plumbing and should route through this helper
/// when those paths grow backend SNI override support.
///
/// Caller invariant: any `tls.sni` value came from resolved configuration that
/// already passed `validate_backend_tls_sni`; this helper intentionally does
/// no normalization or validation on the request path.
pub fn backend_tls_server_name<'a>(tls: &'a BackendTlsConfig, host: &'a str) -> &'a str {
    tls.sni.as_deref().unwrap_or(host)
}

/// Return an owned rustls backend server name for pool-backed TLS handshakes.
pub fn backend_tls_server_name_owned(
    tls: &BackendTlsConfig,
    host: &str,
) -> Result<rustls::pki_types::ServerName<'static>, rustls::pki_types::InvalidDnsNameError> {
    rustls::pki_types::ServerName::try_from(backend_tls_server_name(tls, host))
        .map(|server_name| server_name.to_owned())
}

#[derive(Debug)]
enum BackendServerVerifier {
    WebPki(Arc<WebPkiServerVerifier>),
    SanAllowList(Arc<SanAllowListVerifier>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SanAllowListEntry {
    Dns(String),
    Uri(String),
    Ip(IpAddr),
}

impl SanAllowListEntry {
    fn parse(value: &str) -> Result<Self, TlsError> {
        validate_backend_tls_san_allow_list_entry(value)
            .map_err(|e| TlsError::Rustls(format!("backend TLS SAN allow-list {e}")))?;
        if let Ok(ip) = value.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }
        if value
            .get(..9)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("spiffe://"))
        {
            let Some(canonical) = canonicalize_spiffe_uri(value) else {
                return Err(TlsError::Rustls(
                    "backend TLS SAN allow-list SPIFFE URI is invalid".to_string(),
                ));
            };
            return Ok(Self::Uri(canonical));
        }
        Ok(Self::Dns(value.to_ascii_lowercase()))
    }
}

fn split_spiffe_uri(value: &str) -> Option<(&str, &str)> {
    let prefix = value.get(..9)?;
    if !prefix.eq_ignore_ascii_case("spiffe://") {
        return None;
    }
    let rest = value.get(9..)?;
    let slash = rest.find('/')?;
    if slash == 0 || slash + 1 >= rest.len() {
        return None;
    }
    Some((&rest[..slash], &rest[slash..]))
}

fn canonicalize_spiffe_uri(value: &str) -> Option<String> {
    let (trust_domain, path) = split_spiffe_uri(value)?;
    Some(format!(
        "spiffe://{}{}",
        trust_domain.to_ascii_lowercase(),
        path
    ))
}

fn spiffe_uri_matches(actual: &str, expected: &str) -> bool {
    let Some((actual_trust_domain, actual_path)) = split_spiffe_uri(actual) else {
        return false;
    };
    let Some((expected_trust_domain, expected_path)) = split_spiffe_uri(expected) else {
        return false;
    };
    actual_trust_domain.eq_ignore_ascii_case(expected_trust_domain) && actual_path == expected_path
}

/// A backend server verifier that delegates normal chain/name verification to
/// webpki, then requires at least one certificate SAN to match an explicit
/// allow-list entry.
#[derive(Debug)]
pub struct SanAllowListVerifier {
    inner: Arc<WebPkiServerVerifier>,
    allowed_sans: Arc<Vec<SanAllowListEntry>>,
}

impl SanAllowListVerifier {
    pub fn new(
        inner: Arc<WebPkiServerVerifier>,
        allowed_sans: Vec<String>,
    ) -> Result<Self, TlsError> {
        let allowed_sans = allowed_sans
            .iter()
            .map(|san| SanAllowListEntry::parse(san))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            inner,
            allowed_sans: Arc::new(allowed_sans),
        })
    }

    fn verify_allowed_sans(&self, end_entity: &CertificateDer<'_>) -> Result<(), RustlsError> {
        if self.allowed_sans.is_empty() {
            return Ok(());
        }
        certificate_matches_allowed_sans(end_entity, &self.allowed_sans)
    }
}

impl ServerCertVerifier for SanAllowListVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let verified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        self.verify_allowed_sans(end_entity)?;
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn certificate_matches_allowed_sans(
    end_entity: &CertificateDer<'_>,
    allowed_sans: &[SanAllowListEntry],
) -> Result<(), RustlsError> {
    let (_, cert) = x509_parser::parse_x509_certificate(end_entity.as_ref()).map_err(|e| {
        RustlsError::General(format!(
            "backend certificate SAN allow-list: failed to parse end-entity certificate: {e}"
        ))
    })?;

    let mut saw_subject_alt_name = false;
    for extension in cert.extensions() {
        let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() else {
            continue;
        };
        if saw_subject_alt_name {
            return Err(RustlsError::General(
                "backend certificate SAN allow-list rejected certificate: multiple SAN extensions"
                    .into(),
            ));
        }
        saw_subject_alt_name = true;
        for name in &san.general_names {
            if general_name_matches_any_allowed(name, allowed_sans) {
                return Ok(());
            }
        }
    }

    if saw_subject_alt_name {
        Err(RustlsError::General(
            "backend certificate SAN allow-list rejected certificate: no SAN matched".into(),
        ))
    } else {
        Err(RustlsError::General(
            "backend certificate SAN allow-list rejected certificate: no SAN extension".into(),
        ))
    }
}

fn general_name_matches_any_allowed(
    name: &GeneralName<'_>,
    allowed_sans: &[SanAllowListEntry],
) -> bool {
    allowed_sans
        .iter()
        .any(|allowed| general_name_matches_allowed(name, allowed))
}

fn general_name_matches_allowed(name: &GeneralName<'_>, allowed: &SanAllowListEntry) -> bool {
    match (name, allowed) {
        (GeneralName::DNSName(actual), SanAllowListEntry::Dns(expected)) => {
            actual.eq_ignore_ascii_case(expected)
        }
        (GeneralName::URI(actual), SanAllowListEntry::Uri(expected)) => {
            spiffe_uri_matches(actual, expected)
        }
        (GeneralName::IPAddress(actual), SanAllowListEntry::Ip(expected)) => {
            ip_addr_from_san_bytes(actual).is_some_and(|actual| actual == *expected)
        }
        _ => false,
    }
}

fn ip_addr_from_san_bytes(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => {
            let mut octets = [0_u8; 4];
            octets.copy_from_slice(bytes);
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        16 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(bytes);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// Build the backend trust store using the CA chain resolution from CLAUDE.md:
/// proxy CA, else global CA, else webpki roots. Custom CAs are exclusive.
pub fn build_root_cert_store(
    proxy_ca: Option<&Path>,
    global_ca: Option<&Path>,
) -> Result<RootCertStore, TlsError> {
    let ca_path = proxy_ca.or(global_ca);
    if let Some(ca_path) = ca_path {
        let material = load_backend_material(ca_path, MaterialKind::CaBundle, "backend CA bundle")?;
        return crate::tls::root_cert_store_from_pem_bundle(
            material.bytes.expose_secret(),
            "backend CA bundle",
            &material.display_source_id,
        )
        .map_err(|error| TlsError::Rustls(error.to_string()));
    }

    Ok(RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    ))
}

pub struct BackendTlsConfigBuilder<'a> {
    pub proxy: &'a Proxy,
    pub policy: Option<&'a TlsPolicy>,
    pub global_ca: Option<&'a Path>,
    pub global_no_verify: bool,
    pub global_client_cert: Option<&'a Path>,
    pub global_client_key: Option<&'a Path>,
    pub crls: &'a [CertificateRevocationListDer<'static>],
}

enum BackendClientAuth {
    None,
    Materialized {
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    },
    #[cfg(feature = "pkcs11")]
    Resolver(Arc<dyn ResolvesClientCert>),
}

impl<'a> BackendTlsConfigBuilder<'a> {
    pub fn build_rustls(&self) -> Result<ClientConfig, TlsError> {
        let builder = backend_client_config_builder(self.policy)
            .map_err(|e| TlsError::Rustls(format!("Failed to apply backend TLS policy: {}", e)))?;
        self.build_rustls_with_builder(
            builder,
            "Backend TLS certificate verification DISABLED (testing mode)",
        )
    }

    /// Keep the HTTP/3 backend path on a distinct entry point so the call site
    /// makes the QUIC-specific intent obvious in logs and future refactors.
    ///
    /// QUIC requires a TLS 1.3-compatible config. If the general backend TLS
    /// policy is incompatible, fall back to rustls safe defaults for the QUIC
    /// builder only, then continue applying the normal verifier and mTLS logic.
    pub fn build_rustls_quic(&self) -> Result<ClientConfig, TlsError> {
        let builder = match backend_client_config_builder(self.policy) {
            Ok(builder) => builder,
            Err(err) => {
                tracing::warn!(
                    "Backend TLS policy is incompatible with HTTP/3/QUIC ({}); falling back to rustls safe defaults for the QUIC builder",
                    err
                );
                backend_client_config_builder(None).map_err(|fallback_err| {
                    TlsError::Rustls(format!(
                        "Failed to build default HTTP/3 backend TLS config: {}",
                        fallback_err
                    ))
                })?
            }
        };
        self.build_rustls_with_builder(
            builder,
            "Backend TLS certificate verification DISABLED for HTTP/3 backend",
        )
    }

    fn build_rustls_with_builder(
        &self,
        builder: rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>,
        skip_verify_warning: &'static str,
    ) -> Result<ClientConfig, TlsError> {
        let client_auth = self.load_client_auth()?;

        let mut client_config = if self.skip_verification() {
            tracing::warn!("{}", skip_verify_warning);
            if !self.proxy.resolved_tls.san_allow_list.is_empty() {
                tracing::warn!(
                    proxy_id = %self.proxy.id,
                    san_allow_list_entries = self.proxy.resolved_tls.san_allow_list.len(),
                    "Backend TLS SAN allow-list is configured but certificate verification is disabled; SAN allow-list will not be enforced"
                );
            }
            let dangerous = builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier));
            finish_client_config_with_auth(dangerous, client_auth)
        } else {
            let verifier = self.build_server_verifier()?;
            match verifier {
                BackendServerVerifier::WebPki(verifier) => {
                    let builder = builder.with_webpki_verifier(verifier);
                    finish_client_config_with_auth(builder, client_auth)
                }
                BackendServerVerifier::SanAllowList(verifier) => {
                    let dangerous = builder
                        .dangerous()
                        .with_custom_certificate_verifier(verifier);
                    finish_client_config_with_auth(dangerous, client_auth)
                }
            }
        }?;

        crate::tls::apply_client_session_resumption(&mut client_config, self.policy);
        Ok(client_config)
    }

    pub fn build_reqwest(&self) -> Result<ClientBuilder, TlsError> {
        self.build_reqwest_with_http2_enabled(true)
    }

    pub fn build_reqwest_with_http2_enabled(
        &self,
        enable_http2: bool,
    ) -> Result<ClientBuilder, TlsError> {
        // reqwest 0.13 removed `tls_built_in_root_certs`. We always pass a
        // fully-built `rustls::ClientConfig` via `use_preconfigured_tls`, which
        // is the sole source of truth for the trust anchors anyway — the
        // built-in roots toggle never had any effect on this path.
        let mut builder = reqwest::Client::builder().no_proxy();
        if self.skip_verification() {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let force_http1 = self.proxy.forces_backend_http1_only() || !enable_http2;
        let rustls_config = self.build_rustls_for_reqwest(enable_http2)?;
        if force_http1 {
            // Belt-and-suspenders alongside the ALPN restriction in
            // `build_rustls_for_reqwest`: set reqwest's HTTP/1-only preference
            // too (covers the native-tls ALPN path; the rustls ALPN is the
            // load-bearing part for the preconfigured-rustls path we use).
            builder = builder.http1_only();
        }
        Ok(builder.use_preconfigured_tls(rustls_config))
    }

    /// Build the rustls `ClientConfig` for the reqwest backend client, applying
    /// the DestinationRule `connectionPool.http.h2UpgradePolicy = DO_NOT_UPGRADE`
    /// force-H1 ALPN restriction and the resolved backend HTTP/2 enablement.
    ///
    /// `DO_NOT_UPGRADE` must actually prevent HTTP/2 on a TLS backend, not
    /// merely skip the direct-H2 pool. reqwest's `use_preconfigured_tls`
    /// (`BuiltRustls`) path uses this config's ALPN VERBATIM — the connector
    /// does NOT re-derive ALPN from reqwest's `http1_only()` for a preconfigured
    /// config — and reqwest only speaks H2 when the wire-negotiated ALPN is
    /// `h2`. So for a force-H1 proxy we restrict the advertised ALPN to
    /// `http/1.1`: the backend can no longer ALPN-select h2. The same
    /// restriction applies when `pool_enable_http2=false` resolves for this
    /// proxy; otherwise disabling the direct-H2 pool would still leave reqwest
    /// free to negotiate h2.
    ///
    /// This is reqwest-specific (the shared `build_rustls` is left untouched, so
    /// the direct-H2 and H3/QUIC backend configs keep their own ALPN). The
    /// matching force-H1 discriminator in the reqwest pool key keeps this client
    /// from being shared with a default (h2-capable) one.
    fn build_rustls_for_reqwest(&self, enable_http2: bool) -> Result<ClientConfig, TlsError> {
        let mut rustls_config = self.build_rustls()?;
        if self.proxy.forces_backend_http1_only() || !enable_http2 {
            rustls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        }
        Ok(rustls_config)
    }

    fn build_server_verifier(&self) -> Result<BackendServerVerifier, TlsError> {
        let root_store = build_root_cert_store(self.custom_ca_path(), self.global_ca)?;
        let inner = build_server_verifier_with_crls(root_store, self.crls)
            .map_err(|e| TlsError::Rustls(format!("Failed to build server verifier: {}", e)))?;
        if self.proxy.resolved_tls.san_allow_list.is_empty() {
            Ok(BackendServerVerifier::WebPki(inner))
        } else {
            Ok(BackendServerVerifier::SanAllowList(Arc::new(
                SanAllowListVerifier::new(inner, self.proxy.resolved_tls.san_allow_list.clone())?,
            )))
        }
    }

    fn skip_verification(&self) -> bool {
        !self.proxy.resolved_tls.verify_server_cert || self.global_no_verify
    }

    fn custom_ca_path(&self) -> Option<&Path> {
        self.proxy
            .resolved_tls
            .server_ca_cert_path
            .as_deref()
            .map(Path::new)
            .or(self.global_ca)
    }

    fn load_client_auth(&self) -> Result<BackendClientAuth, TlsError> {
        let cert_path = self
            .proxy
            .resolved_tls
            .client_cert_path
            .as_deref()
            .map(Path::new)
            .or(self.global_client_cert);
        let key_path = self
            .proxy
            .resolved_tls
            .client_key_path
            .as_deref()
            .map(Path::new)
            .or(self.global_client_key);

        match (cert_path, key_path) {
            (Some(cert_path), None) => Err(TlsError::Pem {
                kind: "backend TLS client certificate",
                path: cert_path.to_path_buf(),
                details: "the private key is missing".to_string(),
            }),
            (None, Some(key_path)) => Err(TlsError::Pem {
                kind: "backend TLS client private key",
                path: key_path.to_path_buf(),
                details: "the certificate is missing".to_string(),
            }),
            (None, None) => Ok(BackendClientAuth::None),
            (Some(cert_path), Some(key_path)) => {
                let certs = load_cert_chain(
                    cert_path,
                    MaterialKind::Cert,
                    "backend TLS client certificate",
                )?;
                if let Some(uri) = pkcs11_key_uri_from_path(key_path) {
                    return pkcs11_backend_client_auth(certs, &uri);
                }
                let key = load_private_key(key_path, "backend TLS client private key")?;
                Ok(BackendClientAuth::Materialized { certs, key })
            }
        }
    }
}

fn finish_client_config_with_auth(
    builder: rustls::ConfigBuilder<ClientConfig, WantsClientCert>,
    client_auth: BackendClientAuth,
) -> Result<ClientConfig, TlsError> {
    match client_auth {
        BackendClientAuth::None => Ok(builder.with_no_client_auth()),
        BackendClientAuth::Materialized { certs, key } => builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| TlsError::Rustls(format!("Invalid client certificate/key pair: {}", e))),
        #[cfg(feature = "pkcs11")]
        BackendClientAuth::Resolver(resolver) => Ok(builder.with_client_cert_resolver(resolver)),
    }
}

fn pkcs11_key_uri_from_path(path: &Path) -> Option<CertSourceUri> {
    match CertSource::parse(path.to_string_lossy().into_owned(), MaterialKind::Key) {
        CertSource::Uri(uri) if uri.scheme == SourceScheme::Pkcs11 => Some(uri),
        _ => None,
    }
}

#[cfg(feature = "pkcs11")]
fn pkcs11_backend_client_auth(
    certs: Vec<CertificateDer<'static>>,
    uri: &CertSourceUri,
) -> Result<BackendClientAuth, TlsError> {
    let certified_key =
        crate::tls::pkcs11::certified_key_from_uri(certs, uri).map_err(|error| {
            TlsError::Rustls(format!(
                "Failed to configure PKCS#11 backend TLS client key {}: {}",
                uri.source_id(),
                error
            ))
        })?;
    Ok(BackendClientAuth::Resolver(Arc::new(
        rustls::sign::SingleCertAndKey::from(certified_key),
    )))
}

#[cfg(not(feature = "pkcs11"))]
fn pkcs11_backend_client_auth(
    _certs: Vec<CertificateDer<'static>>,
    uri: &CertSourceUri,
) -> Result<BackendClientAuth, TlsError> {
    Err(TlsError::Rustls(format!(
        "PKCS#11 backend TLS client key source {} requires building ferrum-edge with the 'pkcs11' Cargo feature",
        uri.source_id()
    )))
}

fn load_cert_chain(
    path: &Path,
    material_kind: MaterialKind,
    kind: &'static str,
) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let material = load_backend_material(path, material_kind, kind)?;
    let source_id = material.display_source_id.clone();
    let certs =
        crate::tls::parse_pem_certificate_bundle(material.bytes.expose_secret(), kind, &source_id)
            .map_err(|error| TlsError::Pem {
                kind,
                path: PathBuf::from(&source_id),
                details: error.to_string(),
            })?;

    Ok(certs)
}

fn load_private_key(path: &Path, kind: &'static str) -> Result<PrivateKeyDer<'static>, TlsError> {
    let material = load_backend_material(path, MaterialKind::Key, kind)?;
    let source_id = material.display_source_id.clone();
    crate::tls::parse_pem_private_key(material.bytes.expose_secret(), kind, &source_id).map_err(
        |error| TlsError::Pem {
            kind,
            path: PathBuf::from(&source_id),
            details: error.to_string(),
        },
    )
}

fn load_backend_material(
    path: &Path,
    material_kind: MaterialKind,
    kind: &'static str,
) -> Result<crate::tls::source::MaterializedMaterial, TlsError> {
    let raw_source = path.to_string_lossy().into_owned();
    let source = CertSource::parse(raw_source, material_kind);
    load_material_blocking(&source, material_kind).map_err(|err| match err {
        MaterialError::Io { source_id, source } => TlsError::Io {
            kind,
            path: PathBuf::from(source_id),
            source,
        },
        other => TlsError::Rustls(format!(
            "Failed to load {kind} from {}: {other}",
            source.redacted_source_id()
        )),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Once};

    use chrono::Utc;
    use rcgen::{
        BasicConstraints, CertificateParams, CertificateRevocationListParams, IsCa, Issuer,
        KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
    };
    use rustls::client::danger::ServerCertVerifier;
    use tempfile::TempDir;

    use crate::config::types::{AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, Proxy};

    static INIT_CRYPTO: Once = Once::new();

    struct GeneratedCa {
        cert_pem: String,
        issuer: Issuer<'static, KeyPair>,
    }

    struct GeneratedCert {
        cert_pem: String,
        key_pem: String,
        cert_der: CertificateDer<'static>,
        serial: SerialNumber,
    }

    fn ensure_crypto_provider() {
        INIT_CRYPTO.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn generate_ca(cn: &str) -> GeneratedCa {
        let key_pair =
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate CA key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        let cert = params.self_signed(&key_pair).expect("self-sign CA");
        GeneratedCa {
            cert_pem: cert.pem(),
            issuer: Issuer::new(params, key_pair),
        }
    }

    fn generate_signed_cert(ca: &GeneratedCa, cn: &str, sans: &[&str]) -> GeneratedCert {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let mut params =
            CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .expect("leaf params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        let serial = SerialNumber::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        params.serial_number = Some(serial.clone());
        let cert = params.signed_by(&key_pair, &ca.issuer).expect("sign leaf");
        let cert_pem = cert.pem();
        let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("parse leaf PEM")
            .into_iter()
            .next()
            .expect("leaf DER");

        GeneratedCert {
            cert_pem,
            key_pem: key_pair.serialize_pem(),
            cert_der,
            serial,
        }
    }

    fn generate_crl_pem(ca: &GeneratedCa, revoked_serials: &[SerialNumber]) -> String {
        let now = time::OffsetDateTime::now_utc();
        let revoked_certs = revoked_serials
            .iter()
            .cloned()
            .map(|serial_number| RevokedCertParams {
                serial_number,
                revocation_time: now,
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            })
            .collect();

        CertificateRevocationListParams {
            this_update: now,
            next_update: now + time::Duration::days(30),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        }
        .signed_by(&ca.issuer)
        .expect("sign CRL")
        .pem()
        .expect("CRL to PEM")
    }

    fn write_file(dir: &TempDir, name: &str, data: &str) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, data).expect("write test file");
        path
    }

    fn parse_crls(pem: &str) -> Vec<CertificateRevocationListDer<'static>> {
        rustls_pemfile::crls(&mut pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("parse CRLs")
    }

    fn test_proxy() -> Proxy {
        Proxy {
            id: "proxy-1".to_string(),
            name: Some("proxy-1".to_string()),
            namespace: "ferrum".to_string(),
            hosts: vec!["example.com".to_string()],
            listen_path: Some("/".to_string()),
            backend_scheme: Some(BackendScheme::Https),
            dispatch_kind: DispatchKind::from(BackendScheme::Https),
            backend_host: "localhost".to_string(),
            backend_port: 443,
            backend_path: None,
            strip_listen_path: true,
            preserve_host_header: false,
            backend_connect_timeout_ms: 1_000,
            backend_read_timeout_ms: 1_000,
            backend_write_timeout_ms: 1_000,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            resolved_tls: BackendTlsConfig::default_verify(),
            dispatch_port_overrides: None,
            dispatch_port_override_fallback: None,
            dns_override: None,
            dns_cache_ttl_seconds: None,
            auth_mode: AuthMode::default(),
            plugins: Vec::new(),
            pool_idle_timeout_seconds: None,
            pool_enable_http_keep_alive: None,
            pool_enable_http2: None,
            pool_tcp_keepalive_seconds: None,
            pool_http2_keep_alive_interval_seconds: None,
            pool_http2_keep_alive_timeout_seconds: None,
            pool_http2_initial_stream_window_size: None,
            pool_http2_initial_connection_window_size: None,
            pool_http2_adaptive_window: None,
            pool_http2_max_frame_size: None,
            pool_http2_max_concurrent_streams: None,
            pool_http3_connections_per_backend: None,
            h2_upgrade_policy: None,
            pool_max_requests_per_connection: None,
            pool_http1_max_pending_requests: None,
            upstream_id: None,
            upstream_subset: None,
            api_spec_id: None,
            circuit_breaker: None,
            retry: None,
            response_body_mode: Default::default(),
            listen_port: None,
            frontend_tls: false,
            passthrough: false,
            udp_idle_timeout_seconds: 60,
            udp_max_response_amplification_factor: None,
            stream_proxy_protocol: None,
            tcp_idle_timeout_seconds: None,
            websocket_idle_timeout_seconds: None,
            allowed_methods: None,
            allowed_ws_origins: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn builder_for<'a>(
        proxy: &'a Proxy,
        global_ca: Option<&'a Path>,
        global_no_verify: bool,
        global_client_cert: Option<&'a Path>,
        global_client_key: Option<&'a Path>,
        crls: &'a [CertificateRevocationListDer<'static>],
    ) -> BackendTlsConfigBuilder<'a> {
        BackendTlsConfigBuilder {
            proxy,
            policy: None,
            global_ca,
            global_no_verify,
            global_client_cert,
            global_client_key,
            crls,
        }
    }

    #[test]
    fn backend_tls_server_name_defaults_to_connect_host() {
        let tls = BackendTlsConfig::default_verify();
        assert_eq!(
            backend_tls_server_name(&tls, "connect.mesh.internal"),
            "connect.mesh.internal"
        );
    }

    #[test]
    fn backend_tls_server_name_honors_sni_override() {
        let mut tls = BackendTlsConfig::default_verify();
        tls.sni = Some("service.mesh.internal".to_string());
        assert_eq!(
            backend_tls_server_name(&tls, "connect.mesh.internal"),
            "service.mesh.internal"
        );
    }

    #[test]
    fn backend_tls_server_name_owned_honors_sni_override() {
        let mut tls = BackendTlsConfig::default_verify();
        tls.sni = Some("service.mesh.internal".to_string());
        let server_name = backend_tls_server_name_owned(&tls, "connect.mesh.internal").unwrap();

        assert_eq!(server_name.to_str(), "service.mesh.internal");
    }

    fn verify_backend_server_cert(
        verifier: &BackendServerVerifier,
        cert: &CertificateDer<'_>,
        server_name: &str,
    ) -> Result<ServerCertVerified, RustlsError> {
        let server_name = rustls::pki_types::ServerName::try_from(server_name).unwrap();
        match verifier {
            BackendServerVerifier::WebPki(verifier) => {
                verifier.verify_server_cert(cert, &[], &server_name, &[], UnixTime::now())
            }
            BackendServerVerifier::SanAllowList(verifier) => {
                verifier.verify_server_cert(cert, &[], &server_name, &[], UnixTime::now())
            }
        }
    }

    fn new_test_client_config() -> rustls::ClientConfig {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("default protocol versions")
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth()
    }

    fn quic_incompatible_policy() -> TlsPolicy {
        let base_provider = rustls::crypto::ring::default_provider();
        let provider = rustls::crypto::CryptoProvider {
            cipher_suites: vec![
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            ],
            kx_groups: vec![rustls::crypto::ring::kx_group::X25519],
            ..base_provider
        };

        TlsPolicy {
            protocol_versions: vec![&rustls::version::TLS13],
            crypto_provider: Arc::new(provider),
            prefer_server_cipher_order: false,
            session_cache_size: 4096,
            early_data_max_size: 0,
        }
    }

    fn tagged_test_key(base: &str, generation: Option<u64>) -> String {
        let mut key = base.to_string();
        append_backend_svid_generation_key_field(&mut key, generation);
        key
    }

    #[test]
    fn backend_tls_config_cache_reuses_built_configs() {
        ensure_crypto_provider();
        let cache = BackendTlsConfigCache::new();
        let builds = AtomicUsize::new(0);
        let key = tagged_test_key("backend-a", None);

        let first = cache
            .get_or_try_build(key.clone(), || {
                builds.fetch_add(1, Ordering::Relaxed);
                Ok::<_, TlsError>(new_test_client_config())
            })
            .expect("first config");
        let second = cache
            .get_or_try_build(key, || {
                builds.fetch_add(1, Ordering::Relaxed);
                Ok::<_, TlsError>(new_test_client_config())
            })
            .expect("second config");

        assert_eq!(builds.load(Ordering::Relaxed), 1);
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn backend_tls_config_cache_rebuilds_after_svid_generation_changes() {
        ensure_crypto_provider();
        let cache = BackendTlsConfigCache::with_shards(64);
        let builds = AtomicUsize::new(0);

        let first = cache
            .get_or_try_build(tagged_test_key("backend-a", Some(0)), || {
                builds.fetch_add(1, Ordering::Relaxed);
                Ok::<_, TlsError>(new_test_client_config())
            })
            .expect("first config");
        let same_generation = cache
            .get_or_try_build(tagged_test_key("backend-a", Some(0)), || {
                builds.fetch_add(1, Ordering::Relaxed);
                Ok::<_, TlsError>(new_test_client_config())
            })
            .expect("same generation config");

        let rotated = cache
            .get_or_try_build(tagged_test_key("backend-a", Some(1)), || {
                builds.fetch_add(1, Ordering::Relaxed);
                Ok::<_, TlsError>(new_test_client_config())
            })
            .expect("rotated config");

        assert_eq!(builds.load(Ordering::Relaxed), 2);
        assert!(Arc::ptr_eq(&first, &same_generation));
        assert!(!Arc::ptr_eq(&first, &rotated));
    }

    #[test]
    fn svid_generation_matcher_anchors_segment_to_end_or_shard() {
        let matcher = SvidGenerationMatcher::new(42);

        assert!(matcher.matches("backend|443|some|fields|svidg=42"));
        assert!(matcher.matches("backend|443|some|fields|svidg=42#0"));
        assert!(matcher.matches("backend|443|some|fields|svidg=42#7"));

        // Different generation: no false positive.
        assert!(!matcher.matches("backend|443|some|fields|svidg=4"));
        assert!(!matcher.matches("backend|443|some|fields|svidg=420"));
        assert!(!matcher.matches("backend|443|some|fields|svidg=static"));

        // Embedded but not anchored at end-or-shard: no false positive.
        assert!(!matcher.matches("backend|443|svidg=42|some|fields|svidg=static"));
    }

    #[test]
    fn backend_tls_pool_key_fields_include_svid_generation() {
        let mut key = String::from("backend|443|");
        append_backend_tls_pool_key_fields(
            &mut key,
            &BackendTlsConfig::default(),
            None,
            None,
            true,
            Some(42),
        );

        assert!(key.ends_with("|svidg=42"));
        assert!(backend_tls_pool_key_has_svid_generation(&key, 42));
        assert!(!backend_tls_pool_key_has_svid_generation(&key, 41));
    }

    #[test]
    fn backend_tls_pool_key_fields_keep_static_client_material_static() {
        let mut key = String::from("backend|443|");
        append_backend_tls_pool_key_fields(
            &mut key,
            &BackendTlsConfig::default(),
            Some("/operator/client.pem"),
            Some("/operator/client.key"),
            true,
            None,
        );

        assert!(key.ends_with("|svidg=static"));
        assert!(!backend_tls_pool_key_has_svid_generation(&key, 0));
    }

    #[test]
    fn backend_tls_pool_key_fields_escape_reserved_components() {
        let mut tls = BackendTlsConfig {
            server_ca_cert_path: Some("/ca|with|pipes".to_string()),
            sni: Some("backend#blue%canary.example.com".to_string()),
            ..Default::default()
        };
        tls.recompute_san_digest();

        let mut key = String::from("backend|443|");
        append_backend_tls_pool_key_fields(
            &mut key,
            &tls,
            Some("/client|svidg=42#cert.pem"),
            Some("/client%key.pem"),
            true,
            Some(7),
        );

        assert!(key.contains("/ca%7Cwith%7Cpipes"), "{key}");
        assert!(key.contains("backend%23blue%25canary.example.com"), "{key}");
        assert!(key.contains("/client%7Csvidg=42%23cert.pem"), "{key}");
        assert!(key.contains("/client%25key.pem"), "{key}");
        assert!(backend_tls_pool_key_has_svid_generation(&key, 7));
        assert!(
            !backend_tls_pool_key_has_svid_generation(&key, 42),
            "escaped client cert path must not look like an SVID generation marker: {key}"
        );
    }

    #[test]
    fn backend_tls_pool_key_fields_hash_inline_material() {
        let inline_ca = "-----BEGIN CERTIFICATE-----\nsecret-ca\n-----END CERTIFICATE-----\n";
        let inline_cert = "-----BEGIN CERTIFICATE-----\nsecret-client\n-----END CERTIFICATE-----\n";
        let inline_key = "-----BEGIN PRIVATE KEY-----\nsecret-key\n-----END PRIVATE KEY-----\n";
        let mut tls = BackendTlsConfig {
            server_ca_cert_path: Some(inline_ca.to_string()),
            ..Default::default()
        };
        tls.recompute_san_digest();

        let mut key = String::from("backend|443|");
        append_backend_tls_pool_key_fields(
            &mut key,
            &tls,
            Some(inline_cert),
            Some(inline_key),
            true,
            None,
        );

        assert!(key.contains("inline-pem:sha256:"), "{key}");
        assert!(!key.contains("BEGIN"), "{key}");
        assert!(!key.contains("secret"), "{key}");
    }

    #[test]
    fn build_root_cert_store_prefers_proxy_ca_exclusively() {
        let dir = TempDir::new().unwrap();
        let proxy_ca = generate_ca("Proxy CA");
        let global_ca_a = generate_ca("Global CA A");
        let global_ca_b = generate_ca("Global CA B");
        let proxy_path = write_file(&dir, "proxy-ca.pem", &proxy_ca.cert_pem);
        let global_path = write_file(
            &dir,
            "global-ca.pem",
            &(global_ca_a.cert_pem.clone() + &global_ca_b.cert_pem),
        );

        let store =
            build_root_cert_store(Some(&proxy_path), Some(&global_path)).expect("root store");

        assert_eq!(store.roots.len(), 1);
    }

    #[test]
    fn build_root_cert_store_uses_global_ca_when_proxy_ca_is_absent() {
        let dir = TempDir::new().unwrap();
        let global_ca_a = generate_ca("Global CA A");
        let global_ca_b = generate_ca("Global CA B");
        let global_path = write_file(
            &dir,
            "global-ca.pem",
            &(global_ca_a.cert_pem.clone() + &global_ca_b.cert_pem),
        );

        let store = build_root_cert_store(None, Some(&global_path)).expect("root store");

        assert_eq!(store.roots.len(), 2);
    }

    #[test]
    fn build_root_cert_store_falls_back_to_webpki_roots() {
        let store = build_root_cert_store(None, None).expect("root store");
        assert_eq!(store.roots.len(), webpki_roots::TLS_SERVER_ROOTS.len());
    }

    #[test]
    fn build_rustls_requires_client_cert_and_key_as_a_pair() {
        let dir = TempDir::new().unwrap();
        let ca = generate_ca("CA");
        let client = generate_signed_cert(&ca, "client", &["localhost"]);
        let cert_path = write_file(&dir, "client.crt", &client.cert_pem);
        let key_path = write_file(&dir, "client.key", &client.key_pem);

        let mut proxy = test_proxy();
        proxy.resolved_tls.client_cert_path = Some(cert_path.display().to_string());

        let err = builder_for(&proxy, None, false, None, None, &[])
            .build_rustls()
            .unwrap_err();
        assert!(matches!(err, TlsError::Pem { .. }));

        proxy.resolved_tls.client_cert_path = None;
        proxy.resolved_tls.client_key_path = Some(key_path.display().to_string());

        let err = builder_for(&proxy, None, false, None, None, &[])
            .build_rustls()
            .unwrap_err();
        assert!(matches!(err, TlsError::Pem { .. }));
    }

    #[test]
    fn build_rustls_for_reqwest_restricts_alpn_to_http1_under_do_not_upgrade() {
        use crate::config::types::H2UpgradePolicy;
        ensure_crypto_provider();

        // codex round-1 Finding 1: a `DO_NOT_UPGRADE` proxy's reqwest rustls
        // config must advertise ONLY `http/1.1` so a TLS backend cannot
        // ALPN-negotiate h2. The default (probe-driven) config leaves ALPN
        // unrestricted (reqwest's preconfigured-rustls path uses it verbatim).
        let mut proxy = test_proxy();

        // Default proxy: ALPN not restricted to http/1.1-only.
        let default_cfg = builder_for(&proxy, None, false, None, None, &[])
            .build_rustls_for_reqwest(true)
            .expect("build default reqwest rustls config");
        assert_ne!(
            default_cfg.alpn_protocols,
            vec![b"http/1.1".to_vec()],
            "default proxy must NOT be force-restricted to http/1.1 ALPN"
        );

        // DO_NOT_UPGRADE proxy: ALPN restricted to http/1.1 only.
        proxy.h2_upgrade_policy = Some(H2UpgradePolicy::DoNotUpgrade);
        let force_h1_cfg = builder_for(&proxy, None, false, None, None, &[])
            .build_rustls_for_reqwest(true)
            .expect("build force-H1 reqwest rustls config");
        assert_eq!(
            force_h1_cfg.alpn_protocols,
            vec![b"http/1.1".to_vec()],
            "DO_NOT_UPGRADE must restrict reqwest ALPN to http/1.1 so the \
             backend cannot ALPN-negotiate h2"
        );

        // Upgrade / Default are probe-driven — not force-restricted.
        for probe_driven in [H2UpgradePolicy::Upgrade, H2UpgradePolicy::Default] {
            proxy.h2_upgrade_policy = Some(probe_driven);
            let cfg = builder_for(&proxy, None, false, None, None, &[])
                .build_rustls_for_reqwest(true)
                .expect("build probe-driven reqwest rustls config");
            assert_ne!(
                cfg.alpn_protocols,
                vec![b"http/1.1".to_vec()],
                "{probe_driven:?} must not force http/1.1-only ALPN"
            );
        }

        // Resolved `pool_enable_http2=false`: reqwest is also force-H1, even
        // without a DestinationRule h2UpgradePolicy override.
        proxy.h2_upgrade_policy = None;
        let disabled_h2_cfg = builder_for(&proxy, None, false, None, None, &[])
            .build_rustls_for_reqwest(false)
            .expect("build backend-H2-disabled reqwest rustls config");
        assert_eq!(
            disabled_h2_cfg.alpn_protocols,
            vec![b"http/1.1".to_vec()],
            "pool_enable_http2=false must restrict reqwest ALPN to http/1.1"
        );
    }

    #[test]
    fn build_rustls_skips_ca_loading_when_proxy_disables_verification() {
        ensure_crypto_provider();
        let mut proxy = test_proxy();
        proxy.resolved_tls.server_ca_cert_path = Some("/does/not/exist.pem".to_string());
        proxy.resolved_tls.verify_server_cert = false;

        builder_for(&proxy, None, false, None, None, &[])
            .build_rustls()
            .expect("skip-verify should bypass CA loading");
    }

    #[test]
    fn build_rustls_skips_ca_loading_when_global_no_verify_is_enabled() {
        ensure_crypto_provider();
        let mut proxy = test_proxy();
        proxy.resolved_tls.server_ca_cert_path = Some("/does/not/exist.pem".to_string());

        builder_for(&proxy, None, true, None, None, &[])
            .build_rustls()
            .expect("global no-verify should bypass CA loading");
    }

    #[test]
    fn build_rustls_quic_skips_ca_loading_when_verification_is_disabled() {
        ensure_crypto_provider();
        let mut proxy = test_proxy();
        proxy.resolved_tls.server_ca_cert_path = Some("/does/not/exist.pem".to_string());
        proxy.resolved_tls.verify_server_cert = false;

        builder_for(&proxy, None, false, None, None, &[])
            .build_rustls_quic()
            .expect("HTTP/3 skip-verify should bypass CA loading");
    }

    #[test]
    fn build_rustls_quic_falls_back_when_tls_policy_is_quic_incompatible() {
        ensure_crypto_provider();
        let proxy = test_proxy();
        let policy = quic_incompatible_policy();
        let mut builder = builder_for(&proxy, None, false, None, None, &[]);
        builder.policy = Some(&policy);

        builder
            .build_rustls_quic()
            .expect("HTTP/3 should fall back to safe defaults when TLS policy is incompatible");
    }

    #[test]
    fn build_rustls_still_errors_when_tls_policy_is_incompatible() {
        ensure_crypto_provider();
        let proxy = test_proxy();
        let policy = quic_incompatible_policy();
        let mut builder = builder_for(&proxy, None, false, None, None, &[]);
        builder.policy = Some(&policy);

        let err = builder.build_rustls().unwrap_err();

        assert!(
            matches!(err, TlsError::Rustls(message) if message.contains("Failed to apply backend TLS policy"))
        );
    }

    #[test]
    fn build_server_verifier_rejects_revoked_end_entity_cert() {
        ensure_crypto_provider();
        let dir = TempDir::new().unwrap();
        let ca = generate_ca("Revoking CA");
        let leaf = generate_signed_cert(&ca, "localhost", &["localhost"]);
        let ca_path = write_file(&dir, "ca.pem", &ca.cert_pem);
        let crl_path = write_file(&dir, "revoked.crl", &generate_crl_pem(&ca, &[leaf.serial]));
        let crls = parse_crls(&fs::read_to_string(crl_path).unwrap());

        let mut proxy = test_proxy();
        proxy.resolved_tls.server_ca_cert_path = Some(ca_path.display().to_string());
        let verifier = builder_for(&proxy, None, false, None, None, &crls)
            .build_server_verifier()
            .expect("verifier");

        let result = verify_backend_server_cert(&verifier, &leaf.cert_der, "localhost");
        assert!(result.is_err());
    }

    #[test]
    fn build_server_verifier_allows_unknown_revocation_status() {
        ensure_crypto_provider();
        let dir = TempDir::new().unwrap();
        let trusted_ca = generate_ca("Trusted CA");
        let unrelated_crl_ca = generate_ca("CRL CA");
        let leaf = generate_signed_cert(&trusted_ca, "localhost", &["localhost"]);
        let ca_path = write_file(&dir, "ca.pem", &trusted_ca.cert_pem);
        let crl_path = write_file(
            &dir,
            "unrelated.crl",
            &generate_crl_pem(&unrelated_crl_ca, &[SerialNumber::from(99u64)]),
        );
        let crls = parse_crls(&fs::read_to_string(crl_path).unwrap());

        let mut proxy = test_proxy();
        proxy.resolved_tls.server_ca_cert_path = Some(ca_path.display().to_string());
        let verifier = builder_for(&proxy, None, false, None, None, &crls)
            .build_server_verifier()
            .expect("verifier");

        verify_backend_server_cert(&verifier, &leaf.cert_der, "localhost")
            .expect("unrelated CRL should not reject trusted cert");
    }

    #[test]
    fn build_server_verifier_uses_plain_webpki_when_san_allow_list_empty() {
        ensure_crypto_provider();
        let proxy = test_proxy();
        let verifier = builder_for(&proxy, None, false, None, None, &[])
            .build_server_verifier()
            .expect("verifier");

        assert!(matches!(verifier, BackendServerVerifier::WebPki(_)));
    }

    #[test]
    fn build_server_verifier_wraps_when_san_allow_list_configured() {
        ensure_crypto_provider();
        let mut proxy = test_proxy();
        proxy.resolved_tls.san_allow_list = vec!["localhost".to_string()];
        proxy.resolved_tls.recompute_san_digest();

        let verifier = builder_for(&proxy, None, false, None, None, &[])
            .build_server_verifier()
            .expect("verifier");

        assert!(matches!(verifier, BackendServerVerifier::SanAllowList(_)));
    }

    #[test]
    fn san_allow_list_rejects_certificate_without_san_extension() {
        let ca = generate_ca("No SAN CA");
        let leaf = generate_signed_cert(&ca, "localhost", &[]);
        let allowed_sans = vec![SanAllowListEntry::Dns("localhost".to_string())];

        let err = certificate_matches_allowed_sans(&leaf.cert_der, &allowed_sans)
            .expect_err("missing SAN extension should reject");

        assert!(
            format!("{err:?}").contains("no SAN extension"),
            "expected missing SAN extension rejection, got {err:?}"
        );
    }

    #[test]
    fn build_rustls_errors_when_client_cert_file_disappears() {
        let dir = TempDir::new().unwrap();
        let ca = generate_ca("Client CA");
        let client = generate_signed_cert(&ca, "client", &["localhost"]);
        let missing_cert = dir.path().join("missing-client.crt");
        let key_path = write_file(&dir, "client.key", &client.key_pem);

        let mut proxy = test_proxy();
        proxy.resolved_tls.client_cert_path = Some(missing_cert.display().to_string());
        proxy.resolved_tls.client_key_path = Some(key_path.display().to_string());
        proxy.resolved_tls.verify_server_cert = false;

        let err = builder_for(&proxy, None, false, None, None, &[])
            .build_rustls()
            .unwrap_err();
        assert!(matches!(err, TlsError::Io { .. }));
    }

    #[cfg(not(feature = "pkcs11"))]
    #[test]
    fn build_rustls_rejects_pkcs11_client_key_without_feature() {
        ensure_crypto_provider();
        let dir = TempDir::new().unwrap();
        let ca = generate_ca("Client CA");
        let client = generate_signed_cert(&ca, "client", &["localhost"]);
        let cert_path = write_file(&dir, "client.crt", &client.cert_pem);

        let mut proxy = test_proxy();
        proxy.resolved_tls.client_cert_path = Some(cert_path.display().to_string());
        proxy.resolved_tls.client_key_path =
            Some("pkcs11://edge-rsa?module=/usr/lib/pkcs11.so".to_string());
        proxy.resolved_tls.verify_server_cert = false;

        let err = builder_for(&proxy, None, false, None, None, &[])
            .build_rustls()
            .unwrap_err();

        assert!(
            matches!(err, TlsError::Rustls(message) if message.contains("'pkcs11' Cargo feature"))
        );
    }

    #[test]
    fn build_reqwest_uses_preconfigured_tls_with_custom_ca() {
        let dir = TempDir::new().unwrap();
        let ca = generate_ca("Reqwest CA");
        let ca_path = write_file(&dir, "ca.pem", &ca.cert_pem);

        let mut proxy = test_proxy();
        proxy.resolved_tls.server_ca_cert_path = Some(ca_path.display().to_string());

        let _ = builder_for(&proxy, None, false, None, None, &[])
            .build_reqwest()
            .expect("reqwest builder");
    }
}
