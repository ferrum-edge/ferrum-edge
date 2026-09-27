//! Gateway-owned diagnostic references (issue #5767).
//!
//! `X-Gateway-Error` is a closed, coarse, eight-token public vocabulary: one
//! token (`connection_failure`, say) covers DNS, TCP, TLS, pool, and egress
//! policy failures, and the precise `error_class` behind it reaches only the
//! operator's logs. This module adds an additive, opt-in bridge between the
//! two without widening the public surface:
//!
//! * With `FERRUM_DIAGNOSTIC_REFS=errors`, every HTTP-family response that
//!   carries the gateway's own `X-Gateway-Error` token (HTTP/1.1, HTTP/2, and
//!   HTTP/3) also carries `X-Ferrum-Diagnostic-Ref: fd1_<32 lowercase hex>`.
//!   The reference is 128 bits read from the process CSPRNG and embeds
//!   nothing: no cause, route, backend, tenant, time, or counter.
//! * With `FERRUM_DIAGNOSTIC_REFS=all` (issue #5846), every gateway-authored
//!   error response carries one as well: the `errors` set, plus the plugin
//!   rejections (`401`/`403`/`429`, ...), gateway policy fences, and routing
//!   `404`s that carry no `X-Gateway-Error`. A response is gateway-authored only
//!   when a rejection site recorded it in the request's slot; a backend's own
//!   `4xx`/`5xx` relayed to the client never carries a reference.
//! * The detail behind a reference lives only in this process, in a bounded,
//!   TTL-limited, sharded in-memory store ([`DiagnosticRefStore`]). It is
//!   readable only through the authenticated admin lookup
//!   `GET /diagnostics/v1/refs/{ref}`, which requires an admin JWT carrying the
//!   `diagnostics:read` scope and an `ns` claim; a reference outside the
//!   token's namespaces is indistinguishable from an unknown one (`404`).
//! * The header is gateway-owned: a backend (or serverless function) copy is
//!   stripped at every backend response boundary through
//!   `proxy::headers::GATEWAY_OWNED_DIAGNOSTIC_RESPONSE_HEADERS`, and the final
//!   client boundary strips any copy a plugin or hook left, whatever
//!   `FERRUM_DIAGNOSTIC_REFS` says, before an enabled store writes its own, so
//!   a client never sees a reference the gateway did not mint.
//!
//! The lookup detail also names the rejecting policy (phase and, when known,
//! plugin) and every backend attempt the request made (at most
//! [`MAX_RECORDED_ATTEMPTS`]), each with its dispatch outcome, closed
//! `error_class`, and, for a TLS failure, the closed TLS alert or certificate
//! verification reason. Everything in it is a compiled-in label or operator
//! configuration.
//!
//! Hot-path cost: with the default `off`, one `OnceLock` load per HTTP-family
//! request and one header-map removal per response head; every recording site
//! is an `Option` check on the request's absent slot. When enabled, one `Arc`
//! slot per request, and only on a response that gets a reference, one CSPRNG
//! read and one short critical section on one of [`SHARD_COUNT`] shard
//! mutexes. Detail is copied into the slot from the terminal transaction
//! summary, and only for a summary that can carry `X-Gateway-Error` (5xx or a
//! classified dispatch error) or, in `all` mode, a recorded gateway rejection.
//! Each backend attempt takes one uncontended per-request mutex.

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::hash::BuildHasher;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;

use crate::fips::backend::rand::{SecureRandom, SystemRandom};
use crate::plugins::TransactionSummary;
use crate::util::atomic_log_rate_limiter::AtomicLogRateLimiter;

/// Wire name of the gateway-owned diagnostic reference response header.
pub const DIAGNOSTIC_REF_HEADER: &str = "x-ferrum-diagnostic-ref";

/// [`DIAGNOSTIC_REF_HEADER`] as a pre-built `HeaderName`, so stripping and
/// stamping never re-parse the field name. A `static` rather than a `const`:
/// the custom name holds a `Bytes`, and a `const` would be an
/// interior-mutable constant copied at every use.
static DIAGNOSTIC_REF_HEADER_NAME: http::HeaderName =
    http::HeaderName::from_static(DIAGNOSTIC_REF_HEADER);

/// Version prefix of every reference. A future format changes the prefix.
pub const DIAGNOSTIC_REF_PREFIX: &str = "fd1_";

/// Random bytes behind one reference (128 bits).
const DIAGNOSTIC_REF_RANDOM_BYTES: usize = 16;

/// Lowercase hex digits encoding those bytes.
const DIAGNOSTIC_REF_HEX_LEN: usize = DIAGNOSTIC_REF_RANDOM_BYTES * 2;

/// Exact length of a well-formed reference: the prefix plus 32 hex digits.
pub const DIAGNOSTIC_REF_LEN: usize = DIAGNOSTIC_REF_PREFIX.len() + DIAGNOSTIC_REF_HEX_LEN;

/// Admin JWT `scope` value that authorizes a diagnostic reference lookup.
pub const DIAGNOSTICS_READ_SCOPE: &str = "diagnostics:read";

/// `schema_version` of the lookup response body.
pub const DIAGNOSTIC_REF_SCHEMA_VERSION: &str = "ferrum.diagnostic_ref.v1";

/// Default reference lifetime (`FERRUM_DIAGNOSTIC_REF_TTL_SECONDS`).
pub const DEFAULT_TTL_SECONDS: u64 = 900;
/// Lower clamp for `FERRUM_DIAGNOSTIC_REF_TTL_SECONDS`.
pub const MIN_TTL_SECONDS: u64 = 1;
/// Upper clamp for `FERRUM_DIAGNOSTIC_REF_TTL_SECONDS` (one day).
pub const MAX_TTL_SECONDS: u64 = 86_400;

/// Default retained-reference ceiling (`FERRUM_DIAGNOSTIC_REF_MAX_ENTRIES`).
pub const DEFAULT_MAX_ENTRIES: usize = 10_000;
/// Lower clamp for `FERRUM_DIAGNOSTIC_REF_MAX_ENTRIES`: one entry per shard.
pub const MIN_MAX_ENTRIES: usize = SHARD_COUNT;
/// Upper clamp for `FERRUM_DIAGNOSTIC_REF_MAX_ENTRIES`.
pub const MAX_MAX_ENTRIES: usize = 1_000_000;

/// Default admin lookup budget
/// (`FERRUM_DIAGNOSTIC_REF_LOOKUP_RATE_PER_SECOND`).
pub const DEFAULT_LOOKUP_RATE_PER_SECOND: u32 = 10;
/// Lower clamp for `FERRUM_DIAGNOSTIC_REF_LOOKUP_RATE_PER_SECOND`.
pub const MIN_LOOKUP_RATE_PER_SECOND: u32 = 1;
/// Upper clamp for `FERRUM_DIAGNOSTIC_REF_LOOKUP_RATE_PER_SECOND`.
pub const MAX_LOOKUP_RATE_PER_SECOND: u32 = 10_000;

/// Most distinct JWT subjects the per-subject lookup budget tracks within one
/// one-second window. Subjects from earlier windows are purged when the table
/// fills; a new subject that still finds it full is refused (`429`) rather
/// than evicting a live subject's budget, so the table can never be used to
/// reset another caller's count.
pub const MAX_TRACKED_LOOKUP_SUBJECTS: usize = 4_096;

/// Number of independently locked store shards. The first random byte of a
/// reference selects its shard, so load spreads uniformly and one shard's
/// critical section never serializes the others.
pub const SHARD_COUNT: usize = 16;

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Most backend attempts one reference's detail lists. Later attempts are
/// counted in `attempts_omitted` instead, so the detail stays bounded however
/// many retries a route allows.
pub const MAX_RECORDED_ATTEMPTS: usize = 8;

/// Longest rejection phase or plugin name the detail records. A longer or
/// non-label value is recorded as `other` (phase) or dropped (plugin).
pub const MAX_REJECTION_LABEL_LEN: usize = 64;

/// Rejection phase of a request that matched no route (`404`).
pub const ROUTE_NOT_FOUND_PHASE: &str = "route_not_found";

/// Rejection phase of an outbound route miss refused by the mesh
/// `REGISTRY_ONLY` policy.
pub const MESH_REGISTRY_ONLY_PHASE: &str = "mesh_registry_only";

/// Plugin hook phases. A rejection recorded in one of them is a plugin
/// rejection even when the rejecting plugin's name is not known.
const PLUGIN_HOOK_PHASES: [&str; 7] = [
    "on_request_received",
    "authenticate",
    "authorize",
    "before_proxy",
    "on_backend_path_resolved",
    "on_final_request_body",
    "after_proxy",
];

const MODE_PARSE_ERROR: &str = "FERRUM_DIAGNOSTIC_REFS must be `off`, `errors`, or `all`";

/// `FERRUM_DIAGNOSTIC_REFS`: which gateway responses carry a reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiagnosticRefMode {
    /// No references are minted and no store is allocated (default).
    #[default]
    Off,
    /// Responses carrying the gateway's own `X-Gateway-Error` token.
    Errors,
    /// The `errors` set plus every other gateway-authored error response:
    /// plugin rejections, gateway policy fences, and routing `404`s.
    All,
}

impl DiagnosticRefMode {
    /// Parse a configured value. Unknown values fail closed at startup rather
    /// than silently disabling (or widening) the feature.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "errors" => Ok(Self::Errors),
            "all" => Ok(Self::All),
            _ => Err(MODE_PARSE_ERROR.to_string()),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Errors => "errors",
            Self::All => "all",
        }
    }

    pub fn is_enabled(self) -> bool {
        !matches!(self, Self::Off)
    }

    /// Whether gateway-authored error responses without an `X-Gateway-Error`
    /// token also carry a reference (`all`).
    pub fn covers_gateway_rejections(self) -> bool {
        matches!(self, Self::All)
    }
}

/// Client-facing protocol of the response a reference was minted on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticProtocol {
    Http1,
    Http2,
    Http3,
}

impl DiagnosticProtocol {
    /// HTTP/2 and HTTP/3 map to themselves; every HTTP/1.x version is `http1`.
    pub fn from_http_version(version: http::Version) -> Self {
        if version == http::Version::HTTP_2 {
            Self::Http2
        } else if version == http::Version::HTTP_3 {
            Self::Http3
        } else {
            Self::Http1
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http1 => "http1",
            Self::Http2 => "http2",
            Self::Http3 => "http3",
        }
    }
}

/// Bounds of one [`DiagnosticRefStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagnosticRefStoreConfig {
    pub ttl: Duration,
    pub max_entries: usize,
    pub lookup_rate_per_second: u32,
}

impl Default for DiagnosticRefStoreConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(DEFAULT_TTL_SECONDS),
            max_entries: DEFAULT_MAX_ENTRIES,
            lookup_rate_per_second: DEFAULT_LOOKUP_RATE_PER_SECOND,
        }
    }
}

/// Operator-only detail behind a reference, copied from the request's
/// terminal transaction summary.
///
/// Every string-typed field is either a closed compiled-in vocabulary
/// (`&'static str`) or operator configuration (`proxy_id`, and the backend
/// origin reduced to `scheme://host:port`). Request and response bodies,
/// headers, paths, query strings, credentials, client addresses, and raw error
/// text are never recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiagnosticDetail {
    /// Granular `error_class` of the backend dispatch, as the access log names
    /// it (`dns_lookup_error`, `connection_refused`, `tls_error`, ...).
    pub error_class: Option<&'static str>,
    /// Classification of a failure while streaming the response body.
    pub body_error_class: Option<&'static str>,
    /// Gateway rejection phase (`overload`, `circuit_breaker_open`,
    /// `adaptive_concurrency` reads `concurrency_limit`, `config_stale`).
    pub rejection_phase: Option<&'static str>,
    /// Phase of a route rule's total request deadline that produced a
    /// gateway-authored `504` (`before_dispatch`, `dispatch`,
    /// `retry_backoff`).
    pub route_timeout_phase: Option<&'static str>,
    /// Whether and how far the request reached a backend: `not_dispatched`,
    /// `pre_wire_failure`, `ambiguous_failure`, or `backend_response`.
    pub backend_dispatch: &'static str,
    /// ID of the matched proxy, when routing matched one.
    pub proxy_id: Option<String>,
    /// Backend origin (`scheme://host:port`) the request was dispatched to.
    /// Userinfo, path, query, and fragment are removed.
    pub backend_target: Option<String>,
    /// Coarse total-duration bucket (`lt_10ms` .. `ge_10s`, or `unknown`).
    pub duration_bucket: &'static str,
    /// The gateway policy or plugin that rejected the request, when one did.
    /// Absent for a backend dispatch outcome.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection: Option<DiagnosticRejection>,
    /// Every backend attempt the request made, in order, up to
    /// [`MAX_RECORDED_ATTEMPTS`]. Absent when no backend was attempted.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attempts: Vec<DiagnosticAttempt>,
    /// Attempts made beyond [`MAX_RECORDED_ATTEMPTS`]. Absent when zero.
    #[serde(skip_serializing_if = "is_zero")]
    pub attempts_omitted: u32,
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

impl DiagnosticDetail {
    /// Build the detail from a terminal transaction summary plus the two
    /// request-context facts the summary does not carry.
    pub fn from_summary(
        summary: &TransactionSummary,
        backend_dispatch: &'static str,
        route_timeout_phase: Option<&'static str>,
    ) -> Self {
        Self {
            error_class: crate::retry::http_log_error_class(summary.error_class),
            body_error_class: summary.body_error_class.map(|class| class.as_str()),
            rejection_phase: summary
                .rejection_phase()
                .and_then(crate::retry::token_for_rejection_phase),
            route_timeout_phase,
            backend_dispatch,
            proxy_id: summary.proxy_id.clone(),
            backend_target: summary.backend_target.as_deref().and_then(backend_origin),
            duration_bucket: duration_bucket(summary.latency_total_ms),
            rejection: None,
            attempts: Vec::new(),
            attempts_omitted: 0,
        }
    }

    /// Detail of a gateway rejection answered before routing matched a proxy
    /// (a routing `404`, an admission fence): nothing was dispatched and no
    /// proxy or backend is known.
    pub fn unrouted(latency_ms: f64) -> Self {
        Self {
            error_class: None,
            body_error_class: None,
            rejection_phase: None,
            route_timeout_phase: None,
            backend_dispatch: "not_dispatched",
            proxy_id: None,
            backend_target: None,
            duration_bucket: duration_bucket(latency_ms),
            rejection: None,
            attempts: Vec::new(),
            attempts_omitted: 0,
        }
    }
}

/// Who authored a gateway rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticRejectionSource {
    /// A plugin hook rejected the request (authentication, authorization,
    /// rate limiting, request validation, ...).
    Plugin,
    /// A gateway policy fence rejected the request (allowed methods,
    /// connection limits, circuit breaker, admission fences, ...).
    Gateway,
    /// No route matched the request.
    Routing,
}

/// The policy that rejected a request. `phase` is a compiled-in phase or
/// policy label and `plugin` the rejecting plugin's type name; neither is
/// request material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiagnosticRejection {
    pub source: DiagnosticRejectionSource,
    /// Rejection phase or policy (`authenticate`, `authorize`, `before_proxy`,
    /// `allowed_methods`, `websocket_connection_limit`, `route_not_found`,
    /// ...). A value that is not a short label is recorded as `other`.
    pub phase: String,
    /// Name of the rejecting plugin, when the phase that rejected knows it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,
}

impl DiagnosticRejection {
    /// A rejection in `phase`, by `plugin` when known. A plugin hook phase or
    /// a known plugin makes it a plugin rejection; anything else is a gateway
    /// policy rejection.
    pub fn new(phase: &str, plugin: Option<&str>) -> Self {
        let plugin = plugin.and_then(bounded_label);
        let source = if plugin.is_some() || PLUGIN_HOOK_PHASES.contains(&phase) {
            DiagnosticRejectionSource::Plugin
        } else {
            DiagnosticRejectionSource::Gateway
        };
        Self {
            source,
            phase: bounded_label(phase).unwrap_or_else(|| "other".to_string()),
            plugin,
        }
    }

    /// A routing rejection (`route_not_found`, `mesh_registry_only`).
    pub fn routing(phase: &'static str) -> Self {
        Self {
            source: DiagnosticRejectionSource::Routing,
            phase: phase.to_string(),
            plugin: None,
        }
    }

    /// A gateway admission fence that answered before a request context
    /// existed.
    pub fn gateway_fence(phase: &'static str) -> Self {
        Self {
            source: DiagnosticRejectionSource::Gateway,
            phase: phase.to_string(),
            plugin: None,
        }
    }
}

/// `value` when it is a short identifier-like label, never free text.
fn bounded_label(value: &str) -> Option<String> {
    let is_label = !value.is_empty()
        && value.len() <= MAX_REJECTION_LABEL_LEN
        && value.bytes().all(is_label_byte);
    is_label.then(|| value.to_string())
}

fn is_label_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
}

/// One backend attempt of a request, in dispatch order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DiagnosticAttempt {
    /// 1-based attempt number (`1` is the first dispatch, `2` the first
    /// retry).
    pub attempt: u32,
    /// How far this attempt reached the backend: `backend_response`,
    /// `pre_wire_failure`, or `ambiguous_failure`.
    pub backend_dispatch: &'static str,
    /// The backend's HTTP status, when this attempt got a response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Granular `error_class` of a failed attempt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<&'static str>,
    /// TLS failure detail of a `tls_error` attempt, when the typed TLS error
    /// was available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<DiagnosticTlsDetail>,
}

/// Closed description of a backend TLS failure, taken from the typed rustls
/// error. Certificate contents, names, and times are never recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DiagnosticTlsDetail {
    /// `certificate_verification`, `alert_received`,
    /// `no_certificates_presented`, `peer_incompatible`, `peer_misbehaved`,
    /// `invalid_message`, `unexpected_message`, `decrypt_error`,
    /// `no_application_protocol`, `invalid_crl`, or `other`.
    pub failure: &'static str,
    /// The certificate verification reason (`expired`, `unknown_issuer`,
    /// `not_valid_for_name`, ...) or the received alert (`unknown_ca`,
    /// `handshake_failure`, ...). Absent for other failures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}

/// Closed TLS detail of the first rustls error in `err`'s source chain.
pub fn tls_detail(err: &(dyn std::error::Error + 'static)) -> Option<DiagnosticTlsDetail> {
    crate::retry::rustls_error_from_chain(err).map(tls_detail_from_rustls)
}

/// Closed TLS detail of one rustls error.
pub fn tls_detail_from_rustls(err: &rustls::Error) -> DiagnosticTlsDetail {
    let (failure, reason) = match err {
        rustls::Error::InvalidCertificate(cert) => (
            "certificate_verification",
            Some(certificate_error_label(cert)),
        ),
        rustls::Error::AlertReceived(alert) => ("alert_received", Some(alert_label(*alert))),
        rustls::Error::NoCertificatesPresented => ("no_certificates_presented", None),
        rustls::Error::PeerIncompatible(_) => ("peer_incompatible", None),
        rustls::Error::PeerMisbehaved(_) => ("peer_misbehaved", None),
        rustls::Error::InvalidMessage(_) => ("invalid_message", None),
        rustls::Error::InappropriateMessage { .. }
        | rustls::Error::InappropriateHandshakeMessage { .. } => ("unexpected_message", None),
        rustls::Error::DecryptError => ("decrypt_error", None),
        rustls::Error::NoApplicationProtocol => ("no_application_protocol", None),
        rustls::Error::InvalidCertRevocationList(_) => ("invalid_crl", None),
        _ => ("other", None),
    };
    DiagnosticTlsDetail { failure, reason }
}

fn certificate_error_label(err: &rustls::CertificateError) -> &'static str {
    use rustls::CertificateError;
    match err {
        CertificateError::BadEncoding => "bad_encoding",
        CertificateError::Expired | CertificateError::ExpiredContext { .. } => "expired",
        CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
            "not_valid_yet"
        }
        CertificateError::Revoked => "revoked",
        CertificateError::UnhandledCriticalExtension => "unhandled_critical_extension",
        CertificateError::UnknownIssuer => "unknown_issuer",
        CertificateError::UnknownRevocationStatus => "unknown_revocation_status",
        CertificateError::ExpiredRevocationList
        | CertificateError::ExpiredRevocationListContext { .. } => "expired_revocation_list",
        CertificateError::BadSignature => "bad_signature",
        CertificateError::UnsupportedSignatureAlgorithmContext { .. }
        | CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext { .. } => {
            "unsupported_signature_algorithm"
        }
        CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
            "not_valid_for_name"
        }
        CertificateError::InvalidPurpose | CertificateError::InvalidPurposeContext { .. } => {
            "invalid_purpose"
        }
        CertificateError::InvalidOcspResponse => "invalid_ocsp_response",
        CertificateError::ApplicationVerificationFailure => "application_verification_failure",
        _ => "other",
    }
}

fn alert_label(alert: rustls::AlertDescription) -> &'static str {
    use rustls::AlertDescription;
    match alert {
        AlertDescription::CloseNotify => "close_notify",
        AlertDescription::UnexpectedMessage => "unexpected_message",
        AlertDescription::BadRecordMac => "bad_record_mac",
        AlertDescription::RecordOverflow => "record_overflow",
        AlertDescription::HandshakeFailure => "handshake_failure",
        AlertDescription::BadCertificate => "bad_certificate",
        AlertDescription::UnsupportedCertificate => "unsupported_certificate",
        AlertDescription::CertificateRevoked => "certificate_revoked",
        AlertDescription::CertificateExpired => "certificate_expired",
        AlertDescription::CertificateUnknown => "certificate_unknown",
        AlertDescription::IllegalParameter => "illegal_parameter",
        AlertDescription::UnknownCA => "unknown_ca",
        AlertDescription::AccessDenied => "access_denied",
        AlertDescription::DecodeError => "decode_error",
        AlertDescription::DecryptError => "decrypt_error",
        AlertDescription::ProtocolVersion => "protocol_version",
        AlertDescription::InsufficientSecurity => "insufficient_security",
        AlertDescription::InternalError => "internal_error",
        AlertDescription::InappropriateFallback => "inappropriate_fallback",
        AlertDescription::UserCanceled => "user_canceled",
        AlertDescription::MissingExtension => "missing_extension",
        AlertDescription::UnsupportedExtension => "unsupported_extension",
        AlertDescription::UnrecognisedName => "unrecognized_name",
        AlertDescription::BadCertificateStatusResponse => "bad_certificate_status_response",
        AlertDescription::UnknownPSKIdentity => "unknown_psk_identity",
        AlertDescription::CertificateRequired => "certificate_required",
        AlertDescription::NoApplicationProtocol => "no_application_protocol",
        _ => "other",
    }
}

/// Reduce a transaction-summary backend target to its origin.
///
/// `scheme://[userinfo@]host[:port][/path][?query][#fragment]` becomes
/// `scheme://host:port`; a bare `host:port` is kept as is. Anything else
/// (an empty authority, an over-long value, a non-origin shape) is dropped
/// rather than echoed.
pub fn backend_origin(target: &str) -> Option<String> {
    const MAX_ORIGIN_LEN: usize = 300;
    let (scheme, authority) = match target.split_once("://") {
        Some((scheme, rest)) => {
            let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            (Some(scheme), &rest[..end])
        }
        None => (None, target),
    };
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host_port)| host_port);
    let host_port_ok = !host_port.is_empty()
        && host_port.len() <= MAX_ORIGIN_LEN
        && host_port.bytes().all(is_origin_authority_byte);
    if !host_port_ok {
        return None;
    }
    match scheme {
        Some(scheme) => {
            let scheme_ok = !scheme.is_empty()
                && scheme.len() <= 16
                && scheme.bytes().all(is_origin_scheme_byte);
            if !scheme_ok {
                return None;
            }
            Some(format!("{}://{}", scheme.to_ascii_lowercase(), host_port))
        }
        None => Some(host_port.to_string()),
    }
}

/// A byte an origin's `host:port` may carry: printable, non-space, and none
/// of the delimiters that would begin userinfo, a path, a query, or a
/// fragment.
fn is_origin_authority_byte(byte: u8) -> bool {
    byte.is_ascii_graphic() && !matches!(byte, b'/' | b'?' | b'#' | b'@')
}

/// RFC 3986 `scheme` characters after the first.
fn is_origin_scheme_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
}

/// Coarse bucket for a total request duration in milliseconds. A negative or
/// non-finite value (the summary's "unknown" sentinel) is `unknown`.
pub fn duration_bucket(latency_ms: f64) -> &'static str {
    if !latency_ms.is_finite() || latency_ms < 0.0 {
        "unknown"
    } else if latency_ms < 10.0 {
        "lt_10ms"
    } else if latency_ms < 100.0 {
        "lt_100ms"
    } else if latency_ms < 1_000.0 {
        "lt_1s"
    } else if latency_ms < 10_000.0 {
        "lt_10s"
    } else {
        "ge_10s"
    }
}

/// Closed label for a request's backend dispatch state.
pub(crate) fn backend_dispatch_label(state: crate::plugins::BackendDispatchState) -> &'static str {
    use crate::plugins::BackendDispatchState;
    match state {
        BackendDispatchState::NotDispatched => "not_dispatched",
        BackendDispatchState::BackendResponse => "backend_response",
        BackendDispatchState::PreWireFailure => "pre_wire_failure",
        BackendDispatchState::AmbiguousFailure => "ambiguous_failure",
    }
}

/// Per-request rendezvous between the response stamp (which mints the
/// reference) and the terminal transaction log (which knows the detail).
/// Either may happen first: a buffered response logs before hyper receives
/// it, a streamed one after its body ends. The store keeps the slot, so a
/// lookup always reads whatever detail has been recorded by then.
#[derive(Debug, Default)]
pub struct DiagnosticSlot {
    detail: OnceLock<DiagnosticDetail>,
    minted: OnceLock<String>,
    /// The gateway rejection that authored this request's response, set by
    /// the rejection site before the response head is written. In `all` mode
    /// it is what makes a response without `X-Gateway-Error` gateway-authored.
    rejection: OnceLock<DiagnosticRejection>,
    /// Name of the plugin whose hook rejected the request, noted by the hook
    /// dispatcher before the rejection is logged.
    rejecting_plugin: OnceLock<String>,
    attempt_log: Mutex<AttemptLog>,
}

/// Bounded per-request backend attempt log. The first attempt is stored
/// inline, so a request that is not retried allocates nothing for it.
#[derive(Debug, Default)]
struct AttemptLog {
    first: Option<DiagnosticAttempt>,
    retries: Vec<DiagnosticAttempt>,
    omitted: u32,
    /// TLS detail noted by the dispatch that is about to report a
    /// `tls_error` attempt; taken (and cleared) by the next attempt record.
    pending_tls: Option<DiagnosticTlsDetail>,
}

impl DiagnosticSlot {
    /// A fresh, shareable slot for one request.
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record the request's detail. The first record wins, so a later summary
    /// for the same request (a mirror, a retry bookkeeping pass) cannot
    /// replace the one that described the client-visible response.
    pub fn record_detail(&self, detail: DiagnosticDetail) {
        let _ = self.detail.set(detail);
    }

    pub fn detail(&self) -> Option<&DiagnosticDetail> {
        self.detail.get()
    }

    /// The reference already minted for this request, if any.
    pub fn minted_ref(&self) -> Option<&str> {
        self.minted.get().map(String::as_str)
    }

    /// Record the gateway rejection that authored this request's response.
    /// The first record wins: a rejection is terminal, so a later record could
    /// only come from a cleanup path describing the same response.
    pub fn record_rejection(&self, rejection: DiagnosticRejection) {
        let _ = self.rejection.set(rejection);
    }

    pub fn rejection(&self) -> Option<&DiagnosticRejection> {
        self.rejection.get()
    }

    /// Note the plugin whose hook rejected the request. Dropped unless the
    /// name is a short label.
    pub fn note_rejecting_plugin(&self, plugin: &str) {
        if let Some(plugin) = bounded_label(plugin) {
            let _ = self.rejecting_plugin.set(plugin);
        }
    }

    pub fn rejecting_plugin(&self) -> Option<&str> {
        self.rejecting_plugin.get().map(String::as_str)
    }

    fn lock_attempts(&self) -> MutexGuard<'_, AttemptLog> {
        // Every mutation is a single push or field write, so a recovered
        // guard never exposes a torn log (same reasoning as `lock_shard`).
        self.attempt_log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Note the TLS detail of a backend dispatch failure. The next
    /// [`Self::record_attempt`] attaches it when that attempt is a
    /// `tls_error`, and discards it otherwise.
    pub fn note_tls_failure(&self, tls: DiagnosticTlsDetail) {
        self.lock_attempts().pending_tls = Some(tls);
    }

    /// Record one completed backend attempt. `response_status` is kept only
    /// for an attempt that got a backend response.
    pub fn record_attempt(
        &self,
        error_class: Option<crate::retry::ErrorClass>,
        request_on_wire: bool,
        response_status: Option<u16>,
    ) {
        let mut log = self.lock_attempts();
        let pending_tls = log.pending_tls.take();
        let recorded = usize::from(log.first.is_some()) + log.retries.len();
        if recorded >= MAX_RECORDED_ATTEMPTS {
            log.omitted = log.omitted.saturating_add(1);
            return;
        }
        let backend_dispatch = match error_class {
            None => "backend_response",
            Some(_) if request_on_wire => "ambiguous_failure",
            Some(_) => "pre_wire_failure",
        };
        let tls = if error_class == Some(crate::retry::ErrorClass::TlsError) {
            pending_tls
        } else {
            None
        };
        let attempt = DiagnosticAttempt {
            attempt: u32::try_from(recorded + 1).unwrap_or(u32::MAX),
            backend_dispatch,
            status: response_status.filter(|_| error_class.is_none()),
            error_class: crate::retry::http_log_error_class(error_class),
            tls,
        };
        if log.first.is_none() {
            log.first = Some(attempt);
        } else {
            log.retries.push(attempt);
        }
    }

    /// The recorded attempts, in order, and how many more were omitted.
    pub fn attempts(&self) -> (Vec<DiagnosticAttempt>, u32) {
        let log = self.lock_attempts();
        let mut attempts = Vec::with_capacity(usize::from(log.first.is_some()) + log.retries.len());
        attempts.extend(log.first);
        attempts.extend_from_slice(&log.retries);
        (attempts, log.omitted)
    }

    /// The recorded detail completed with the rejection and attempts this
    /// slot holds, for the lookup view.
    fn view_detail(&self) -> Option<DiagnosticDetail> {
        let mut detail = self.detail()?.clone();
        if detail.rejection.is_none() {
            detail.rejection = self.rejection().cloned();
        }
        if detail.attempts.is_empty() {
            let (attempts, omitted) = self.attempts();
            detail.attempts = attempts;
            detail.attempts_omitted = omitted;
        }
        Some(detail)
    }
}

/// Copy the request's detail into its slot from the terminal summary.
///
/// Only a summary that can accompany an `X-Gateway-Error` token (a 5xx or a
/// classified dispatch error), or in `all` mode a recorded gateway rejection,
/// is recorded, so the enabled feature does not copy strings for every
/// successful request. The `error_class` is the one the transaction log
/// reports, including a gateway output-policy refusal the request context
/// selected after the summary was built, so the detail is identical whether it
/// is recorded here synchronously or by the terminal log.
pub(crate) fn record_request_detail(
    slot: &DiagnosticSlot,
    summary: &TransactionSummary,
    ctx: &crate::plugins::RequestContext,
) {
    if slot.detail.get().is_some() {
        return;
    }
    let error_class = ctx.response_policy_error_class(summary.error_class);
    let gateway_rejection = slot.rejection().is_some() && gateway_rejections_enabled();
    if summary.response_status_code < 500 && error_class.is_none() && !gateway_rejection {
        return;
    }
    let mut detail = DiagnosticDetail::from_summary(
        summary,
        backend_dispatch_label(ctx.backend_dispatch_state()),
        ctx.route_request_timeout_phase(),
    );
    detail.error_class = crate::retry::http_log_error_class(error_class);
    slot.record_detail(detail);
}

fn rfc3339_millis(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Encode 16 random bytes as a reference.
fn encode_ref(key: &[u8; DIAGNOSTIC_REF_RANDOM_BYTES]) -> String {
    let mut out = String::with_capacity(DIAGNOSTIC_REF_LEN);
    out.push_str(DIAGNOSTIC_REF_PREFIX);
    for byte in key {
        out.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

/// Decode a reference into its random key. Only the exact
/// `fd1_<32 lowercase hex>` shape is accepted.
fn parse_ref(reference: &str) -> Option<[u8; DIAGNOSTIC_REF_RANDOM_BYTES]> {
    if reference.len() != DIAGNOSTIC_REF_LEN {
        return None;
    }
    let hex = reference.strip_prefix(DIAGNOSTIC_REF_PREFIX)?.as_bytes();
    let mut key = [0u8; DIAGNOSTIC_REF_RANDOM_BYTES];
    for (index, pair) in hex.as_chunks::<2>().0.iter().enumerate() {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        *key.get_mut(index)? = (high << 4) | low;
    }
    Some(key)
}

/// Whether `reference` has the exact `fd1_<32 lowercase hex>` shape.
pub fn is_well_formed_ref(reference: &str) -> bool {
    parse_ref(reference).is_some()
}

#[derive(Debug)]
struct Entry {
    created_at: DateTime<Utc>,
    expires_at_wall: DateTime<Utc>,
    expires_at: Instant,
    protocol: DiagnosticProtocol,
    status: u16,
    gateway_error: Option<&'static str>,
    slot: Option<Arc<DiagnosticSlot>>,
}

type RefKey = [u8; DIAGNOSTIC_REF_RANDOM_BYTES];

/// One independently locked partition. `order` is insertion order, which is
/// also expiry order because every entry shares the store's TTL.
#[derive(Debug, Default)]
struct Shard {
    entries: HashMap<RefKey, Entry>,
    order: VecDeque<(RefKey, Instant)>,
}

impl Shard {
    /// Drop every entry whose TTL has elapsed. Returns how many were removed.
    fn purge_expired(&mut self, now: Instant) -> u64 {
        let mut purged = 0;
        while let Some(&(key, expires_at)) = self.order.front() {
            if expires_at > now {
                break;
            }
            self.order.pop_front();
            if self.entries.remove(&key).is_some() {
                purged += 1;
            }
        }
        purged
    }

    /// Drop the oldest live entry. Returns whether one was removed.
    fn evict_oldest(&mut self) -> bool {
        while let Some((key, _)) = self.order.pop_front() {
            if self.entries.remove(&key).is_some() {
                return true;
            }
        }
        false
    }
}

/// One subject's admitted lookups in one fixed one-second window.
#[derive(Debug, Clone, Copy)]
struct SubjectWindow {
    window: u64,
    count: u32,
}

/// Bounded result label of one admin lookup, for
/// `ferrum_diagnostic_ref_lookups_total{result}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticRefLookupResult {
    Found,
    NotFound,
    Forbidden,
    RateLimited,
}

impl DiagnosticRefLookupResult {
    pub const ALL: [Self; 4] = [
        Self::Found,
        Self::NotFound,
        Self::Forbidden,
        Self::RateLimited,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Found => "found",
            Self::NotFound => "not_found",
            Self::Forbidden => "forbidden",
            Self::RateLimited => "rate_limited",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Found => 0,
            Self::NotFound => 1,
            Self::Forbidden => 2,
            Self::RateLimited => 3,
        }
    }
}

/// Versioned lookup body (`schema_version` = [`DIAGNOSTIC_REF_SCHEMA_VERSION`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiagnosticRefView {
    pub schema_version: &'static str,
    #[serde(rename = "ref")]
    pub reference: String,
    pub namespace: String,
    pub created_at: String,
    pub expires_at: String,
    pub protocol: DiagnosticProtocol,
    pub status: u16,
    /// The response's `X-Gateway-Error` token, or `null` for an `all`-mode
    /// reference on a gateway rejection that carries none.
    pub gateway_error: Option<&'static str>,
    /// `false` until the request's terminal transaction summary has been
    /// recorded (a streamed response records it when its body ends), and
    /// for gateway fences that answer before a request context exists.
    pub detail_available: bool,
    pub detail: Option<DiagnosticDetail>,
}

/// Bounded, TTL-limited, sharded in-memory reference store for one gateway
/// process. Every reference it holds was minted for this process's data-plane
/// namespace.
#[derive(Debug)]
pub struct DiagnosticRefStore {
    namespace: Arc<str>,
    mode: DiagnosticRefMode,
    ttl: Duration,
    ttl_wall: chrono::Duration,
    per_shard_capacity: usize,
    lookup_rate_per_second: u32,
    per_subject_lookup_rate_per_second: u32,
    shards: Box<[Mutex<Shard>]>,
    epoch: Instant,
    /// Fixed one-second lookup window: high 32 bits are the window's second
    /// since `epoch`, low 32 bits the lookups admitted in it.
    rate_window: AtomicU64,
    /// Per-subject share of the same one-second window, keyed by a
    /// process-keyed hash of the JWT `sub` (bounded by
    /// [`MAX_TRACKED_LOOKUP_SUBJECTS`]). Admin-lookup cold path only.
    subject_windows: Mutex<HashMap<u64, SubjectWindow>>,
    subject_hasher: RandomState,
    minted_total: AtomicU64,
    evicted_capacity_total: AtomicU64,
    evicted_expired_total: AtomicU64,
    lookups_total: [AtomicU64; 4],
}

impl DiagnosticRefStore {
    /// Build a store. Out-of-range bounds are clamped to the documented
    /// limits, so a store can never be unbounded.
    pub fn new(namespace: impl Into<Arc<str>>, config: DiagnosticRefStoreConfig) -> Self {
        let ttl = config.ttl.clamp(
            Duration::from_secs(MIN_TTL_SECONDS),
            Duration::from_secs(MAX_TTL_SECONDS),
        );
        let max_entries = config.max_entries.clamp(MIN_MAX_ENTRIES, MAX_MAX_ENTRIES);
        let lookup_rate_per_second = config
            .lookup_rate_per_second
            .clamp(MIN_LOOKUP_RATE_PER_SECOND, MAX_LOOKUP_RATE_PER_SECOND);
        Self {
            namespace: namespace.into(),
            mode: DiagnosticRefMode::Errors,
            ttl,
            ttl_wall: chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::zero()),
            per_shard_capacity: (max_entries / SHARD_COUNT).max(1),
            lookup_rate_per_second,
            per_subject_lookup_rate_per_second: (lookup_rate_per_second / 2).max(1),
            shards: (0..SHARD_COUNT)
                .map(|_| Mutex::new(Shard::default()))
                .collect(),
            epoch: Instant::now(),
            rate_window: AtomicU64::new(0),
            subject_windows: Mutex::new(HashMap::new()),
            subject_hasher: RandomState::new(),
            minted_total: AtomicU64::new(0),
            evicted_capacity_total: AtomicU64::new(0),
            evicted_expired_total: AtomicU64::new(0),
            lookups_total: Default::default(),
        }
    }

    /// The same store minting for `mode`. [`Self::new`] mints for `errors`;
    /// `off` is not a store mode and keeps `errors`.
    pub fn with_mode(mut self, mode: DiagnosticRefMode) -> Self {
        if mode.is_enabled() {
            self.mode = mode;
        }
        self
    }

    /// Which responses this store mints references for (`errors` or `all`).
    pub fn mode(&self) -> DiagnosticRefMode {
        self.mode
    }

    /// Namespace every reference in this store belongs to.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Effective reference lifetime.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Effective retained-reference ceiling (never above the configured one).
    pub fn capacity(&self) -> usize {
        self.per_shard_capacity * SHARD_COUNT
    }

    /// Share of the lookup budget one JWT `sub` may use per second: half the
    /// configured budget, and at least one.
    pub fn per_subject_lookup_rate_per_second(&self) -> u32 {
        self.per_subject_lookup_rate_per_second
    }

    fn lock_shard(&self, key: &RefKey) -> MutexGuard<'_, Shard> {
        let index = usize::from(key[0]) % self.shards.len();
        // A panic while holding a shard lock cannot leave a half-written
        // entry the next caller could misread (every mutation is a single
        // map/deque operation), so recovering the guard is safe and keeps the
        // store serving instead of propagating the poison into request paths.
        self.shards[index]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Mint and retain a reference for a response carrying `gateway_error`.
    pub fn mint(
        &self,
        protocol: DiagnosticProtocol,
        status: u16,
        gateway_error: &'static str,
        slot: Option<&Arc<DiagnosticSlot>>,
    ) -> Option<String> {
        self.mint_at(Instant::now(), protocol, status, gateway_error, slot)
    }

    /// [`Self::mint`] against an explicit monotonic clock.
    ///
    /// A request that already minted a reference gets the same one back, so a
    /// response is never described by two references. A CSPRNG failure mints
    /// nothing: the response simply carries no reference.
    pub fn mint_at(
        &self,
        now: Instant,
        protocol: DiagnosticProtocol,
        status: u16,
        gateway_error: &'static str,
        slot: Option<&Arc<DiagnosticSlot>>,
    ) -> Option<String> {
        self.mint_entry_at(now, protocol, status, Some(gateway_error), slot)
    }

    /// Mint for a response carrying `gateway_error`, or for an `all`-mode
    /// gateway rejection without a token (`None`).
    fn mint_entry_at(
        &self,
        now: Instant,
        protocol: DiagnosticProtocol,
        status: u16,
        gateway_error: Option<&'static str>,
        slot: Option<&Arc<DiagnosticSlot>>,
    ) -> Option<String> {
        if let Some(existing) = slot.and_then(|slot| slot.minted.get()) {
            return Some(existing.clone());
        }
        let mut key = [0u8; DIAGNOSTIC_REF_RANDOM_BYTES];
        if SystemRandom::new().fill(&mut key).is_err() {
            return None;
        }
        let reference = encode_ref(&key);
        if let Some(slot) = slot
            && slot.minted.set(reference.clone()).is_err()
        {
            // A concurrent stamp of the same request won the slot.
            return slot.minted.get().cloned();
        }
        let created_at = Utc::now();
        let entry = Entry {
            created_at,
            expires_at_wall: created_at
                .checked_add_signed(self.ttl_wall)
                .unwrap_or(created_at),
            // An unrepresentable deadline expires immediately (fail closed).
            expires_at: now.checked_add(self.ttl).unwrap_or(now),
            protocol,
            status,
            gateway_error,
            slot: slot.cloned(),
        };
        let expires_at = entry.expires_at;
        let (expired, evicted) = {
            let mut shard = self.lock_shard(&key);
            let expired = shard.purge_expired(now);
            let mut evicted = 0u64;
            while shard.entries.len() >= self.per_shard_capacity {
                if !shard.evict_oldest() {
                    break;
                }
                evicted += 1;
            }
            shard.order.push_back((key, expires_at));
            shard.entries.insert(key, entry);
            (expired, evicted)
        };
        self.minted_total.fetch_add(1, Ordering::Relaxed);
        if expired > 0 {
            self.evicted_expired_total
                .fetch_add(expired, Ordering::Relaxed);
        }
        if evicted > 0 {
            self.evicted_capacity_total
                .fetch_add(evicted, Ordering::Relaxed);
        }
        Some(reference)
    }

    /// Resolve a reference. `None` for a malformed, unknown, expired, or
    /// evicted reference. Callers authorize the returned namespace.
    pub fn lookup_at(&self, now: Instant, reference: &str) -> Option<DiagnosticRefView> {
        let key = parse_ref(reference)?;
        let (expired, view) = {
            let mut shard = self.lock_shard(&key);
            let expired = shard.purge_expired(now);
            let view = match shard.entries.get(&key) {
                Some(entry) if entry.expires_at > now => Some(self.view(reference, entry)),
                _ => None,
            };
            (expired, view)
        };
        if expired > 0 {
            self.evicted_expired_total
                .fetch_add(expired, Ordering::Relaxed);
        }
        view
    }

    fn view(&self, reference: &str, entry: &Entry) -> DiagnosticRefView {
        let detail = entry.slot.as_ref().and_then(|slot| slot.view_detail());
        DiagnosticRefView {
            schema_version: DIAGNOSTIC_REF_SCHEMA_VERSION,
            reference: reference.to_string(),
            namespace: self.namespace.to_string(),
            created_at: rfc3339_millis(entry.created_at),
            expires_at: rfc3339_millis(entry.expires_at_wall),
            protocol: entry.protocol,
            status: entry.status,
            gateway_error: entry.gateway_error,
            detail_available: detail.is_some(),
            detail,
        }
    }

    /// The fixed one-second lookup window `now` falls in.
    fn lookup_window(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.epoch).as_secs() & 0xFFFF_FFFF
    }

    /// Admit one admin lookup attempt by `subject` (the JWT `sub`) against
    /// that subject's share of the window and, when `charge_global` is set,
    /// the global budget as well.
    ///
    /// Both are decided and committed under the subject-table lock: a subject
    /// over its share never charges the global budget, and an attempt the
    /// global budget refuses never spends the subject's share. Callers pass
    /// `charge_global = false` for an attempt already refused for its
    /// credential, so credentials that may not read references can only ever
    /// exhaust their own shares, never the budget authorized operators use.
    pub fn try_acquire_subject_lookup_at(
        &self,
        now: Instant,
        subject: &str,
        charge_global: bool,
    ) -> bool {
        let window = self.lookup_window(now);
        let key = self.subject_hasher.hash_one(subject);
        // Same poison reasoning as `lock_shard`: every mutation is a single
        // map operation, so a recovered guard never exposes a torn entry.
        let mut windows = self
            .subject_windows
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let used = match windows.get(&key) {
            Some(entry) if entry.window == window => entry.count,
            Some(_) => 0,
            None => {
                if windows.len() >= MAX_TRACKED_LOOKUP_SUBJECTS {
                    windows.retain(|_, entry| entry.window == window);
                    if windows.len() >= MAX_TRACKED_LOOKUP_SUBJECTS {
                        return false;
                    }
                }
                0
            }
        };
        if used >= self.per_subject_lookup_rate_per_second {
            return false;
        }
        if charge_global && !self.try_acquire_lookup_at(now) {
            return false;
        }
        let count = used + 1;
        windows.insert(key, SubjectWindow { window, count });
        true
    }

    /// Admit one admin lookup against the global fixed one-second window.
    pub fn try_acquire_lookup_at(&self, now: Instant) -> bool {
        let window = self.lookup_window(now);
        let limit = u64::from(self.lookup_rate_per_second);
        let mut current = self.rate_window.load(Ordering::Relaxed);
        loop {
            let current_window = current >> 32;
            let count = current & 0xFFFF_FFFF;
            let next = if current_window != window {
                (window << 32) | 1
            } else if count >= limit {
                return false;
            } else {
                current + 1
            };
            match self.rate_window.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    /// Count one admin lookup outcome.
    pub fn record_lookup(&self, result: DiagnosticRefLookupResult) {
        self.lookups_total[result.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// References currently retained (expired ones are counted until the next
    /// operation on their shard purges them).
    pub fn len(&self) -> usize {
        let mut total = 0;
        for shard in self.shards.iter() {
            let guard = shard.lock().unwrap_or_else(PoisonError::into_inner);
            total += guard.entries.len();
        }
        total
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn minted_total(&self) -> u64 {
        self.minted_total.load(Ordering::Relaxed)
    }

    pub fn evicted_capacity_total(&self) -> u64 {
        self.evicted_capacity_total.load(Ordering::Relaxed)
    }

    pub fn evicted_expired_total(&self) -> u64 {
        self.evicted_expired_total.load(Ordering::Relaxed)
    }

    pub fn lookups_total(&self, result: DiagnosticRefLookupResult) -> u64 {
        self.lookups_total[result.index()].load(Ordering::Relaxed)
    }

    /// Prometheus exposition for this store. Cold path (scrape only).
    pub fn render_prometheus(&self) -> String {
        let mut output = String::with_capacity(1_536);
        output.push_str(
            "# HELP ferrum_diagnostic_ref_lookups_total Authenticated admin diagnostic reference lookups, by bounded result.\n\
# TYPE ferrum_diagnostic_ref_lookups_total counter\n",
        );
        for result in DiagnosticRefLookupResult::ALL {
            output.push_str(&format!(
                "ferrum_diagnostic_ref_lookups_total{{result=\"{}\"}} {}\n",
                result.as_str(),
                self.lookups_total(result)
            ));
        }
        output.push_str(
            "# HELP ferrum_diagnostic_refs_entries Diagnostic references currently retained in the bounded in-memory store.\n\
# TYPE ferrum_diagnostic_refs_entries gauge\n",
        );
        output.push_str(&format!("ferrum_diagnostic_refs_entries {}\n", self.len()));
        output.push_str(
            "# HELP ferrum_diagnostic_refs_evicted_total Diagnostic references removed from the store before lookup, by bounded reason.\n\
# TYPE ferrum_diagnostic_refs_evicted_total counter\n",
        );
        output.push_str(&format!(
            "ferrum_diagnostic_refs_evicted_total{{reason=\"capacity\"}} {}\n",
            self.evicted_capacity_total()
        ));
        output.push_str(&format!(
            "ferrum_diagnostic_refs_evicted_total{{reason=\"expired\"}} {}\n",
            self.evicted_expired_total()
        ));
        output.push_str(
            "# HELP ferrum_diagnostic_refs_minted_total Diagnostic references minted on gateway-authored error responses.\n\
# TYPE ferrum_diagnostic_refs_minted_total counter\n",
        );
        output.push_str(&format!(
            "ferrum_diagnostic_refs_minted_total {}\n",
            self.minted_total()
        ));
        output
    }
}

/// Drop every client-bound copy of the reference header.
///
/// The header is gateway-owned whatever `FERRUM_DIAGNOSTIC_REFS` says, so the
/// final client boundary calls this even when references are off: a plugin or
/// hook can never hand a client a reference the gateway did not mint.
/// `http::HeaderMap` normalizes field names to lowercase, so the one `remove`
/// drops every spelling and every repeated value.
pub fn strip_response_header(headers: &mut http::HeaderMap) {
    headers.remove(&DIAGNOSTIC_REF_HEADER_NAME);
}

/// Whether a response head reports an error: an HTTP status of at least
/// `400`, or a gRPC Trailers-Only head whose `grpc-status` is not `0`.
pub fn is_error_response(status: u16, headers: &http::HeaderMap) -> bool {
    status >= 400
        || headers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.trim() != "0")
}

/// Strip every client-bound copy of the reference header, then stamp a fresh
/// reference when the response carries a gateway-authored `X-Gateway-Error`
/// token from the closed vocabulary or, in `all` mode, when the request's slot
/// recorded a gateway rejection and the head reports an error. Returns the
/// stamped reference.
pub fn stamp_response_headers(
    store: &DiagnosticRefStore,
    slot: Option<&Arc<DiagnosticSlot>>,
    protocol: DiagnosticProtocol,
    status: u16,
    headers: &mut http::HeaderMap,
) -> Option<String> {
    strip_response_header(headers);
    let token = headers
        .get(crate::proxy::headers::X_GATEWAY_ERROR_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(crate::retry::intern_http_observability_error_class);
    let gateway_rejection = token.is_none()
        && store.mode.covers_gateway_rejections()
        && slot.is_some_and(|slot| slot.rejection().is_some())
        && is_error_response(status, headers);
    if token.is_none() && !gateway_rejection {
        return None;
    }
    let reference = store.mint_entry_at(Instant::now(), protocol, status, token, slot)?;
    let value = http::HeaderValue::from_str(&reference).ok()?;
    headers.insert(&DIAGNOSTIC_REF_HEADER_NAME, value);
    Some(reference)
}

/// Outcome of an authorized admin lookup.
#[derive(Debug)]
pub enum DiagnosticRefLookup {
    Found(Box<DiagnosticRefView>),
    /// Malformed, unknown, expired, evicted, outside the caller's namespaces,
    /// or the feature is off: one answer, so references cannot be probed.
    NotFound,
    /// The admin JWT lacks the `diagnostics:read` scope.
    MissingScope,
    /// The admin JWT carries no `ns` claim, so it is not namespace-bound.
    MissingNamespaceBinding,
    RateLimited,
}

impl DiagnosticRefLookup {
    /// Bounded metric / audit label.
    pub fn result(&self) -> DiagnosticRefLookupResult {
        match self {
            Self::Found(_) => DiagnosticRefLookupResult::Found,
            Self::NotFound => DiagnosticRefLookupResult::NotFound,
            Self::MissingScope | Self::MissingNamespaceBinding => {
                DiagnosticRefLookupResult::Forbidden
            }
            Self::RateLimited => DiagnosticRefLookupResult::RateLimited,
        }
    }
}

/// Throttle for the `diagnostic_ref_lookup` audit event.
///
/// `found` / `not_found` lookups are always audited. Refused (`forbidden`) and
/// rate-limited attempts are throttled to one event per window per result,
/// each carrying how many were suppressed since the previous one, so a caller
/// hammering the endpoint cannot flood the audit log. The lookup metric still
/// counts every attempt.
#[derive(Debug, Default)]
pub struct DiagnosticRefLookupAudit {
    forbidden: AtomicLogRateLimiter,
    rate_limited: AtomicLogRateLimiter,
}

impl DiagnosticRefLookupAudit {
    pub const fn new() -> Self {
        Self {
            forbidden: AtomicLogRateLimiter::new(),
            rate_limited: AtomicLogRateLimiter::new(),
        }
    }

    /// Whether the audit event for `result` at `now_ms` (monotonic millis) is
    /// emitted: `Some(suppressed_since_last)` to emit, `None` to suppress.
    pub fn admit(&self, result: DiagnosticRefLookupResult, now_ms: u64) -> Option<u64> {
        match result {
            DiagnosticRefLookupResult::Found | DiagnosticRefLookupResult::NotFound => Some(0),
            DiagnosticRefLookupResult::Forbidden => self.forbidden.on_event(now_ms),
            DiagnosticRefLookupResult::RateLimited => self.rate_limited.on_event(now_ms),
        }
    }
}

/// Authorize and resolve one admin lookup by the JWT subject `subject`.
///
/// Order is fixed and independent of the reference:
///
/// 1. With the store enabled, every attempt is charged against the subject's
///    share of the rate limit first, including one that is then refused for
///    its credential, so a credential lacking the scope cannot probe without
///    limit. Only an attempt whose credential carries the scope and an `ns`
///    binding that allows the store's namespace is also charged against the
///    global budget, so credentials that may not read references can never
///    exhaust it for authorized operators.
/// 2. The scope and namespace binding (they depend only on the credential).
/// 3. The store's own namespace against the token's `ns` claim. Every
///    reference in the store belongs to that one namespace, so a caller
///    outside it is charged only its subject share and gets `NotFound` without
///    the store being read, the same answer as an unknown reference.
/// 4. The store.
pub fn authorize_lookup(
    store: Option<&DiagnosticRefStore>,
    subject: &str,
    scope_granted: bool,
    allowed_namespaces: &crate::grpc::auth::AllowedNamespaces,
    reference: &str,
    now: Instant,
) -> DiagnosticRefLookup {
    let authorized = scope_granted
        && allowed_namespaces.is_present()
        && store.is_some_and(|store| allowed_namespaces.allows(store.namespace()));
    let admitted = match store {
        Some(store) => store.try_acquire_subject_lookup_at(now, subject, authorized),
        None => true,
    };
    let outcome = if !admitted {
        DiagnosticRefLookup::RateLimited
    } else if !scope_granted {
        DiagnosticRefLookup::MissingScope
    } else if !allowed_namespaces.is_present() {
        DiagnosticRefLookup::MissingNamespaceBinding
    } else {
        let view = match store {
            Some(store) if allowed_namespaces.allows(store.namespace()) => {
                store.lookup_at(now, reference)
            }
            _ => None,
        };
        match view {
            Some(view) => DiagnosticRefLookup::Found(Box::new(view)),
            None => DiagnosticRefLookup::NotFound,
        }
    };
    if let Some(store) = store {
        store.record_lookup(outcome.result());
    }
    outcome
}

static ACTIVE_STORE: OnceLock<DiagnosticRefStore> = OnceLock::new();

/// Publish the process store from the accepted configuration. `off` installs
/// nothing. Called once at startup, before any listener accepts traffic.
pub fn install(
    mode: DiagnosticRefMode,
    namespace: &str,
    config: DiagnosticRefStoreConfig,
) -> Result<(), String> {
    if !mode.is_enabled() {
        return Ok(());
    }
    let store = DiagnosticRefStore::new(namespace, config).with_mode(mode);
    ACTIVE_STORE
        .set(store)
        .map_err(|_| ALREADY_INSTALLED_ERROR.to_string())
}

const ALREADY_INSTALLED_ERROR: &str =
    "diagnostic reference store is already installed for this process";

/// [`install`] from an accepted [`crate::config::EnvConfig`].
pub fn install_from_env_config(env_config: &crate::config::EnvConfig) -> Result<(), String> {
    install(
        env_config.diagnostic_refs,
        &env_config.namespace,
        DiagnosticRefStoreConfig {
            ttl: Duration::from_secs(env_config.diagnostic_ref_ttl_seconds),
            max_entries: env_config.diagnostic_ref_max_entries,
            lookup_rate_per_second: env_config.diagnostic_ref_lookup_rate_per_second,
        },
    )
}

/// The process store, or `None` when references are off.
pub fn active_store() -> Option<&'static DiagnosticRefStore> {
    ACTIVE_STORE.get()
}

/// Whether the process store mints for gateway rejections (`all`).
pub fn gateway_rejections_enabled() -> bool {
    active_store().is_some_and(|store| store.mode.covers_gateway_rejections())
}

/// Note the plugin whose hook rejected the request. A no-op (one `Option`
/// check) when references are off.
pub(crate) fn note_rejecting_plugin(ctx: &crate::plugins::RequestContext, plugin: &str) {
    if let Some(slot) = ctx.diagnostic_slot() {
        slot.note_rejecting_plugin(plugin);
    }
}

/// Note the source of a backend admission rejection. A plugin-named source
/// is the rejecting plugin; a `__`-prefixed source is a gateway-internal
/// admission ceiling, not a plugin.
pub(crate) fn note_admission_rejection_source(ctx: &crate::plugins::RequestContext, source: &str) {
    if !source.starts_with("__") {
        note_rejecting_plugin(ctx, source);
    }
}

/// Record the gateway or plugin rejection that authored the request's
/// response, from the shared rejection-log funnel, before the response head
/// is written. A no-op when references are off.
pub(crate) fn record_rejection(ctx: &crate::plugins::RequestContext, phase: &str) {
    if let Some(slot) = ctx.diagnostic_slot() {
        let rejection = DiagnosticRejection::new(phase, slot.rejecting_plugin());
        slot.record_rejection(rejection);
    }
}

/// The slot a gateway rejection answered before routing matched a proxy (a
/// routing `404`, an admission fence) is recorded in. Only `all` mode
/// references such a response when it carries no `X-Gateway-Error`, so this is
/// `None` in `errors` mode as well as when references are off, and the callers
/// build nothing then.
fn unrouted_rejection_slot(slot: Option<&Arc<DiagnosticSlot>>) -> Option<&Arc<DiagnosticSlot>> {
    slot.filter(|_| gateway_rejections_enabled())
}

/// Record a routing rejection (`phase` is [`ROUTE_NOT_FOUND_PHASE`] or
/// [`MESH_REGISTRY_ONLY_PHASE`]) for a request received at `started`, with its
/// unrouted detail.
pub(crate) fn record_route_miss(
    slot: Option<&Arc<DiagnosticSlot>>,
    phase: &'static str,
    started: Instant,
) {
    if let Some(slot) = unrouted_rejection_slot(slot) {
        let latency_ms = started.elapsed().as_secs_f64() * 1000.0;
        slot.record_rejection(DiagnosticRejection::routing(phase));
        slot.record_detail(DiagnosticDetail::unrouted(latency_ms));
    }
}

/// Record a frontend admission fence that answered before a request context
/// existed, with its unrouted detail. Fences answer without waiting, so the
/// duration bucket is the shortest one.
pub(crate) fn record_admission_fence(slot: Option<&Arc<DiagnosticSlot>>, phase: &'static str) {
    if let Some(slot) = unrouted_rejection_slot(slot) {
        slot.record_rejection(DiagnosticRejection::gateway_fence(phase));
        slot.record_detail(DiagnosticDetail::unrouted(0.0));
    }
}

/// Note the TLS detail of a backend dispatch failure for the attempt the
/// dispatch is about to report. A no-op when references are off.
pub(crate) fn note_backend_tls_failure(
    slot: Option<&Arc<DiagnosticSlot>>,
    err: &(dyn std::error::Error + 'static),
) {
    if let Some(slot) = slot
        && let Some(tls) = tls_detail(err)
    {
        slot.note_tls_failure(tls);
    }
}

/// `/metrics` families; empty when references are off.
pub fn render_prometheus() -> String {
    active_store()
        .map(DiagnosticRefStore::render_prometheus)
        .unwrap_or_default()
}

/// HTTP/1.1 and HTTP/2 per-request handle, created at the frontend service
/// boundary and applied to the response that boundary returns.
pub(crate) struct RequestDiagnostic {
    store: &'static DiagnosticRefStore,
    slot: Arc<DiagnosticSlot>,
    protocol: DiagnosticProtocol,
}

impl RequestDiagnostic {
    /// `None` (one `OnceLock` load, no allocation) when references are off.
    pub(crate) fn begin(protocol: DiagnosticProtocol) -> Option<Self> {
        active_store().map(|store| Self {
            store,
            slot: DiagnosticSlot::shared(),
            protocol,
        })
    }

    pub(crate) fn slot(&self) -> Arc<DiagnosticSlot> {
        Arc::clone(&self.slot)
    }

    /// Stamp (or strip) the reference on the response hyper receives.
    pub(crate) fn stamp(&self, status: u16, headers: &mut http::HeaderMap) {
        let _ =
            stamp_response_headers(self.store, Some(&self.slot), self.protocol, status, headers);
    }
}

tokio::task_local! {
    /// The HTTP/3 request's slot. HTTP/3 writes response heads from many
    /// helpers deep inside the request task, so the slot rides the task
    /// instead of every helper signature. Set only when references are on.
    static H3_REQUEST_SLOT: Arc<DiagnosticSlot>;
}

/// Drive an HTTP/3 request future with a fresh diagnostic slot as its
/// task-local when references are on, and directly when they are off.
///
/// The request future is taken by pinned reference, never by value, so the
/// wrapper adds a pointer and the slot to the request task instead of a second
/// copy of the (large) `handle_h3_request` future. Tokio swaps the slot into
/// the task-local on each poll; nothing is cloned or allocated per poll.
pub(crate) async fn run_h3_request<F: Future>(request: Pin<&mut F>) -> F::Output {
    if active_store().is_none() {
        return request.await;
    }
    let slot = DiagnosticSlot::shared();
    H3_REQUEST_SLOT.scope(slot, request).await
}

/// The current HTTP/3 request's slot. `None` when references are off or
/// outside a scoped request task.
pub(crate) fn current_h3_slot() -> Option<Arc<DiagnosticSlot>> {
    active_store()?;
    H3_REQUEST_SLOT.try_with(Arc::clone).ok()
}

/// Final stamp for an HTTP/3 response head, applied at every `send_response`
/// site. When references are off it only strips a plugin- or hook-written
/// copy of the gateway-owned header.
pub(crate) fn stamp_h3_response(mut response: http::Response<()>) -> http::Response<()> {
    match active_store() {
        Some(store) => {
            let slot = H3_REQUEST_SLOT.try_with(Arc::clone).ok();
            let status = response.status().as_u16();
            let _ = stamp_response_headers(
                store,
                slot.as_ref(),
                DiagnosticProtocol::Http3,
                status,
                response.headers_mut(),
            );
        }
        None => strip_response_header(response.headers_mut()),
    }
    response
}
