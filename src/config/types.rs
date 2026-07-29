//! Core domain model types and validation for the gateway configuration.
//!
//! Key design decisions:
//! - **Regex auto-anchoring**: `anchor_regex_pattern()` adds `^`/`$` to regex
//!   listen_paths for full-path matching, preventing accidental prefix matches.
//! - **Stream proxy routing**: TCP/UDP proxies are matched by `listen_port`,
//!   not `listen_path`, so path validation and router invalidation skip them.
//! - **Validation deduplication**: TLS cert/key paths are validated via a
//!   `validated_tls_paths` cache so each unique source/role is parsed only once.
//! - **Control character rejection**: Resource IDs, hostnames, and paths reject
//!   control characters to prevent log injection attacks.

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::cell::OnceCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, OnceLock, Weak};
use std::time::SystemTime;

/// Maximum length for resource IDs.
pub(crate) const MAX_ID_LENGTH: usize = 254;

// ---- Field length limits (aligned with DB schema VARCHAR widths) ----

/// Maximum length for name fields (proxy.name, upstream.name). Matches VARCHAR(255) in DB.
pub const MAX_NAME_LENGTH: usize = 255;
/// Maximum length for backend_host. Matches VARCHAR(255) in DB.
pub const MAX_BACKEND_HOST_LENGTH: usize = 255;
/// Maximum length for backend_path.
pub const MAX_BACKEND_PATH_LENGTH: usize = 2048;
/// Maximum length for listen_path (non-regex). Matches VARCHAR(500) in DB.
pub const MAX_LISTEN_PATH_LENGTH: usize = 500;
/// Maximum length for consumer username. Matches VARCHAR(255) in DB.
pub const MAX_USERNAME_LENGTH: usize = 255;
/// Maximum length for consumer custom_id. Matches VARCHAR(255) in DB.
pub const MAX_CUSTOM_ID_LENGTH: usize = 255;
/// Maximum length for individual hostname entries (DNS spec is 253).
pub const MAX_HOST_LENGTH: usize = 253;
/// Maximum number of host entries per proxy.
pub const MAX_HOSTS_PER_PROXY: usize = 100;
/// Maximum number of targets per upstream.
pub const MAX_TARGETS_PER_UPSTREAM: usize = 1000;
/// Maximum number of tags per upstream target.
pub const MAX_TAGS_PER_TARGET: usize = 50;
/// Maximum number of subset definitions per upstream.
pub const MAX_SUBSETS_PER_UPSTREAM: usize = 100;
/// Maximum number of backend TLS SAN allow-list entries per upstream.
pub const MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES: usize = 256;
/// Maximum length for one backend TLS SAN allow-list entry.
pub const MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRY_LENGTH: usize = 2048;
/// Maximum length for a subset name.
pub const MAX_SUBSET_NAME_LENGTH: usize = 255;
/// Maximum length for a tag key or value.
pub const MAX_TAG_LENGTH: usize = 255;
/// Maximum length of an Istio-style `region/zone/subzone` locality string.
pub const MAX_LOCALITY_LENGTH: usize = 255;
/// Maximum size of plugin config JSON in bytes.
pub const MAX_PLUGIN_CONFIG_SIZE: usize = 1_048_576; // 1 MiB
/// Maximum size of an owned country-capable MaxMind database snapshot.
///
/// This accommodates current GeoIP2 Enterprise MMDB releases while bounding
/// admission-time allocation before any untrusted file contents are parsed.
pub const MAX_COUNTRY_MMDB_SIZE_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB
/// Maximum aggregate bytes admitted for country MMDB snapshots in one config
/// validation generation or plugin-cache build session, and for the global
/// peak of live plus in-flight candidate snapshot buffers.
///
/// Keeping this equal to the per-file ceiling permits one maximum-size
/// Enterprise database while preventing several individually valid files from
/// exhausting the heap before a candidate config is accepted or rejected.
pub const MAX_COUNTRY_MMDB_AGGREGATE_SIZE_BYTES: u64 = MAX_COUNTRY_MMDB_SIZE_BYTES;
/// Maximum OpenAPI validator config JSON size in bytes.
///
/// Generated validator configs embed resolved operation schemas, so they need
/// a larger budget than ordinary plugin configs. Keep this safely below
/// MongoDB's 16 MiB BSON document ceiling because database mode may store a
/// generated validator as one plugin row.
pub const MAX_OPENAPI_VALIDATOR_CONFIG_SIZE: usize = 14_680_064; // 14 MiB
/// Maximum OpenAPI validator config JSON nesting depth.
pub const MAX_OPENAPI_VALIDATOR_CONFIG_DEPTH: usize = 64;
/// Default OpenAPI validator media types for generated and direct configs.
pub const OPENAPI_VALIDATOR_DEFAULT_CONTENT_TYPES: &[&str] = &[
    "application/json",
    "application/xml",
    "text/xml",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
    "application/octet-stream",
];
/// Maximum size of consumer credentials JSON in bytes.
pub const MAX_CREDENTIALS_SIZE: usize = 65_536; // 64 KiB
/// Maximum length for individual credential string values (API keys, secrets, identities).
pub const MAX_CREDENTIAL_VALUE_LENGTH: usize = 4096;
/// Minimum length for JWT secrets (admin API and consumer credentials).
pub const MIN_JWT_SECRET_LENGTH: usize = 32;
/// Minimum length for hmac_auth shared secrets.
pub const MIN_HMAC_SECRET_LENGTH: usize = 32;
/// Placeholder substituted for secret credential values in ordinary Consumer
/// responses and audit diffs.
pub const CREDENTIAL_REDACTION_PLACEHOLDER: &str = "[REDACTED]";
/// Known credential types whose secret field the ordinary Consumer response
/// projection replaces with [`CREDENTIAL_REDACTION_PLACEHOLDER`], paired with
/// that field name.
pub const REDACTED_CREDENTIAL_SECRET_FIELDS: &[(&str, &str)] = &[
    ("keyauth", "key"),
    ("jwt", "secret"),
    ("hmac_auth", "secret"),
];
/// Maximum length of a credential type key.
pub const MAX_CREDENTIAL_TYPE_LENGTH: usize = 64;
/// Credential types whose entries must contain exactly one field, paired with
/// that field name. A row written before that contract was enforced can still
/// carry extra ignored fields, so any path that re-validates such an entry has
/// to reduce it to the canonical field first.
pub const SINGLE_FIELD_CREDENTIAL_TYPES: &[(&str, &str)] = &[
    ("jwt", "secret"),
    ("hmac_auth", "secret"),
    ("mtls_auth", "identity"),
];

/// The single canonical field of `cred_type`, when it has one.
fn single_credential_field(cred_type: &str) -> Option<&'static str> {
    SINGLE_FIELD_CREDENTIAL_TYPES
        .iter()
        .find(|(known, _)| *known == cred_type)
        .map(|(_, field)| *field)
}

/// Reduces a credential entry to its single canonical `field`.
///
/// Entries without a string at `field` are returned untouched so genuinely
/// unrepresentable data surfaces at validation instead of being silently
/// rewritten.
fn canonical_single_field_entry(entry: &serde_json::Value, field: &str) -> serde_json::Value {
    match entry.get(field).and_then(serde_json::Value::as_str) {
        Some(value) => serde_json::json!({ (field): value }),
        None => entry.clone(),
    }
}

fn is_path_safe_credential_type_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// Validates a credential type key.
///
/// Credential type keys are addressable URI path segments: every stored type
/// must stay removable through
/// `DELETE /consumers/{consumer_id}/credentials/{cred_type}`, and the admin
/// router matches that route by splitting the raw request path on `/` without
/// percent-decoding. A key containing `/`, `%`, a control byte, or any other
/// reserved or non-literal URI character would therefore become unreachable
/// once stored. Restricting keys to one path-safe token at this single write
/// and restore boundary — which create, update, batch, and restore all pass
/// through — keeps that guarantee without per-route filtering. Every built-in
/// credential type already satisfies the rule.
fn validate_credential_type_name(cred_type: &str) -> Result<(), String> {
    if cred_type.is_empty() {
        return Err("credential type must not be empty".to_string());
    }
    let length = cred_type.chars().count();
    if length > MAX_CREDENTIAL_TYPE_LENGTH {
        return Err(format!(
            "credential type must not exceed {} characters (got {})",
            MAX_CREDENTIAL_TYPE_LENGTH, length
        ));
    }
    if !cred_type.chars().all(is_path_safe_credential_type_char) {
        return Err(format!(
            "credential type '{}' must be ASCII letters, digits, underscores, or hyphens",
            cred_type
        ));
    }
    Ok(())
}

// Current ISO 3166-1 alpha-2 assignments plus XK, the user-assigned Kosovo
// code emitted by MaxMind country-capable products. Keeping this list in the
// config layer lets policy admission and MMDB record validation share exactly
// one supported-code contract.
pub(crate) const SUPPORTED_GEO_COUNTRY_CODES: &[u8] = concat!(
    "ADAEAFAGAIALAMAOAQARASATAUAWAXAZ",
    "BABBBDBEBFBGBHBIBJBLBMBNBOBQBRBSBTBVBWBYBZ",
    "CACCCDCFCGCHCICKCLCMCNCOCRCUCVCWCXCYCZ",
    "DEDJDKDMDODZ",
    "ECEEEGEHERESET",
    "FIFJFKFMFOFR",
    "GAGBGDGEGFGGGHGIGLGMGNGPGQGRGSGTGUGWGY",
    "HKHMHNHRHTHU",
    "IDIEILIMINIOIQIRISIT",
    "JEJMJOJP",
    "KEKGKHKIKMKNKPKRKWKYKZ",
    "LALBLCLILKLRLSLTLULVLY",
    "MAMCMDMEMFMGMHMKMLMMMNMOMPMQMRMSMTMUMVMWMXMYMZ",
    "NANCNENFNGNINLNONPNRNUNZ",
    "OM",
    "PAPEPFPGPHPKPLPMPNPRPSPTPWPY",
    "QA",
    "RERORSRURW",
    "SASBSCSDSESGSHSISJSKSLSMSNSOSRSSSTSVSXSYSZ",
    "TCTDTFTGTHTJTKTLTMTNTOTRTTTVTWTZ",
    "UAUGUMUSUYUZ",
    "VAVCVEVGVIVNVU",
    "WFWS",
    "XK",
    "YEYT",
    "ZAZMZW",
)
.as_bytes();

/// Effective strength of an hmac_auth secret: whitespace does not count
/// toward [`MIN_HMAC_SECRET_LENGTH`]. Shared by admission-time field
/// validation and the full-load quarantine so the two policies cannot drift.
pub(crate) fn hmac_secret_strength(secret: &str) -> usize {
    secret.chars().filter(|ch| !ch.is_whitespace()).count()
}
/// Minimum byte length for the server-side Basic-auth HMAC secret.
pub const MIN_BASIC_AUTH_HMAC_SECRET_LENGTH: usize = 32;
/// Default maximum number of credential entries per type (for zero-downtime rotation).
/// Overridable at runtime via `FERRUM_MAX_CREDENTIALS_PER_TYPE` env var / conf file.
pub const DEFAULT_MAX_CREDENTIALS_PER_TYPE: usize = 2;

/// Resolve the runtime max credentials per type from env var / conf file, falling
/// back to `DEFAULT_MAX_CREDENTIALS_PER_TYPE` if unset or unparsable.
pub fn max_credentials_per_type() -> usize {
    crate::config::conf_file::resolve_ferrum_var("FERRUM_MAX_CREDENTIALS_PER_TYPE")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_CREDENTIALS_PER_TYPE)
}

/// Validate the shared Basic-auth HMAC secret without exposing its value.
pub fn validate_basic_auth_hmac_secret(secret: &str) -> Result<(), String> {
    if secret.len() < MIN_BASIC_AUTH_HMAC_SECRET_LENGTH {
        return Err(format!(
            "FERRUM_BASIC_AUTH_HMAC_SECRET must be at least {} bytes",
            MIN_BASIC_AUTH_HMAC_SECRET_LENGTH
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) enum BasicAuthCredentialPreparationError {
    InvalidCredential(String),
    ServerConfiguration(String),
}

impl std::fmt::Display for BasicAuthCredentialPreparationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCredential(message) | Self::ServerConfiguration(message) => {
                formatter.write_str(message)
            }
        }
    }
}

fn basic_auth_credential_error(
    credential: &serde_json::Map<String, serde_json::Value>,
) -> Option<&'static str> {
    if credential.len() != 1 {
        return Some("must contain exactly one of 'password' or 'password_hash'");
    }

    if let Some(password) = credential.get("password") {
        return match password.as_str() {
            Some("") => Some("password must not be empty"),
            Some(password) if password.chars().count() > MAX_CREDENTIAL_VALUE_LENGTH => {
                Some("password must not exceed 4096 characters")
            }
            Some(password) if contains_control_chars(password) => {
                Some("password must not contain control characters")
            }
            Some(_) => None,
            None => Some("password must be a string"),
        };
    }

    if let Some(password_hash) = credential.get("password_hash") {
        let valid = password_hash.as_str().is_some_and(|password_hash| {
            password_hash
                .strip_prefix("hmac_sha256:")
                .is_some_and(|hex_hash| {
                    hex_hash.len() == 64
                        && hex_hash
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
        });
        return (!valid).then_some(
            "password_hash must be a string in 'hmac_sha256:<64 lowercase hex>' format",
        );
    }

    Some("must contain exactly one of 'password' or 'password_hash'")
}
/// Maximum number of ACL groups per consumer.
pub const MAX_ACL_GROUPS_PER_CONSUMER: usize = 500;
/// Maximum length for an ACL group name.
pub const MAX_ACL_GROUP_LENGTH: usize = 255;
/// Maximum length for hash_on field in upstream.
pub const MAX_HASH_ON_LENGTH: usize = 255;
/// Maximum number of status codes in circuit breaker / retry / health check lists.
/// Allows any bounded subset of the valid HTTP status-code range (100-599),
/// including translated Istio retry expressions such as `5xx` plus explicit
/// non-5xx codes.
pub const MAX_STATUS_CODES: usize = 500;
/// Maximum number of retryable methods.
pub const MAX_RETRYABLE_METHODS: usize = 9;
/// Maximum length for file path fields (TLS cert/key paths).
pub const MAX_FILE_PATH_LENGTH: usize = 4096;
/// Maximum size for inline PEM TLS material in config fields.
pub const MAX_TLS_INLINE_PEM_LENGTH: usize = 1_048_576; // 1 MiB
/// Maximum length for service discovery optional string fields.
pub const MAX_SD_STRING_LENGTH: usize = 255;

// ---- Numeric range limits ----

/// Maximum timeout value in milliseconds (24 hours).
pub const MAX_TIMEOUT_MS: u64 = 86_400_000;
/// Maximum timeout value in seconds (24 hours).
pub const MAX_TIMEOUT_SECONDS: u64 = 86_400;
/// Maximum for threshold fields (circuit breaker, health checks).
pub const MAX_THRESHOLD: u32 = 10_000;
/// Maximum entries in the passive health recent_failures map per target.
/// Prevents unbounded memory growth during cascading failure scenarios.
/// Also acts as the upper bound for `PassiveHealthCheck::unhealthy_threshold`
/// validation — a threshold above this cap could never trip reliably because
/// the map is hard-capped at this size.
pub const MAX_RECENT_FAILURES_PER_TARGET: usize = 1000;
/// Maximum retry count.
pub const MAX_RETRIES: u32 = 100;
/// Maximum backoff delay in milliseconds (5 minutes).
pub const MAX_BACKOFF_MS: u64 = 300_000;
/// Maximum target weight.
pub const MAX_TARGET_WEIGHT: u32 = 65_535;
/// Maximum service discovery poll interval in seconds (1 hour).
pub const MAX_SD_POLL_INTERVAL: u64 = 3600;
/// Maximum health check interval in seconds (1 hour).
pub const MAX_HEALTH_CHECK_INTERVAL: u64 = 3600;
/// Maximum UDP idle timeout in seconds (1 hour).
pub const MAX_UDP_IDLE_TIMEOUT: u64 = 3600;
/// Maximum TCP idle timeout in seconds (24 hours).
pub const MAX_TCP_IDLE_TIMEOUT: u64 = 86_400;
/// Maximum WebSocket idle timeout in seconds (24 hours). WebSocket sessions are
/// long-lived streams, so the ceiling matches TCP rather than the 1-hour pool cap.
pub const MAX_WEBSOCKET_IDLE_TIMEOUT: u64 = 86_400;
/// Maximum pool idle timeout in seconds (1 hour).
pub const MAX_POOL_IDLE_TIMEOUT: u64 = 3600;
/// Maximum DNS cache TTL in seconds (24 hours).
pub const MAX_DNS_CACHE_TTL: u64 = 86_400;
/// Minimum HTTP/2 initial window size (RFC 9113 §6.9.2: 64 KiB default).
pub const MIN_HTTP2_WINDOW_SIZE: u32 = 65_535;
/// Maximum HTTP/2 initial window size (128 MiB practical operational limit).
pub const MAX_HTTP2_WINDOW_SIZE: u32 = 128 * 1024 * 1024;
/// Minimum HTTP/2 max frame size (RFC 9113 §6.5.2: 16 KiB).
pub const MIN_HTTP2_MAX_FRAME_SIZE: u32 = 16_384;
/// Maximum HTTP/2 max frame size (1 MiB practical operational limit).
pub const MAX_HTTP2_MAX_FRAME_SIZE: u32 = 1_048_576;
/// Maximum value for proxy pool integer fields stored in SQL INTEGER columns.
pub const MAX_POOL_SQL_INTEGER_VALUE: u64 = i32::MAX as u64;
/// Maximum HTTP/3 connections per backend (reasonable operational limit).
pub const MAX_HTTP3_CONNECTIONS_PER_BACKEND: usize = 256;

/// Valid HTTP methods for allowed_methods and retryable_methods validation.
pub const VALID_HTTP_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT",
];

/// Regex pattern for valid resource IDs.
/// Must start with alphanumeric, followed by alphanumeric, dots, underscores, or hyphens.
static ID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$").expect("invalid ID regex"));

/// Regex for valid exact hostnames: lowercase letters, digits, dots, hyphens.
static HOST_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$").expect("invalid host regex"));

/// Regex for wildcard host patterns: *.domain.tld
static WILDCARD_HOST_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\*\.[a-z0-9]([a-z0-9.-]*[a-z0-9])?$").expect("invalid wildcard host regex")
});

/// Validate a resource ID format.
///
/// Valid IDs must:
/// - Be non-empty and at most 254 characters
/// - Start with an alphanumeric character
/// - Contain only alphanumeric characters, dots, underscores, or hyphens
///
/// Returns `Ok(())` if valid, or `Err(message)` describing the violation.
pub fn validate_resource_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("ID must not be empty".to_string());
    }
    if id.len() > MAX_ID_LENGTH {
        return Err(format!(
            "ID must be at most {} characters, got {}",
            MAX_ID_LENGTH,
            id.len()
        ));
    }
    if !ID_REGEX.is_match(id) {
        return Err(format!(
            "ID '{}' is invalid: must start with an alphanumeric character and contain only \
             alphanumeric characters, dots, underscores, or hyphens",
            id
        ));
    }
    Ok(())
}

/// Load balancing algorithm for distributing requests across upstream targets.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancerAlgorithm {
    #[default]
    RoundRobin,
    WeightedRoundRobin,
    LeastConnections,
    LeastLatency,
    ConsistentHashing,
    Random,
    /// Istio `loadBalancer.simple=PASSTHROUGH`: dial the original destination
    /// the client addressed, bypassing load balancing. Only meaningful when a
    /// captured original-destination is available (mesh capture paths) AND it
    /// matches a target in the upstream's pool; the request path
    /// (`select_upstream_target`) intercepts this algorithm to do the orig-dst
    /// match. When orig-dst is absent or unmatched, selection falls back to
    /// round-robin, so the balancer's internal selectors treat `Passthrough`
    /// exactly like `RoundRobin` (no hash ring / WRR / latency state is built
    /// for it at construction).
    Passthrough,
}

/// Per-subset traffic policy overrides (Istio DestinationRule subset.trafficPolicy).
///
/// When a subset is selected for routing, these overrides replace the upstream's
/// default settings for the matching subset targets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SubsetTrafficPolicy {
    /// Override the upstream's load balancer algorithm for this subset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_balancer_algorithm: Option<LoadBalancerAlgorithm>,
    /// Hash-key source for subset-scoped consistent hashing. Uses the same
    /// format as [`Upstream::hash_on`]: `"ip"`, `"header:<name>"`, or
    /// `"cookie:<name>"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_on: Option<String>,
    /// Override the upstream's backend TLS posture for targets selected via
    /// this subset (Istio `subsets[].trafficPolicy.tls`). The cold-path
    /// `apply_destination_rules` overlays this on the upstream-level TLS and
    /// stores the resulting `BackendTlsConfig` in
    /// [`Upstream::resolved_subset_tls`], where it is projected onto
    /// `Proxy.resolved_tls` for proxies whose `upstream_subset` selects this
    /// subset. Nested as `MeshTrafficPolicyTls` (mode / SNI / CA / mTLS
    /// material / SAN allow-list / `insecureSkipVerify`) to keep this struct
    /// small and to share the SVID/SAN/SNI projection logic with the
    /// upstream-level apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<crate::modes::mesh::config::MeshTrafficPolicyTls>,
    /// Override the upstream's backend connect timeout (ms) for this subset
    /// (Istio `subsets[].trafficPolicy.connectionPool.tcp.connectTimeout`).
    /// `apply_destination_rules` projects this onto `backend_connect_timeout_ms`
    /// of every proxy whose `upstream_subset` selects this subset, taking
    /// precedence over the DestinationRule's top-level `connectTimeout`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,
    /// Per-subset passive health (Istio `subsets[].trafficPolicy.outlierDetection`),
    /// already resolved from the Istio outlier shape. The ejection *thresholds*
    /// (consecutive errors, interval, base-ejection time, min-health) are
    /// consulted per-subset by `passive_health_for_target` for proxies bound to
    /// this subset, overriding the upstream-level passive health. The
    /// `maxEjectionPercent` *cap* is also resolved per-subset, by
    /// `LoadBalancerCache::max_ejection_percent_resolved_from` with the SAME
    /// per-port > per-subset > upstream tier precedence as the thresholds, so
    /// the cap and the thresholds come from the same tier. The cap is also
    /// scoped to the subset's candidate pool (the denominator is the subset
    /// target count, not the whole upstream). The per-port cap tier applies
    /// only when a single dispatch port is resolvable pre-selection (non-subset
    /// dispatch, single-port upstreams, or port-pinned retries); for a
    /// subset-routed dispatch on a multi-port upstream the subset cap governs
    /// (see `max_ejection_percent_resolved_from`'s pre-selection-asymmetry note).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passive_health_check: Option<PassiveHealthCheck>,
}

/// Whether plain-HTTP backend dispatch may upgrade to HTTP/2.
///
/// Mapped from Istio DestinationRule
/// `connectionPool.http.h2UpgradePolicy`. Only the plain-HTTPS h1-vs-h2
/// dispatch fork in `proxy_to_backend` consults this — it does NOT touch
/// gRPC (always H2), HBONE, or mesh-mTLS transport selection. Projected
/// onto `Proxy.h2_upgrade_policy` per target port.
///
/// All three Istio values are represented. `Default` and `None` (field
/// absent) are treated identically by dispatch — probe-driven — but they are
/// kept distinct in the typed model so an EXPLICIT port-level `DEFAULT` can
/// CLEAR an inherited top-level `UPGRADE`/`DO_NOT_UPGRADE` for that port
/// (operator explicitly chose probe-driven), whereas an OMITTED port-level
/// value leaves the inherited slot untouched. See
/// `apply_connection_pool_http_to_port_override` in `src/modes/mesh/mod.rs`.
///
/// **Serde names** match the operator-facing Istio surface, not Rust variant
/// spelling: `SCREAMING_SNAKE_CASE` (`DEFAULT` / `UPGRADE` / `DO_NOT_UPGRADE`)
/// like the sibling mesh enum `MeshSimpleLb`. This enum is serde-deserialized on
/// the native/file mesh config path (`MeshConnectionPoolHttp.h2_upgrade_policy`
/// for `FERRUM_MESH_CONFIG_PROTOCOL=file`) and round-tripped through the xDS
/// `MeshSliceCarrier`, so a slice authored with the Istio value must
/// deserialize. The lowercase/snake aliases (`do_not_upgrade`, etc.) are also
/// accepted for ergonomics. The K8s/Istio translator parses the CRD string
/// manually in `translate_h2_upgrade_policy` (not via serde), so this naming is
/// independent of that path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum H2UpgradePolicy {
    /// Istio `DEFAULT`: probe-driven. Behaves identically to "field absent"
    /// at the dispatch fork, but as an EXPLICIT port-level value it clears an
    /// inherited top-level `Upgrade`/`DoNotUpgrade` (back to probe-driven for
    /// that port). Carried (not collapsed to `None` at parse) so absent and
    /// explicit-`DEFAULT` are distinguishable in port-level merge semantics.
    #[serde(alias = "default")]
    Default,
    /// Istio `UPGRADE`: prefer HTTP/2 to the backend. Used as a hint when
    /// the capability registry has not yet classified the target
    /// (`Unknown` → try direct-H2 instead of defaulting to reqwest/H1).
    /// Stays fail-safe: a target proven `Unsupported` (e.g. ALPN
    /// negotiated H1) is NOT forced onto H2.
    #[serde(alias = "upgrade")]
    Upgrade,
    /// Istio `DO_NOT_UPGRADE`: force the HTTP/1.1 path (reqwest). Skips the
    /// direct-H2 pool even when the capability registry marks the target
    /// `h2_tls` Supported, and restricts the reqwest client's ALPN to
    /// `http/1.1` so the backend cannot ALPN-negotiate h2 either. (A
    /// backend-TLS SNI override still requires direct-H2 because reqwest
    /// cannot apply a per-request SNI — that case wins and is documented.)
    #[serde(alias = "do_not_upgrade")]
    DoNotUpgrade,
}

/// Per-destination-port traffic policy overrides on an upstream.
///
/// Populated from an Istio DestinationRule's `trafficPolicy.portLevelSettings[]`
/// (see [`crate::modes::mesh::config::MeshDestinationRule::port_level_settings`]).
/// The gateway projects these into [`ResolvedPortOverride`] on each referencing
/// `Proxy` during config resolution so request dispatch can consult a
/// precomputed map instead of re-deriving DestinationRule policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct UpstreamPortOverride {
    /// Per-port backend connect timeout override (milliseconds). Consulted on
    /// the dispatch hot path when the resolved destination port matches a key
    /// in `Upstream.port_overrides`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,
    /// Per-port load-balancing algorithm override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<LoadBalancerAlgorithm>,
    /// Per-port consistent-hash key override. Uses the same `"ip"`,
    /// `"header:<name>"`, and `"cookie:<name>"` syntax as `Upstream.hash_on`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_on: Option<String>,
    /// Per-port passive health override mapped from DestinationRule
    /// `outlierDetection`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passive_health_check: Option<PassiveHealthCheck>,
    /// Per-port locality LB override mapped from DestinationRule
    /// `portLevelSettings[].loadBalancer.localityLbSetting`. When present,
    /// HTTP-family / gRPC / WebSocket / HBONE dispatch consults this before
    /// the upstream-level `Upstream.locality_lb_setting`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locality_lb_setting: Option<UpstreamLocalityLbSetting>,
    /// Per-port cap on concurrent open backend connections, mapped from
    /// DestinationRule `connectionPool.tcp.maxConnections`. Enforced by
    /// stream-family (TCP / TCP+TLS) backend dispatch and by the HTTP-family
    /// **WebSocket** dispatch path (H1/H2 and H3), each of which opens one
    /// dedicated backend connection per session/relay whose lifetime an RAII
    /// guard can bound — matching Envoy `maxConnections` semantics. The cap is
    /// keyed per resolved `(host, port)` endpoint, not per logical cluster, so
    /// an upstream with N endpoint hosts on one port has an effective ceiling
    /// of N×cap (equivalent to Envoy's per-cluster total for a single-host
    /// destination).
    ///
    /// The pooled, multiplexed HTTP-family transports (reqwest H1/H2, direct
    /// H2, gRPC, HTTP/3, HBONE) do **not** enforce this field: their backend
    /// connections are created and reused inside connection pools, so "open a
    /// new backend connection" is decoupled from the request hot path by pool
    /// reuse, sharding, and idle eviction, and a request-keyed counter would
    /// measure request concurrency rather than open connections. See
    /// `docs/mesh.md` and `src/backend_conn_limit.rs` for the rationale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,
    /// Per-port TCP keepalive overrides, mapped from DestinationRule
    /// `connectionPool.tcp.tcpKeepalive`. Currently applied only by
    /// stream-family backend dispatch on the newly connected backend socket
    /// (HTTP-family dispatch is a follow-on PR).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_keepalive: Option<TcpKeepaliveCfg>,
    /// Legacy carrier for DestinationRule
    /// `connectionPool.http.maxRequestsPerConnection`.
    ///
    /// New translation does not populate this field, and
    /// `resolve_effective_proxy_for_target` intentionally ignores any legacy
    /// carried value because Ferrum has no backend close-after-N-requests
    /// runtime behavior. K8s status reports the DR field as deferred instead of
    /// presenting this as effective policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_max_requests_per_connection: Option<u32>,
    /// Per-port HTTP idle-timeout mapped from DestinationRule
    /// `connectionPool.http.idleTimeout` (milliseconds). Projected onto the
    /// per-target effective proxy's `pool_idle_timeout_seconds` (whole
    /// seconds, with sub-second values rejected at translate time).
    ///
    /// On the reqwest pool this value is part of the client-behavior (`rcfg`)
    /// pool-key segment, so divergent per-port idle timeouts isolate distinct
    /// shared clients rather than first-creator-wins leaking. Direct-H2 / gRPC
    /// pool keys still exclude several builder-only knobs (see those pools'
    /// first-materializer notes). Request-only connect timeouts remain
    /// per-request and do not fragment any pool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_idle_timeout_ms: Option<u64>,
    /// Per-port HTTP/2 concurrent-streams cap mapped from DestinationRule
    /// `connectionPool.http.http2MaxRequests`. Projected onto the per-target
    /// effective proxy's `pool_http2_max_concurrent_streams` and threaded
    /// into the H2/gRPC backend builders via
    /// `http2::Builder::max_concurrent_streams` (peer SETTINGS) and
    /// `initial_max_send_streams` (local outbound-stream initial cap).
    /// Applies to direct-H2 and gRPC pool entries; reqwest's H2 path does
    /// not expose the same builder knob today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h2_max_concurrent_streams: Option<u32>,
    /// Per-port backend TLS posture, mapped from DestinationRule
    /// `portLevelSettings[].tls`. Resolved against the upstream-level TLS at
    /// apply time and projected onto the per-target effective proxy's
    /// `resolved_tls` by `resolve_effective_proxy_for_target`, taking
    /// precedence over the upstream-/subset-level TLS for dials to this port.
    /// `resolved_tls` identity fields (CA, cert/key, SNI, SAN, verify) are part
    /// of the backend pool key, so a distinct per-port TLS posture fragments
    /// its own pool rather than sharing a connection with another port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<BackendTlsConfig>,
    /// Per-port HTTP/2 upgrade policy, mapped from DestinationRule
    /// `connectionPool.http.h2UpgradePolicy`. Projected onto the per-target
    /// effective proxy's `h2_upgrade_policy` and consulted at the
    /// plain-HTTPS H2-vs-H1 dispatch fork. `DEFAULT`/absent leaves probe-driven
    /// behavior unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h2_upgrade_policy: Option<H2UpgradePolicy>,
    /// Per-port retry-count cap, mapped from DestinationRule
    /// `connectionPool.http.maxRetries`. Interpreted as an upper bound on the
    /// per-request `Proxy.retry.max_retries` (NOT Envoy's cluster-wide
    /// outstanding-retry budget — see `docs/mesh.md`). Applied via
    /// `cap_proxy_retry_for_target` once the dispatch target port is known:
    /// effective `max_retries = min(existing, this)`; never increases retries
    /// and never synthesizes a retry policy when the proxy has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_retries: Option<u32>,
    /// Per-port cap on concurrent *pending* (connection-waiting) HTTP/1.1
    /// requests, mapped from DestinationRule
    /// `connectionPool.http.http1MaxPendingRequests`. Enforced on the
    /// reqwest/HTTP-1.1 backend-dispatch path by
    /// [`crate::backend_pending_limit::BackendPendingLimiter`]: a request that
    /// cannot get a pending slot is shed with a 503 ("upstream overflow") in
    /// the connection-pending phase, rather than queued unboundedly. Projected
    /// onto the per-target effective proxy's `pool_http1_max_pending_requests`.
    /// The cap is keyed per resolved `(host, port)` endpoint, not per logical
    /// cluster (same keying tradeoff as `max_connections`).
    ///
    /// HTTP/1.1-scoped: the multiplexed transports (direct H2, gRPC, HTTP/3,
    /// HBONE, mesh-mTLS) do NOT consult this field — their request concurrency
    /// is governed by `http2MaxRequests` (`h2_max_concurrent_streams`), not a
    /// connection-pending queue. Always positive when set (zero rejected at
    /// translate time).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http1_max_pending_requests: Option<u32>,
}

/// Per-target TCP keepalive override. Mirrors Istio's
/// `ConnectionPoolSettings.TCPSettings.TcpKeepalive` (time/interval/probes)
/// but stores integer seconds so the schema round-trips through serde without
/// pulling in Istio duration parsing on the apply side. Translation from
/// `google.protobuf.Duration` happens at the K8s translator boundary.
///
/// Fields are independently optional so operators can configure only the knobs
/// they care about (e.g. just `time_seconds` to extend the idle probe delay).
/// Sub-second durations are rejected at translate time — the underlying
/// `TCP_KEEPIDLE` / `TCP_KEEPINTVL` socket options are specified in seconds on
/// every supported platform.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TcpKeepaliveCfg {
    /// Idle time before the first keepalive probe (`TCP_KEEPIDLE` on Linux,
    /// `TCP_KEEPALIVE` on macOS/iOS). Always positive when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_seconds: Option<u32>,
    /// Interval between successive keepalive probes (`TCP_KEEPINTVL`).
    /// Always positive when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_seconds: Option<u32>,
    /// Maximum number of unacknowledged probes before declaring the
    /// connection dead (`TCP_KEEPCNT`). Always positive when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probes: Option<u32>,
}

impl TcpKeepaliveCfg {
    /// `true` when no field is set — used by translators to avoid emitting an
    /// empty override on the upstream slot.
    pub fn is_empty(&self) -> bool {
        self.time_seconds.is_none() && self.interval_seconds.is_none() && self.probes.is_none()
    }
}

/// Cold-path projection of an [`UpstreamPortOverride`] onto a `Proxy`.
///
/// This is intentionally skipped during serde because it is derived state:
/// upstreams own the mesh policy, proxies cache the small per-port view needed
/// by request dispatch.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ResolvedPortOverride {
    pub connect_timeout_ms: Option<u64>,
    pub algorithm: Option<LoadBalancerAlgorithm>,
    pub hash_on: Option<String>,
    pub passive_health_check: Option<PassiveHealthCheck>,
    pub locality_lb_setting: Option<UpstreamLocalityLbSetting>,
    pub max_connections: Option<u32>,
    pub tcp_keepalive: Option<TcpKeepaliveCfg>,
    pub http_max_requests_per_connection: Option<u32>,
    pub http_idle_timeout_ms: Option<u64>,
    pub h2_max_concurrent_streams: Option<u32>,
    pub tls: Option<BackendTlsConfig>,
    pub h2_upgrade_policy: Option<H2UpgradePolicy>,
    pub max_retries: Option<u32>,
    pub http1_max_pending_requests: Option<u32>,
}

impl ResolvedPortOverride {
    pub fn from_upstream_override(value: &UpstreamPortOverride) -> Option<Self> {
        let mut tls = value.tls.clone();
        if let Some(tls) = &mut tls {
            tls.normalize_fields();
        }
        let resolved = Self {
            connect_timeout_ms: value.connect_timeout_ms,
            algorithm: value.algorithm,
            hash_on: value.hash_on.clone(),
            passive_health_check: value.passive_health_check.clone(),
            locality_lb_setting: value.locality_lb_setting.clone(),
            max_connections: value.max_connections,
            tcp_keepalive: value.tcp_keepalive.clone(),
            http_max_requests_per_connection: value.http_max_requests_per_connection,
            http_idle_timeout_ms: value.http_idle_timeout_ms,
            h2_max_concurrent_streams: value.h2_max_concurrent_streams,
            tls,
            h2_upgrade_policy: value.h2_upgrade_policy,
            max_retries: value.max_retries,
            http1_max_pending_requests: value.http1_max_pending_requests,
        };
        (!resolved.is_empty()).then_some(resolved)
    }

    fn is_empty(&self) -> bool {
        self.connect_timeout_ms.is_none()
            && self.algorithm.is_none()
            && self.hash_on.is_none()
            && self.passive_health_check.is_none()
            && self.locality_lb_setting.is_none()
            && self.max_connections.is_none()
            && self.tcp_keepalive.is_none()
            && self.http_max_requests_per_connection.is_none()
            && self.http_idle_timeout_ms.is_none()
            && self.h2_max_concurrent_streams.is_none()
            && self.tls.is_none()
            && self.h2_upgrade_policy.is_none()
            && self.max_retries.is_none()
            && self.http1_max_pending_requests.is_none()
    }

    /// Field-by-field seed of the `connectionPool.http` fields from a
    /// service-discovery TOP-LEVEL fallback overlay onto this (per-port) entry.
    ///
    /// For each supported `connectionPool.http` field, the per-port value wins
    /// when set; otherwise the fallback's value is inherited. This mirrors
    /// Ferrum's documented NON-SD apply-time field-level merge exactly: there,
    /// the top-level
    /// `connectionPool.http` is fanned onto the port slot FIRST and a partial
    /// per-port `portLevelSettings.connectionPool.http` then overlays only the
    /// fields it sets (see `apply_connection_pool_http_to_port_override` in
    /// `src/modes/mesh/mod.rs`). SD upstreams cannot fan out at apply time, so
    /// the top-level overlay is carried separately on
    /// `Proxy.dispatch_port_override_fallback` and merged HERE at dispatch — so
    /// an unrelated per-port field (e.g. `connectTimeout`/`tls`) no longer wipes
    /// an inherited top-level `idleTimeout`/`http2MaxRequests`/`maxRetries`.
    ///
    /// Only `connectionPool.http` fields are merged; the fallback only ever
    /// carries those (it is built solely from the DR top-level
    /// `connectionPool.http` block), so non-`connectionPool.http` fields
    /// (`connect_timeout_ms`/`algorithm`/`tls`/`max_connections`/… ) are left as
    /// this per-port entry already has them.
    pub fn seed_connection_pool_http_from_fallback(&mut self, fallback: &ResolvedPortOverride) {
        self.http_max_requests_per_connection = self
            .http_max_requests_per_connection
            .or(fallback.http_max_requests_per_connection);
        self.http_idle_timeout_ms = self.http_idle_timeout_ms.or(fallback.http_idle_timeout_ms);
        self.h2_max_concurrent_streams = self
            .h2_max_concurrent_streams
            .or(fallback.h2_max_concurrent_streams);
        self.h2_upgrade_policy = self.h2_upgrade_policy.or(fallback.h2_upgrade_policy);
        self.max_retries = self.max_retries.or(fallback.max_retries);
        self.http1_max_pending_requests = self
            .http1_max_pending_requests
            .or(fallback.http1_max_pending_requests);
    }
}

/// Project an upstream's service-discovery TOP-LEVEL `connectionPool.http`
/// overlay (`Upstream.dispatch_port_override_fallback`) into the resolved
/// [`ResolvedPortOverride`] shape carried on a referencing `Proxy`
/// (`Proxy.dispatch_port_override_fallback`).
///
/// Returns `None` for the common non-SD case (no top-level overlay) and for an
/// overlay that resolves empty. Shared by config-build projection
/// ([`GatewayConfig::resolve_dispatch_port_overrides`]) and the route-override
/// path (`apply_route_overrides_inner` in `src/plugins/mod.rs`) so a route that
/// swaps the destination upstream recomputes (or clears) the fallback exactly
/// like `dispatch_port_overrides`, never leaking one upstream's overlay onto a
/// different destination.
pub(crate) fn dispatch_port_override_fallback_from_upstream(
    upstream: &Upstream,
) -> Option<ResolvedPortOverride> {
    // TOP-LEVEL `connectionPool.http` overlay ONLY.
    // An explicit per-port `portLevelSettings` still WINS via the dispatch-time
    // per-port lookup in `resolve_effective_proxy_for_target`: discovered mesh
    // targets carry their owning declared Service port in
    // `UpstreamTarget.service_port_policy_key`, while ordinary targets key by
    // their resolved dial port.
    // We deliberately do NOT fold the upstream's `port_overrides` into this fallback:
    // a multi-port upstream would cross-leak one port's `connectionPool.http` onto a
    // different port (codex r3). Immediate route-rebuild on a DR-only edit remains
    // tracked separately because this is a `#[serde(skip)]` DR-derived field, like
    // the established per-port `dispatch_port_overrides`.
    upstream
        .dispatch_port_override_fallback
        .as_ref()
        .and_then(ResolvedPortOverride::from_upstream_override)
}

/// A named subset of upstream targets identified by label selectors.
///
/// Targets whose `tags` are a superset of `labels` belong to this subset.
/// Used for Istio DestinationRule subset routing: a proxy's `upstream_subset`
/// field selects a named subset, and the load balancer pre-filters targets
/// to only those matching the subset's labels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SubsetDefinition {
    pub name: String,
    pub labels: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic_policy: Option<SubsetTrafficPolicy>,
}

/// Cold-path projection of a `SubsetTrafficPolicy` onto a resolved hot-path
/// slot.
///
/// Same pattern as [`ResolvedPortOverride`]: the upstream owns the mesh-derived
/// policy ([`SubsetTrafficPolicy`]) and the gateway pre-computes the resolved
/// view at cold-path apply so request dispatch never re-derives the
/// DestinationRule TLS overlay. Currently carries only `tls`; future fields
/// (subset-scoped connectionPool, outlierDetection, etc.) live here too.
///
/// Stored on [`Upstream::resolved_subset_tls`] keyed by subset name and
/// projected onto `Proxy.resolved_tls` by
/// [`GatewayConfig::resolve_upstream_tls`] when a proxy's `upstream_subset`
/// selects a subset that carries a TLS override.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ResolvedSubsetTrafficPolicy {
    /// Subset-resolved backend TLS posture. `Some` when the subset's
    /// `trafficPolicy.tls` overlay produced a non-empty override (subset TLS
    /// is layered over the upstream-level TLS and stored fully resolved here,
    /// so the hot path can swap one `BackendTlsConfig` for another without
    /// re-running the overlay).
    pub tls: Option<BackendTlsConfig>,
    /// Subset-resolved passive health (ejection thresholds AND the
    /// `maxEjectionPercent` cap), from the subset's `outlierDetection`. `Some`
    /// when the subset configured outlier detection; consulted by
    /// `passive_health_for_target` ahead of the upstream-level passive health for
    /// proxies bound to this subset. The `maxEjectionPercent` cap is resolved
    /// per-subset by `LoadBalancerCache::max_ejection_percent_resolved_from`
    /// (reading this overlay), with the SAME per-port > per-subset > upstream
    /// tier precedence as the thresholds, and is scoped to the subset's
    /// candidate pool (denominator = subset target count). The per-port tier
    /// applies only when a single dispatch port is resolvable pre-selection;
    /// for subset dispatch on a multi-port upstream the subset cap governs.
    pub passive_health_check: Option<PassiveHealthCheck>,
}

impl ResolvedSubsetTrafficPolicy {
    /// Build from a fully-resolved subset TLS and/or passive-health overlay.
    /// Returns `None` when neither is present (so callers can skip inserting
    /// empty entries into [`Upstream::resolved_subset_tls`]).
    pub fn new(
        tls: Option<BackendTlsConfig>,
        passive_health_check: Option<PassiveHealthCheck>,
    ) -> Option<Self> {
        let resolved = Self {
            tls,
            passive_health_check,
        };
        (!resolved.is_empty()).then_some(resolved)
    }

    fn is_empty(&self) -> bool {
        self.tls.is_none() && self.passive_health_check.is_none()
    }
}

/// A single backend target within an upstream group.
pub const UPSTREAM_TARGET_SERVICE_NAMESPACE_TAG: &str = "_ferrum_service_namespace";
pub const UPSTREAM_TARGET_SERVICE_NAME_TAG: &str = "_ferrum_service_name";
pub const UPSTREAM_TARGET_SERVICE_PORT_TAG: &str = "_ferrum_service_port";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamTarget {
    pub host: String,
    pub port: u16,
    /// Internal DestinationRule policy key for discovered mesh targets whose
    /// declared Service port differs from the resolved workload dial port.
    ///
    /// `port` remains the actual connection destination. This field is derived
    /// during materialization and skipped by serde so file/admin config cannot
    /// set it.
    #[serde(default, skip)]
    pub service_port_policy_key: Option<u16>,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default)]
    pub tags: HashMap<String, String>,
    /// Optional Istio-style `region/zone/subzone` locality for this target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    /// Optional path prefix that overrides the proxy's `backend_path` when this
    /// target is selected by the load balancer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl UpstreamTarget {
    /// DestinationRule `portLevelSettings` key that governs this target.
    ///
    /// Static targets and ordinary discovery targets use their dial port. Mesh
    /// Service discovery can stamp the owning declared Service port when
    /// Kubernetes `targetPort` resolves to a different workload port.
    #[inline]
    pub fn dispatch_policy_port(&self) -> u16 {
        self.service_port_policy_key.unwrap_or(self.port)
    }
}

/// Parsed locality preference used by the load balancer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalityPreference {
    pub region: String,
    pub zone: Option<String>,
    pub sub_zone: Option<String>,
}

impl LocalityPreference {
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }

        let mut parts = trimmed.splitn(3, '/').map(str::trim);
        let region = parts.next()?.to_string();
        if region.is_empty() {
            return None;
        }
        let zone = parts
            .next()
            .filter(|part| !part.is_empty())
            .map(ToString::to_string);
        let sub_zone = parts
            .next()
            .filter(|part| !part.is_empty())
            .map(ToString::to_string);

        Some(Self {
            region,
            zone,
            sub_zone,
        })
    }

    #[inline]
    pub fn exact_matches(&self, target: &Self) -> bool {
        self.region == target.region && self.zone == target.zone && self.sub_zone == target.sub_zone
    }

    #[inline]
    pub fn same_zone(&self, target: &Self) -> bool {
        self.region == target.region && self.zone.is_some() && self.zone == target.zone
    }

    #[inline]
    pub fn same_region(&self, target: &Self) -> bool {
        self.region == target.region
    }
}

fn default_weight() -> u32 {
    1
}

/// Resolved projection of Istio
/// `DestinationRule.trafficPolicy.localityLbSetting` onto an `Upstream`.
///
/// `enabled` defaults to `true` (matches Istio semantics — an explicit
/// `enabled: false` disables locality preference, distribute weighting,
/// and failover override entirely). `distribute` and `failover` are
/// mutually exclusive at evaluation time: when a `distribute` entry
/// matches the source locality the load balancer uses per-locality
/// weights and skips the priority tier preference; otherwise `failover`
/// (when configured) supplies a fourth tier consulted after `region`
/// and before the unfiltered fallback set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpstreamLocalityLbSetting {
    #[serde(default = "default_true_locality_lb_enabled")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub distribute: Vec<LocalityDistribute>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failover: Vec<LocalityFailover>,
}

fn default_true_locality_lb_enabled() -> bool {
    true
}

impl Default for UpstreamLocalityLbSetting {
    fn default() -> Self {
        Self {
            enabled: true,
            distribute: Vec::new(),
            failover: Vec::new(),
        }
    }
}

/// One `localityLbSetting.distribute[]` entry. `from` is an Istio-style
/// `region/zone/subzone` locality string; `to` maps target localities
/// (same syntax) to integer weights. Istio treats the values as
/// percentages summing to 100; we propagate the integers verbatim and use
/// them as ratios so non-summing operator configs still produce a
/// deterministic split.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalityDistribute {
    pub from: String,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub to: std::collections::BTreeMap<String, u32>,
}

/// One `localityLbSetting.failover[]` entry. `from` and `to` are Istio
/// region names (the first `region/zone/subzone` segment of a locality).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalityFailover {
    pub from: String,
    pub to: String,
}

/// Health check probe type.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HealthProbeType {
    /// HTTP GET probe (default). Sends a request to `http_path` and checks status code.
    #[default]
    Http,
    /// TCP probe. Attempts a TCP connection — success means healthy.
    Tcp,
    /// UDP probe. Sends `udp_probe_payload` and expects any response within timeout.
    Udp,
    /// gRPC health check using the standard grpc.health.v1.Health/Check RPC.
    Grpc,
}

/// Active health check configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveHealthCheck {
    #[serde(default = "default_health_path")]
    pub http_path: String,
    #[serde(default = "default_health_interval")]
    pub interval_seconds: u64,
    #[serde(default = "default_health_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
    #[serde(default = "default_healthy_status_codes")]
    pub healthy_status_codes: Vec<u16>,
    /// Use HTTPS for health check probes instead of HTTP.
    #[serde(default)]
    pub use_tls: bool,
    /// Probe type: `http` (default), `tcp`, or `udp`.
    #[serde(default)]
    pub probe_type: HealthProbeType,
    /// Hex-encoded probe payload for UDP health checks.
    /// Sent to the target; any response within timeout means healthy.
    #[serde(default)]
    pub udp_probe_payload: Option<String>,
    /// Service name for gRPC health check requests (grpc.health.v1.Health/Check).
    /// Empty string (default) checks overall server health.
    #[serde(default)]
    pub grpc_service_name: Option<String>,
}

impl Default for ActiveHealthCheck {
    fn default() -> Self {
        Self {
            http_path: default_health_path(),
            interval_seconds: default_health_interval(),
            timeout_ms: default_health_timeout(),
            healthy_threshold: default_healthy_threshold(),
            unhealthy_threshold: default_unhealthy_threshold(),
            healthy_status_codes: default_healthy_status_codes(),
            use_tls: false,
            probe_type: HealthProbeType::default(),
            udp_probe_payload: None,
            grpc_service_name: None,
        }
    }
}

fn default_health_path() -> String {
    "/health".to_string()
}
fn default_health_interval() -> u64 {
    10
}
fn default_health_timeout() -> u64 {
    5000
}
fn default_healthy_threshold() -> u32 {
    3
}
fn default_unhealthy_threshold() -> u32 {
    3
}
fn default_healthy_status_codes() -> Vec<u16> {
    vec![200, 302]
}

/// Passive health check configuration.
///
/// When a target accumulates `unhealthy_threshold` failures (matching
/// `unhealthy_status_codes`) within `unhealthy_window_seconds`, it is
/// marked unhealthy and removed from the load balancer rotation.
///
/// Recovery happens via two mechanisms:
/// 1. **Automatic timer**: After `healthy_after_seconds` (default 30s),
///    the target is automatically restored to the rotation, giving it
///    a fresh chance — similar to a circuit breaker's half-open state.
/// 2. **On-success recovery**: If a request to the target succeeds
///    (e.g., via the all-unhealthy fallback path), it is immediately
///    marked healthy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PassiveHealthCheck {
    #[serde(default = "default_passive_unhealthy_codes")]
    pub unhealthy_status_codes: Vec<u16>,
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
    #[serde(default = "default_passive_window")]
    pub unhealthy_window_seconds: u64,
    /// Seconds after which an unhealthy target is automatically restored
    /// to the rotation. Acts as a recovery timer / half-open circuit breaker.
    /// Default: 30 seconds. Set to 0 to disable automatic recovery (rely
    /// on active health checks or all-unhealthy fallback only).
    #[serde(default = "default_passive_healthy_after")]
    pub healthy_after_seconds: u64,
    /// Maximum percentage of targets (0-100) that can be ejected simultaneously
    /// via passive health checks. Prevents cascading failures where a transient
    /// issue ejects all backends. When the ejection count would exceed this cap,
    /// the earliest passive ejections are re-admitted first.
    /// `None` (default) = no cap (existing behavior).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ejection_percent: Option<u8>,
    /// Reserved for DestinationRule parity: subset of HTTP status codes (e.g., 502, 503, 504) that count as
    /// gateway errors for outlier detection, tracked separately from the
    /// general `unhealthy_status_codes`. When `split_external_local_origin_errors`
    /// is true, these codes will be used for the external-origin error bucket.
    /// Currently validated and persisted, but not yet applied by passive health.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_error_codes: Option<Vec<u16>>,
    /// Reserved for DestinationRule parity: when true, track local-origin errors (connection failures, timeouts)
    /// separately from external errors (HTTP 5xx responses). This allows
    /// different thresholds and windows for network-level vs application-level
    /// failures in outlier detection. Currently validated and persisted, but
    /// not yet applied by passive health.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split_external_local_origin_errors: Option<bool>,
}

impl Default for PassiveHealthCheck {
    fn default() -> Self {
        Self {
            unhealthy_status_codes: default_passive_unhealthy_codes(),
            unhealthy_threshold: default_unhealthy_threshold(),
            unhealthy_window_seconds: default_passive_window(),
            healthy_after_seconds: default_passive_healthy_after(),
            max_ejection_percent: None,
            gateway_error_codes: None,
            split_external_local_origin_errors: None,
        }
    }
}

fn default_passive_healthy_after() -> u64 {
    30
}

fn default_passive_unhealthy_codes() -> Vec<u16> {
    vec![500, 502, 503, 504]
}
fn default_passive_window() -> u64 {
    30
}

/// Health check configuration for an upstream.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    #[serde(default)]
    pub active: Option<ActiveHealthCheck>,
    #[serde(default)]
    pub passive: Option<PassiveHealthCheck>,
}

/// Cookie configuration for `hash_on: "cookie:<name>"` sticky sessions.
///
/// When consistent hashing uses a cookie as the hash key and the cookie is not
/// present in the request, the gateway sets a `Set-Cookie` response header so
/// subsequent requests from the same client stick to the same backend target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashOnCookieConfig {
    /// Cookie `Path` attribute. Default: `"/"`.
    #[serde(default = "default_cookie_path")]
    pub path: String,
    /// Cookie `Max-Age` in seconds. Default: 3600 (1 hour).
    #[serde(default = "default_cookie_ttl")]
    pub ttl_seconds: u64,
    /// Optional `Domain` attribute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Set `HttpOnly` flag. Default: true.
    #[serde(default = "default_true")]
    pub http_only: bool,
    /// Set `Secure` flag. Default: false.
    #[serde(default)]
    pub secure: bool,
    /// `SameSite` attribute (`"Strict"`, `"Lax"`, or `"None"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub same_site: Option<String>,
}

fn default_cookie_path() -> String {
    "/".to_string()
}

fn default_cookie_ttl() -> u64 {
    3600
}

impl Default for HashOnCookieConfig {
    fn default() -> Self {
        Self {
            path: default_cookie_path(),
            ttl_seconds: default_cookie_ttl(),
            domain: None,
            http_only: true,
            secure: false,
            same_site: None,
        }
    }
}

/// Maximum length for cookie config path field.
pub const MAX_COOKIE_PATH_LENGTH: usize = 2048;
/// Maximum length for cookie config domain field.
pub const MAX_COOKIE_DOMAIN_LENGTH: usize = 253;

/// Resolved backend TLS configuration.
///
/// At config load time, each proxy's effective TLS config is resolved:
/// - If the proxy references an upstream, the upstream's TLS fields are used.
/// - Otherwise, the proxy's own TLS fields are used (direct-backend proxies).
///
/// All runtime code (connection pools, health checks, proxy dispatch) reads
/// from this resolved config rather than raw proxy/upstream fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendTlsConfig {
    #[serde(default)]
    pub client_cert_path: Option<String>,
    #[serde(default)]
    pub client_key_path: Option<String>,
    #[serde(default)]
    pub server_ca_cert_path: Option<String>,
    #[serde(default = "default_true")]
    pub verify_server_cert: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub san_allow_list: Vec<String>,
    #[serde(skip)]
    pub san_allow_list_key_digest: Option<String>,
}

impl BackendTlsConfig {
    /// Create a config with verification enabled and no client certs.
    pub fn default_verify() -> Self {
        Self {
            client_cert_path: None,
            client_key_path: None,
            server_ca_cert_path: None,
            verify_server_cert: true,
            sni: None,
            san_allow_list: Vec::new(),
            san_allow_list_key_digest: None,
        }
    }

    /// Project an upstream's backend TLS fields into the resolved runtime form.
    pub fn from_upstream(upstream: &Upstream) -> Self {
        let digest = Self::compute_san_digest(&upstream.backend_tls_san_allow_list);
        Self {
            client_cert_path: upstream.backend_tls_client_cert_path.clone(),
            client_key_path: upstream.backend_tls_client_key_path.clone(),
            server_ca_cert_path: upstream.backend_tls_server_ca_cert_path.clone(),
            verify_server_cert: upstream.backend_tls_verify_server_cert,
            sni: upstream.backend_tls_sni.clone(),
            san_allow_list: upstream.backend_tls_san_allow_list.clone(),
            san_allow_list_key_digest: digest,
        }
    }

    /// Project a direct-backend proxy's TLS fields into the resolved runtime form.
    pub fn from_proxy(proxy: &Proxy) -> Self {
        Self {
            client_cert_path: proxy.backend_tls_client_cert_path.clone(),
            client_key_path: proxy.backend_tls_client_key_path.clone(),
            server_ca_cert_path: proxy.backend_tls_server_ca_cert_path.clone(),
            verify_server_cert: proxy.backend_tls_verify_server_cert,
            sni: None,
            san_allow_list: Vec::new(),
            san_allow_list_key_digest: None,
        }
    }

    pub fn recompute_san_digest(&mut self) {
        self.san_allow_list_key_digest = Self::compute_san_digest(&self.san_allow_list);
    }

    /// Normalize TLS identity fields and refresh derived SAN pool-key state
    /// skipped by serde.
    pub fn normalize_fields(&mut self) {
        if let Some(sni) = &mut self.sni {
            *sni = sni.to_ascii_lowercase();
        }
        for san in &mut self.san_allow_list {
            normalize_backend_tls_san_allow_list_entry(san);
        }
        self.recompute_san_digest();
    }

    pub(crate) fn compute_san_digest(sans: &[String]) -> Option<String> {
        if sans.is_empty() {
            return None;
        }
        let mut canonical_sans: Vec<&str> = sans.iter().map(String::as_str).collect();
        canonical_sans.sort_unstable();
        canonical_sans.dedup();
        // FNV-1a 64-bit: stable across Rust versions unlike DefaultHasher.
        const FNV_OFFSET: u64 = 0xcbf29ce484222325;
        const FNV_PRIME: u64 = 0x00000100000001B3;
        let mut h = FNV_OFFSET;
        for byte in (canonical_sans.len() as u64).to_le_bytes() {
            h ^= byte as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
        for san in canonical_sans {
            for byte in san.as_bytes() {
                h ^= *byte as u64;
                h = h.wrapping_mul(FNV_PRIME);
            }
            h ^= 0xFF;
            h = h.wrapping_mul(FNV_PRIME);
        }
        Some(format!("{:016x}", h))
    }
}

/// An upstream defines a group of backend targets with load balancing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    /// Namespace this resource belongs to. Defaults to "ferrum".
    #[serde(default = "default_namespace")]
    pub namespace: String,
    pub targets: Vec<UpstreamTarget>,
    #[serde(default)]
    pub algorithm: LoadBalancerAlgorithm,
    #[serde(default)]
    pub hash_on: Option<String>,
    /// Cookie attributes for `hash_on: "cookie:<name>"` sticky sessions.
    /// Ignored when `hash_on` is not cookie-based.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_on_cookie_config: Option<HashOnCookieConfig>,
    #[serde(default)]
    pub health_checks: Option<HealthCheckConfig>,
    #[serde(default)]
    pub service_discovery: Option<ServiceDiscoveryConfig>,
    /// Named subsets of targets identified by label selectors.
    /// Used for Istio DestinationRule subset routing. Targets whose `tags`
    /// are a superset of a subset's `labels` belong to that subset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subsets: Option<Vec<SubsetDefinition>>,
    /// Per-destination-port traffic policy overrides populated by Istio
    /// `DestinationRule.trafficPolicy.portLevelSettings[]`. Keyed by
    /// destination port number; empty by default. Round-trips identically to
    /// the prior schema when empty (via `skip_serializing_if`).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub port_overrides: HashMap<u16, UpstreamPortOverride>,
    /// Optional source-workload locality used by mesh-mode locality-aware
    /// balancing. Projected from the selected workload at slice-apply time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_locality: Option<String>,
    /// Strict local-first locality LB for this upstream. Default `false`
    /// (fail-open): when `source_locality` is absent the locality-aware LB
    /// returns mixed local + remote endpoints. When `true` (fail-closed-to-
    /// local): an absent `source_locality` restricts selection to LOCAL-locality
    /// endpoints (targets not tagged with the synthetic `remote-<cluster>`
    /// locality), widening to the full healthy pool only when there are no local
    /// endpoints. Projected from `FERRUM_MESH_LOCALITY_LB_STRICT` onto mesh
    /// upstreams at slice apply; the load balancer reads it at cache-build time.
    /// Stays `false` for non-mesh upstreams, preserving existing behavior.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub locality_lb_strict: bool,
    /// Optional projection of Istio
    /// `DestinationRule.trafficPolicy.localityLbSetting`. Populated by the
    /// mesh apply layer from a matching `MeshDestinationRule`; `None` for
    /// hand-crafted upstreams. The load balancer reads this at construction
    /// time to honour weighted `distribute` and region-`failover` overrides
    /// on top of the priority-tier preference driven by `source_locality`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locality_lb_setting: Option<UpstreamLocalityLbSetting>,
    /// Path to a PEM client certificate for mTLS with backend targets.
    #[serde(default)]
    pub backend_tls_client_cert_path: Option<String>,
    /// Path to a PEM private key for mTLS with backend targets.
    #[serde(default)]
    pub backend_tls_client_key_path: Option<String>,
    /// Whether to verify the backend server's TLS certificate.
    #[serde(default = "default_true")]
    pub backend_tls_verify_server_cert: bool,
    /// Path to a PEM CA bundle for verifying backend server certificates.
    #[serde(default)]
    pub backend_tls_server_ca_cert_path: Option<String>,
    /// Optional backend TLS SNI override, populated by mesh DestinationRule
    /// `trafficPolicy.tls.sni`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_tls_sni: Option<String>,
    /// Optional backend certificate SAN allow-list, populated by mesh
    /// DestinationRule `trafficPolicy.tls.subjectAltNames`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backend_tls_san_allow_list: Vec<String>,
    /// Cold-path projection of each subset's `SubsetTrafficPolicy.tls` overlay
    /// onto a fully-resolved `BackendTlsConfig`. Keyed by subset name. Built by
    /// the mesh `apply_destination_rules` final pass after upstream-level TLS
    /// has been settled; consulted by
    /// [`GatewayConfig::resolve_upstream_tls`] when projecting each proxy's
    /// effective `resolved_tls`. Not serialized — derived from
    /// `Upstream.subsets[].traffic_policy.tls`.
    #[serde(skip)]
    pub resolved_subset_tls: HashMap<String, ResolvedSubsetTrafficPolicy>,
    /// Top-level (non-`portLevelSettings`) DestinationRule `connectionPool.http`
    /// overlay for a **service-discovery** upstream.
    ///
    /// Non-SD upstreams fan the top-level `connectionPool.http` block out onto
    /// every served `port_overrides` entry at apply time. SD upstreams cannot —
    /// their target ports are resolved at runtime, not at apply — so the
    /// top-level overlay is captured here instead and applied by the
    /// LB-**selected** target port at dispatch. `resolve_dispatch_port_overrides`
    /// projects this onto `Proxy.dispatch_port_override_fallback`, which the
    /// HTTP-family dispatch resolvers (`resolve_effective_proxy_for_target` /
    /// `cap_proxy_retry_for_target`) consult only when the selected port has no
    /// explicit per-port override — so an explicit `portLevelSettings` entry
    /// still wins. Not serialized — derived from the matching DestinationRule.
    #[serde(default, skip)]
    pub dispatch_port_override_fallback: Option<UpstreamPortOverride>,
    /// ID of the `ApiSpec` that created this upstream via the spec-import admin API.
    /// `None` for hand-crafted upstreams. Used to scope cascading DELETE when a
    /// spec is removed. NOT loaded by the gateway runtime — admin-only metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_spec_id: Option<String>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

/// Service discovery provider type.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SdProvider {
    /// DNS-based service discovery using SRV records.
    DnsSd,
    /// Kubernetes EndpointSlice-based service discovery.
    Kubernetes,
    /// HashiCorp Consul service discovery via HTTP API.
    Consul,
    /// Ferrum mesh service discovery from the CP-delivered mesh model.
    Mesh,
}

/// DNS-SD specific configuration (SRV record-based discovery).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSdConfig {
    /// The DNS name to query for SRV records (e.g., "_http._tcp.my-service.example.com").
    pub service_name: String,
    /// Poll interval in seconds for re-querying DNS records. Default: 30.
    #[serde(default = "default_sd_poll_interval")]
    pub poll_interval_seconds: u64,
}

/// Kubernetes service discovery configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesConfig {
    /// Kubernetes namespace. Default: "default".
    #[serde(default = "default_k8s_namespace")]
    pub namespace: String,
    /// Service name in Kubernetes.
    pub service_name: String,
    /// Port name to select from EndpointSlice. If not set, uses the first port.
    #[serde(default)]
    pub port_name: Option<String>,
    /// Label selector for filtering EndpointSlices.
    #[serde(default)]
    pub label_selector: Option<String>,
    /// Poll interval in seconds. Default: 30.
    #[serde(default = "default_sd_poll_interval")]
    pub poll_interval_seconds: u64,
}

/// Consul service discovery configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsulConfig {
    /// Consul HTTP API address (e.g., "http://consul:8500").
    pub address: String,
    /// Service name registered in Consul.
    pub service_name: String,
    /// Datacenter filter. If not set, uses the local datacenter.
    #[serde(default)]
    pub datacenter: Option<String>,
    /// Service tag filter. If not set, no tag filtering.
    #[serde(default)]
    pub tag: Option<String>,
    /// Only return healthy services. Default: true.
    #[serde(default = "default_sd_healthy_only")]
    pub healthy_only: bool,
    /// Consul ACL token for authentication.
    #[serde(default)]
    pub token: Option<String>,
    /// Poll interval in seconds for blocking query long-poll. Default: 30.
    #[serde(default = "default_sd_poll_interval")]
    pub poll_interval_seconds: u64,
}

/// Ferrum mesh service discovery configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshSdConfig {
    /// Mesh service name to resolve from the CP-delivered mesh model.
    pub service_name: String,
    /// Mesh namespace. Defaults to the upstream's namespace when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Service port to select. If omitted, uses the first service port, then
    /// falls back to the first advertised workload port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Poll interval in seconds for checking the local mesh snapshot. Default: 30.
    #[serde(default = "default_sd_poll_interval")]
    pub poll_interval_seconds: u64,
    /// Destination mesh topology. Selects which mesh transport discovered
    /// targets are tagged for: `ambient` (default) tags targets `mesh.hbone`
    /// (HTTP/2 CONNECT over SVID mTLS to the peer's `:15008` HBONE listener);
    /// `sidecar` tags targets `mesh.mtls` (plain SVID-mTLS HTTP/2 to the peer
    /// sidecar's `:15006` inbound listener — sidecars have no HBONE listener,
    /// so `ambient` targets pointed at sidecar workloads fail closed with 502).
    #[serde(default, skip_serializing_if = "MeshSdTopology::is_default")]
    pub topology: MeshSdTopology,
}

/// Destination mesh topology for gateway-to-mesh service discovery
/// ([`MeshSdConfig`]). Mesh transports are per-topology: Ambient/waypoint
/// peers accept HBONE on `:15008`, Sidecar peers accept plain SVID-mTLS HTTP/2
/// on `:15006` — a target must carry the transport tag its destination
/// actually serves.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshSdTopology {
    /// Ambient/waypoint destinations: discovered targets are tagged
    /// `mesh.hbone=true` and dispatch through the HBONE outbound pool.
    #[default]
    Ambient,
    /// Sidecar destinations: discovered targets are tagged `mesh.mtls=true`
    /// and dispatch through the Sidecar SVID-mTLS pool.
    Sidecar,
}

impl MeshSdTopology {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// Service discovery configuration for an upstream.
///
/// Attaches a dynamic service discovery source to an upstream. Discovered
/// targets are merged with any statically configured targets and fed into
/// the load balancer. If the discovery source becomes unavailable, the
/// gateway continues serving with the last-known targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDiscoveryConfig {
    /// The service discovery provider to use.
    pub provider: SdProvider,
    /// DNS-SD provider configuration. Required when `provider` is `dns_sd`.
    #[serde(default)]
    pub dns_sd: Option<DnsSdConfig>,
    /// Kubernetes provider configuration. Required when `provider` is `kubernetes`.
    #[serde(default)]
    pub kubernetes: Option<KubernetesConfig>,
    /// Consul provider configuration. Required when `provider` is `consul`.
    #[serde(default)]
    pub consul: Option<ConsulConfig>,
    /// Ferrum mesh provider configuration. Required when `provider` is `mesh`.
    #[serde(default)]
    pub mesh: Option<MeshSdConfig>,
    /// Default weight assigned to discovered targets. Default: 1.
    #[serde(default = "default_weight")]
    pub default_weight: u32,
}

fn default_sd_poll_interval() -> u64 {
    30
}

fn default_k8s_namespace() -> String {
    "default".to_string()
}

fn default_sd_healthy_only() -> bool {
    true
}

/// Circuit breaker configuration for a proxy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,
    #[serde(default = "default_circuit_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_failure_status_codes")]
    pub failure_status_codes: Vec<u16>,
    #[serde(default = "default_half_open_max")]
    pub half_open_max_requests: u32,
    #[serde(default = "default_trip_on_connection_errors")]
    pub trip_on_connection_errors: bool,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: default_failure_threshold(),
            success_threshold: default_success_threshold(),
            timeout_seconds: default_circuit_timeout(),
            failure_status_codes: default_failure_status_codes(),
            half_open_max_requests: default_half_open_max(),
            trip_on_connection_errors: default_trip_on_connection_errors(),
        }
    }
}

fn default_failure_threshold() -> u32 {
    5
}
fn default_success_threshold() -> u32 {
    3
}
fn default_circuit_timeout() -> u64 {
    30
}
fn default_failure_status_codes() -> Vec<u16> {
    vec![500, 502, 503, 504]
}
fn default_half_open_max() -> u32 {
    1
}
fn default_trip_on_connection_errors() -> bool {
    true
}

/// Retry backoff strategy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackoffStrategy {
    Fixed { delay_ms: u64 },
    Exponential { base_ms: u64, max_ms: u64 },
}

impl Default for BackoffStrategy {
    fn default() -> Self {
        Self::Fixed { delay_ms: 100 }
    }
}

/// Retry configuration for a proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryConfig {
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_retryable_status_codes")]
    pub retryable_status_codes: Vec<u16>,
    #[serde(default = "default_retryable_methods")]
    pub retryable_methods: Vec<String>,
    #[serde(default)]
    pub backoff: BackoffStrategy,
    /// Whether to retry on TCP/connection failures (connect refused, timeout,
    /// DNS resolution failure, TLS handshake error). Defaults to true.
    /// This is independent of `retryable_status_codes` — a connection failure
    /// never reaches the HTTP layer, so it would not be retried by status code
    /// matching alone.
    #[serde(default = "default_retry_on_connect_failure")]
    pub retry_on_connect_failure: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            retryable_status_codes: default_retryable_status_codes(),
            retryable_methods: default_retryable_methods(),
            backoff: BackoffStrategy::default(),
            retry_on_connect_failure: default_retry_on_connect_failure(),
        }
    }
}

fn default_max_retries() -> u32 {
    3
}
fn default_retryable_status_codes() -> Vec<u16> {
    vec![]
}
fn default_retryable_methods() -> Vec<String> {
    vec![
        "GET".to_string(),
        "HEAD".to_string(),
        "OPTIONS".to_string(),
        "PUT".to_string(),
        "DELETE".to_string(),
    ]
}
fn default_retry_on_connect_failure() -> bool {
    true
}

/// Wire-level scheme the proxy uses to talk to its backend.
///
/// Six variants cover every transport Ferrum Edge supports:
///
/// - HTTP family (`Http`, `Https`) covers HTTP/1.1, HTTP/2, HTTP/3, gRPC, and
///   WebSocket. Which of those is actually spoken is determined per-request
///   via `HttpFlavor` (content-type / Upgrade / ALPN negotiation) — it is
///   never pinned in config. A single `Https` proxy transparently serves a
///   mix of REST, gRPC, and WebSocket traffic on the same backend pool.
/// - Stream family (`Tcp`, `Tcps`, `Udp`, `Dtls`) are raw L4 proxies selected
///   by `listen_port`.
///
/// `Tcps` follows the `http`/`https`, `ws`/`wss`, pattern (serde name `"tcps"`).
/// Only the canonical six scheme names are accepted on the serde and database
/// boundaries.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum BackendScheme {
    Http,
    Https,
    Tcp,
    Tcps,
    Udp,
    Dtls,
}

impl BackendScheme {
    /// True when this is a raw L4 stream proxy (TCP/UDP/TLS/DTLS).
    ///
    /// Kept public (and annotated `#[allow(dead_code)]`) because
    /// `BackendScheme` is re-exported from `lib.rs` for downstream consumers
    /// (tests, future plugins) even when the gateway itself prefers the
    /// pre-computed `DispatchKind::is_stream()` on the hot path.
    #[inline]
    #[allow(dead_code)]
    pub fn is_stream(&self) -> bool {
        matches!(self, Self::Tcp | Self::Tcps | Self::Udp | Self::Dtls)
    }

    /// True when this uses HTTP-family transport (HTTP/1.1, HTTP/2, HTTP/3,
    /// gRPC, WebSocket — determined per-request from `HttpFlavor`).
    #[inline]
    #[allow(dead_code)]
    pub fn is_http_family(&self) -> bool {
        matches!(self, Self::Http | Self::Https)
    }

    /// True when this uses UDP transport (plaintext or DTLS).
    #[inline]
    pub fn is_udp(&self) -> bool {
        matches!(self, Self::Udp | Self::Dtls)
    }

    /// True when the backend connection uses TLS/DTLS.
    #[inline]
    #[allow(dead_code)]
    pub fn is_tls_backend(&self) -> bool {
        matches!(self, Self::Https | Self::Tcps | Self::Dtls)
    }

    /// Canonical serde string for this scheme. Takes `self` by value because
    /// `BackendScheme: Copy` and clippy's `wrong-self-convention` lint flags
    /// `to_*` methods that borrow on `Copy` types.
    #[inline]
    pub fn to_scheme_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Tcp => "tcp",
            Self::Tcps => "tcps",
            Self::Udp => "udp",
            Self::Dtls => "dtls",
        }
    }
}

impl std::fmt::Display for BackendScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_scheme_str())
    }
}

/// Per-request HTTP flavor detected from the incoming request. Only
/// meaningful when the proxy's scheme is HTTP-family (`Http` or `Https`).
///
/// Detection is purely runtime — gRPC and WebSocket are no longer pinned
/// in config. See `detect_http_flavor()` in `src/proxy/mod.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpFlavor {
    /// Regular HTTP (GET/POST/…) — anything that isn't gRPC or WebSocket.
    /// Covers HTTP/1.1, HTTP/2, and HTTP/3 bodies.
    Plain,
    /// gRPC — identified by `content-type: application/grpc[+proto|+json|...]`.
    Grpc,
    /// WebSocket upgrade — HTTP/1.1 `Connection: Upgrade` + `Upgrade: websocket`,
    /// or HTTP/2 Extended CONNECT (RFC 8441) with `:protocol=websocket`.
    WebSocket,
}

/// Pre-computed dispatch classification for a proxy. Populated once at
/// config-load time in `GatewayConfig::resolve_dispatch_kind()` so the
/// request hot path is a single match on a 1-byte enum instead of a
/// cascade of scheme/capability checks.
///
/// Same pattern as `Proxy::resolved_tls` (cached computation, `#[serde(skip)]`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DispatchKind {
    /// Plaintext HTTP family (scheme = Http). Plain flavor → reqwest; Grpc →
    /// GrpcPool h2c path; WebSocket → plaintext `ws://` upgrade.
    #[default]
    HttpPool,
    /// TLS HTTP family (scheme = Https). Plain → reqwest, Http2ConnectionPool,
    /// or Http3ConnectionPool based on the backend capability registry; Grpc →
    /// GrpcPool TLS; WebSocket → `wss://` upgrade.
    HttpsPool,
    /// Raw TCP stream proxy.
    TcpRaw,
    /// TCP + TLS stream proxy.
    TcpTls,
    /// Raw UDP stream proxy.
    UdpRaw,
    /// UDP + DTLS stream proxy.
    UdpDtls,
}

impl DispatchKind {
    #[inline]
    pub fn is_stream(&self) -> bool {
        matches!(
            self,
            Self::TcpRaw | Self::TcpTls | Self::UdpRaw | Self::UdpDtls
        )
    }

    #[inline]
    pub fn is_http_family(&self) -> bool {
        matches!(self, Self::HttpPool | Self::HttpsPool)
    }

    #[inline]
    #[allow(dead_code)] // part of public API, exercised via re-export + tests
    pub fn is_tls_backend(&self) -> bool {
        matches!(self, Self::HttpsPool | Self::TcpTls | Self::UdpDtls)
    }

    #[inline]
    pub fn is_udp(&self) -> bool {
        matches!(self, Self::UdpRaw | Self::UdpDtls)
    }
}

impl From<BackendScheme> for DispatchKind {
    #[inline]
    fn from(scheme: BackendScheme) -> Self {
        match scheme {
            BackendScheme::Http => Self::HttpPool,
            BackendScheme::Https => Self::HttpsPool,
            BackendScheme::Tcp => Self::TcpRaw,
            BackendScheme::Tcps => Self::TcpTls,
            BackendScheme::Udp => Self::UdpRaw,
            BackendScheme::Dtls => Self::UdpDtls,
        }
    }
}

/// Authentication mode for a proxy.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    #[default]
    Single,
    Multi,
}

/// Controls whether proxy responses are streamed or buffered before
/// being forwarded to the client.
///
/// - **Stream** (default): Response chunks are forwarded to the client as
///   they arrive from the backend. Lower memory usage and lower latency
///   for large responses. Incompatible with plugins that need to inspect
///   or modify the full response body — those will automatically force
///   buffering regardless of this setting.
/// - **Buffer**: The entire response body is collected in memory before
///   forwarding. Required when a plugin needs access to the complete
///   response body (e.g., response body transformation).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ResponseBodyMode {
    #[default]
    Stream,
    Buffer,
}

/// Plugin scope (global, per-proxy, or proxy-group).
///
/// - **Global**: Plugin runs on ALL proxies (unless overridden by a proxy-scoped
///   or proxy-group-scoped plugin of the same name).
/// - **Proxy**: Plugin runs on exactly ONE proxy. Requires `proxy_id` to be set.
/// - **ProxyGroup**: Plugin runs on a SUBSET of proxies. The set of proxies is
///   determined by which proxies include this plugin in their `plugins` association
///   list. `proxy_id` must be `None`. A single `ProxyGroup` plugin instance is
///   shared across all associated proxies, so stateful plugins (e.g., rate_limiting)
///   share counters across the group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PluginScope {
    Global,
    Proxy,
    #[serde(rename = "proxy_group")]
    ProxyGroup,
}

/// A proxy resource defines a route to a backend.
///
/// HTTP-family proxies route on `hosts` + `listen_path`. At least one of the two
/// must be set; if both are empty/absent the config is rejected. Stream-family
/// proxies (`tcp`/`tcp_tls`/`udp`/`dtls`) route on `listen_port` and MUST NOT
/// set `listen_path`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proxy {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    /// Namespace this resource belongs to. Defaults to "ferrum".
    /// Used for multi-tenant resource isolation — each gateway instance
    /// loads only resources matching its configured namespace.
    #[serde(default = "default_namespace")]
    pub namespace: String,
    /// Optional list of hostnames this proxy matches on.
    /// Empty means match all hosts (catch-all).
    /// Supports exact hostnames and DNS suffix wildcard prefixes (e.g., "*.example.com").
    /// For HTTP-family proxies, either `hosts` or `listen_path` must be set
    /// (both may be set together).
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Path prefix, `~regex`, or `=/exact-path` this proxy matches.
    /// - HTTP-family proxies: required UNLESS `hosts` is non-empty. When both
    ///   `hosts` is empty and this is `None`, the config is rejected — that
    ///   would be "match literally everything" and collides with every
    ///   other catch-all route.
    /// - When `None` on an HTTP proxy, the proxy matches any path under the
    ///   specified hosts. `strip_listen_path` is a no-op; `backend_path`
    ///   (if set) prepends to the forwarded path.
    /// - Stream-family proxies: MUST be `None`. Stream proxies route on
    ///   `listen_port`.
    #[serde(default)]
    pub listen_path: Option<String>,
    /// Backend wire scheme. Optional on HTTP-family proxies (defaults to
    /// `Https` during normalization if absent), REQUIRED on stream proxies
    /// (validation rejects missing scheme when `listen_port` is set).
    ///
    /// WebSocket and gRPC are no longer schemes — they are detected per-request
    /// from the incoming traffic (`HttpFlavor`). HTTP/3 is learned per backend
    /// by the capability registry when the scheme resolves to `Https`.
    #[serde(default)]
    pub backend_scheme: Option<BackendScheme>,
    /// Populated during `normalize_fields()` — O(1) dispatch target used by
    /// the request hot path. Never serialized. Same pattern as `resolved_tls`.
    #[serde(skip)]
    pub dispatch_kind: DispatchKind,
    pub backend_host: String,
    pub backend_port: u16,
    #[serde(default)]
    pub backend_path: Option<String>,
    /// When true, strip the matched `listen_path` prefix from the forwarded
    /// request path. No-op when `listen_path` is `None` (host-only proxy) —
    /// there is no prefix to strip.
    #[serde(default = "default_true")]
    pub strip_listen_path: bool,
    #[serde(default)]
    pub preserve_host_header: bool,
    #[serde(default = "default_connect_timeout")]
    pub backend_connect_timeout_ms: u64,
    #[serde(default = "default_read_timeout")]
    pub backend_read_timeout_ms: u64,
    #[serde(default = "default_write_timeout")]
    pub backend_write_timeout_ms: u64,
    /// Path to a PEM client certificate for mTLS with backend targets.
    /// Used only for direct-backend proxies (no `upstream_id`). When an upstream
    /// is referenced, the upstream's TLS config takes precedence.
    #[serde(default)]
    pub backend_tls_client_cert_path: Option<String>,
    /// Path to a PEM private key for mTLS with backend targets.
    /// Used only for direct-backend proxies (no `upstream_id`).
    #[serde(default)]
    pub backend_tls_client_key_path: Option<String>,
    /// Whether to verify the backend server's TLS certificate.
    /// Used only for direct-backend proxies (no `upstream_id`).
    #[serde(default = "default_true")]
    pub backend_tls_verify_server_cert: bool,
    /// Path to a PEM CA bundle for verifying backend server certificates.
    /// Used only for direct-backend proxies (no `upstream_id`).
    #[serde(default)]
    pub backend_tls_server_ca_cert_path: Option<String>,
    /// Resolved backend TLS config (populated during `normalize_fields()`).
    /// When the proxy references an upstream, this is the upstream's TLS config.
    /// For direct-backend proxies, this is the proxy's own TLS fields.
    /// Not serialized — derived from the upstream or proxy fields.
    #[serde(skip)]
    pub resolved_tls: BackendTlsConfig,
    /// Per-destination-port `connect_timeout_ms` overrides projected from the
    /// referenced upstream's `port_overrides` at config-resolve time. `None`
    /// when the proxy has no upstream or the upstream has no per-port
    /// overrides — the common case, so the dispatch hot path skips the lookup
    /// entirely with a single field read. Populated by
    /// `GatewayConfig::resolve_dispatch_port_overrides()` after mesh
    /// `apply_destination_rules` has written into `Upstream.port_overrides`.
    #[serde(skip)]
    pub dispatch_port_overrides: Option<HashMap<u16, ResolvedPortOverride>>,
    /// Top-level (non-`portLevelSettings`) DestinationRule `connectionPool.http`
    /// overlay for a **service-discovery** upstream, projected from
    /// `Upstream.dispatch_port_override_fallback` by
    /// `GatewayConfig::resolve_dispatch_port_overrides()`.
    ///
    /// SD upstreams have no apply-time port set to fan the top-level overlay
    /// onto (targets resolve at runtime), so `dispatch_port_overrides` is empty
    /// for the discovered ports. The HTTP-family dispatch resolvers
    /// (`resolve_effective_proxy_for_target` / `cap_proxy_retry_for_target`)
    /// fall back to this overlay when the LB-selected target port has no
    /// explicit per-port override — so an explicit `portLevelSettings` entry for
    /// that port still wins. `None` for the common (non-SD, or SD without a
    /// top-level `connectionPool.http`) case, so the hot path skips it with a
    /// single field read. `#[serde(skip)]` (derived-only) like
    /// `dispatch_port_overrides`; DB/file loaders start it `None`.
    #[serde(skip)]
    pub dispatch_port_override_fallback: Option<ResolvedPortOverride>,
    #[serde(default)]
    pub dns_override: Option<String>,
    #[serde(default)]
    pub dns_cache_ttl_seconds: Option<u64>,
    #[serde(default)]
    pub auth_mode: AuthMode,
    #[serde(default)]
    pub plugins: Vec<PluginAssociation>,
    // Connection pooling settings (optional - override global defaults)
    // Note: pool_max_idle_per_host is intentionally global-only (FERRUM_POOL_MAX_IDLE_PER_HOST).
    // Per-proxy overrides were removed because they fragment the connection pool — different
    // values create separate reqwest::Client instances for the same backend, destroying
    // connection reuse and increasing P95 latency.
    #[serde(default)]
    pub pool_idle_timeout_seconds: Option<u64>,
    #[serde(default)]
    pub pool_enable_http_keep_alive: Option<bool>,
    #[serde(default)]
    pub pool_enable_http2: Option<bool>,
    #[serde(default)]
    pub pool_tcp_keepalive_seconds: Option<u64>,
    #[serde(default)]
    pub pool_http2_keep_alive_interval_seconds: Option<u64>,
    #[serde(default)]
    pub pool_http2_keep_alive_timeout_seconds: Option<u64>,
    // HTTP/2 flow control & performance tuning overrides
    #[serde(default)]
    pub pool_http2_initial_stream_window_size: Option<u32>,
    #[serde(default)]
    pub pool_http2_initial_connection_window_size: Option<u32>,
    #[serde(default)]
    pub pool_http2_adaptive_window: Option<bool>,
    #[serde(default)]
    pub pool_http2_max_frame_size: Option<u32>,
    #[serde(default)]
    pub pool_http2_max_concurrent_streams: Option<u32>,
    /// Per-proxy override for HTTP/3 connections per backend.
    /// When set, overrides the global `FERRUM_HTTP3_CONNECTIONS_PER_BACKEND` default.
    #[serde(default)]
    pub pool_http3_connections_per_backend: Option<usize>,
    /// Istio DestinationRule `connectionPool.http.h2UpgradePolicy`. Controls
    /// the plain-HTTPS backend HTTP/1.1-vs-HTTP/2 dispatch fork in
    /// `proxy_to_backend`: `DoNotUpgrade` forces the reqwest/H1 path even when
    /// the capability registry marks the target H2-capable; `Upgrade` prefers
    /// direct-H2 (and treats an `Unknown` capability as a hint to try H2
    /// instead of defaulting to reqwest). `Default`/`None` leaves the
    /// probe-driven behavior unchanged.
    ///
    /// **Derived-only — never an input field.** It is projected at dispatch
    /// time by `resolve_effective_proxy_for_target` from the DestinationRule
    /// `Upstream.port_overrides[port].h2_upgrade_policy` slot, exactly like
    /// `resolved_tls` / `dispatch_port_overrides`. It is `#[serde(skip)]` so
    /// the file/admin/API config surface (and the SQL/Mongo loaders, which
    /// never persist a column for it) can neither accept nor emit it — an
    /// operator value would otherwise be silently dropped on reload. The DB
    /// loaders therefore always start it at `None`. Does NOT affect gRPC
    /// (always H2) or HBONE/mesh-mTLS transport selection.
    #[serde(skip)]
    pub h2_upgrade_policy: Option<H2UpgradePolicy>,
    /// Deprecated proxy-level `maxRequestsPerConnection` carrier.
    /// Reqwest/hyper do not expose a stable close-after-N-requests builder knob
    /// for the shared backend client pool, so this direct proxy field is
    /// admitted for backward compatibility but has no live runtime effect.
    /// DestinationRule translation no longer projects into this field; K8s
    /// status reports DR `connectionPool.http.maxRequestsPerConnection` as
    /// deferred instead.
    /// `None` (default) = no configured cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_max_requests_per_connection: Option<u64>,
    /// Istio DestinationRule `connectionPool.http.http1MaxPendingRequests`. The
    /// cap on concurrent *pending* (connection-waiting) requests on the
    /// reqwest/HTTP-1.1 backend-dispatch path. Consulted by `proxy_to_backend`
    /// via [`crate::backend_pending_limit::BackendPendingLimiter`]: a request
    /// that cannot get a pending slot for its `(host, port)` is shed with a 503
    /// ("upstream overflow") in the connection-pending phase. Does NOT gate
    /// direct-H2 / gRPC / HTTP/3 / HBONE / mesh-mTLS dispatch.
    ///
    /// **Derived-only — never an input field.** It is projected at dispatch
    /// time by `resolve_effective_proxy_for_target` from the DestinationRule
    /// `Upstream.port_overrides[port].http1_max_pending_requests` slot, exactly
    /// like `h2_upgrade_policy` / `resolved_tls` / `dispatch_port_overrides`. It
    /// is `#[serde(skip)]` so the file/admin/API config surface (and the
    /// SQL/Mongo loaders, which never persist a column for it) can neither
    /// accept nor emit it — an operator value would otherwise be silently
    /// dropped on reload. The DB loaders therefore always start it at `None`.
    #[serde(skip)]
    pub pool_http1_max_pending_requests: Option<u32>,
    /// Optional upstream ID for load-balanced backends.
    /// When set, overrides backend_host/backend_port with upstream target selection.
    #[serde(default)]
    pub upstream_id: Option<String>,
    /// Named subset within the upstream to route traffic to. Must reference
    /// a subset name defined in the upstream's `subsets` list. When set,
    /// the load balancer pre-filters targets to only those matching the
    /// subset's label selectors before applying the LB algorithm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_subset: Option<String>,
    /// ID of the `ApiSpec` that created this proxy via the spec-import admin API.
    /// `None` for hand-crafted proxies. Used to scope cascading DELETE when a
    /// spec is removed. NOT loaded by the gateway runtime — admin-only metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_spec_id: Option<String>,
    /// Circuit breaker configuration.
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerConfig>,
    /// Retry configuration.
    #[serde(default)]
    pub retry: Option<RetryConfig>,
    /// Response body mode: `stream` (default) or `buffer`.
    /// Streaming forwards response chunks as they arrive from the backend.
    /// Buffering collects the entire response before forwarding. Plugins
    /// that require the full response body will force buffering regardless
    /// of this setting.
    #[serde(default)]
    pub response_body_mode: ResponseBodyMode,
    /// Port the gateway listens on for this TCP/UDP proxy.
    /// Required when backend_scheme is Tcp/Tcps/Udp/Dtls.
    /// Not used for HTTP-based protocols.
    #[serde(default)]
    pub listen_port: Option<u16>,
    /// Whether to terminate TLS on the gateway side for incoming TCP connections.
    /// For TCP: uses the gateway's TLS certificate for TLS termination.
    /// For UDP: uses the DTLS certificate for DTLS termination (ECDSA P-256 or P-384).
    #[serde(default)]
    pub frontend_tls: bool,
    /// When true, forward encrypted client bytes directly to the backend without
    /// terminating TLS (TCP) or DTLS (UDP). The proxy peeks at the TLS/DTLS
    /// ClientHello to extract SNI for routing and logging but never decrypts
    /// application data. Only valid for stream proxies (tcp, tcp_tls, udp, dtls).
    /// Mutually exclusive with `frontend_tls`.
    #[serde(default)]
    pub passthrough: bool,
    /// UDP session idle timeout in seconds. After this duration of inactivity,
    /// the UDP session mapping is removed. Default: 60 seconds.
    #[serde(default = "default_udp_idle_timeout")]
    pub udp_idle_timeout_seconds: u64,
    /// Maximum allowed response amplification factor for UDP proxies.
    /// When set, backend→client datagrams are dropped if their size exceeds
    /// `payload_size * factor`. A zero-length request receives a one-byte reply
    /// allowance so it cannot black-hole the session; nonempty requests retain
    /// the exact configured payload ratio. `None` (default) = no limit.
    #[serde(default)]
    pub udp_max_response_amplification_factor: Option<f32>,
    /// TCP stream idle timeout in seconds. After this duration of no data
    /// transfer in either direction, the connection is closed.
    /// Per-proxy override; when `None`, uses the global `FERRUM_TCP_IDLE_TIMEOUT_SECONDS`
    /// (default: 300s / 5 min). Set to 0 to disable (rely on OS TCP timeouts only).
    #[serde(default)]
    pub tcp_idle_timeout_seconds: Option<u64>,
    /// Enable inbound PROXY protocol (v1 text or v2 binary, auto-detected) on
    /// this stream proxy listener. When `true`, every inbound TCP connection
    /// **must** begin with a valid PROXY header; connections that do not are
    /// closed immediately (fail closed).
    ///
    /// **Trust requirement**: the forwarded address is honoured only when the
    /// socket peer (the load balancer's own IP) belongs to the
    /// `FERRUM_TRUSTED_PROXIES` CIDR set. A connection from an untrusted peer
    /// on a PROXY-protocol-enabled listener is also closed, preventing
    /// direct-connect clients from spoofing their source IP.
    ///
    /// After a successful trusted parse, `client_ip` in the
    /// `StreamConnectionContext` (and in stream logs and authz plugins) is
    /// the forwarded source IP from the PROXY header; `direct_client_ip` is
    /// still the raw socket peer (the LB's own IP). This mirrors how
    /// `FERRUM_TRUSTED_PROXIES` + XFF work on the HTTP path.
    ///
    /// Only valid for `tcp` / `tcp_tls` stream proxies. Setting it on a UDP,
    /// DTLS, or HTTP proxy produces a validation error: PROXY protocol is
    /// TCP-borne and cannot carry UDP session addressing.
    ///
    /// Default: `false` (PROXY protocol disabled; socket peer is always used).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_proxy_protocol: Option<bool>,
    /// WebSocket relay idle timeout in seconds for upgraded sessions on this
    /// proxy. After this duration with no activity in EITHER direction (frames,
    /// including Ping/Pong, or transport bytes), the session is closed. Applies
    /// to both the frame-parsed relay and the raw tunnel-mode relay, and to
    /// H1/H2/H3 frontends.
    /// Per-proxy override; when `None`, uses the global
    /// `FERRUM_WEBSOCKET_IDLE_TIMEOUT_SECONDS` (default: 300s / 5 min).
    /// Set to `0` to disable for this proxy (idle sessions live forever, bounded
    /// only by `FERRUM_WEBSOCKET_MAX_CONNECTIONS`).
    ///
    /// HTTP/3 caveat: on QUIC frontends the transport-level connection idle
    /// timeout (`FERRUM_HTTP3_IDLE_TIMEOUT`, default 30s) can close an
    /// otherwise-idle H3 connection before a longer WebSocket idle timer fires.
    /// Multiplexed H3 connections with other active streams may stay open. Raise
    /// `FERRUM_HTTP3_IDLE_TIMEOUT` when isolated H3 WebSockets need a longer
    /// idle window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub websocket_idle_timeout_seconds: Option<u64>,
    /// Optional list of allowed HTTP methods (e.g., ["GET", "POST"]).
    /// When `None` (default), all methods are allowed. When `Some`, requests
    /// with methods not in the list receive 405 Method Not Allowed.
    #[serde(default)]
    pub allowed_methods: Option<Vec<String>>,
    /// Optional list of allowed WebSocket Origin values (e.g., ["https://example.com"]).
    /// When non-empty, WebSocket upgrade requests must include an Origin header
    /// matching one of these values (case-insensitive). Empty list (default) means
    /// no origin check — all origins are permitted. Protects against Cross-Site
    /// WebSocket Hijacking (CSWSH) per RFC 6455 §10.2.
    #[serde(default)]
    pub allowed_ws_origins: Vec<String>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

/// Links a proxy to a plugin configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginAssociation {
    pub plugin_config_id: String,
}

/// A consumer resource (API user).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Consumer {
    #[serde(default)]
    pub id: String,
    pub username: String,
    /// Namespace this resource belongs to. Defaults to "ferrum".
    #[serde(default = "default_namespace")]
    pub namespace: String,
    #[serde(default)]
    pub custom_id: Option<String>,
    #[serde(default)]
    pub credentials: HashMap<String, serde_json::Value>,
    /// ACL group memberships. A consumer can belong to multiple groups, and the
    /// `access_control` plugin can allow/deny by group instead of (or in
    /// addition to) individual consumer usernames.
    #[serde(default)]
    pub acl_groups: Vec<String>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

/// A plugin configuration resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginConfig {
    #[serde(default)]
    pub id: String,
    pub plugin_name: String,
    /// Namespace this resource belongs to. Defaults to "ferrum".
    #[serde(default = "default_namespace")]
    pub namespace: String,
    #[serde(default)]
    pub config: serde_json::Value,
    pub scope: PluginScope,
    #[serde(default)]
    pub proxy_id: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional execution priority override. When set, replaces the plugin's
    /// built-in priority constant. Lower values execute first. Useful when
    /// multiple instances of the same plugin type are attached to a proxy
    /// (e.g., two `http_logging` instances for different log destinations)
    /// and you need to control their relative execution order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority_override: Option<u16>,
    /// ID of the `ApiSpec` that created this plugin config via the spec-import admin API.
    /// `None` for hand-crafted plugin configs. Used to scope cascading DELETE when a
    /// spec is removed. NOT loaded by the gateway runtime — admin-only metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_spec_id: Option<String>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

/// Wire format of the stored OpenAPI / Swagger spec document.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SpecFormat {
    Json,
    Yaml,
}

/// An ingested OpenAPI / Swagger spec — admin-only metadata.
///
/// # Hot-path isolation
///
/// `ApiSpec` is intentionally absent from [`GatewayConfig`] and from every
/// polling / gRPC-distribution path. The gateway runtime never reads this
/// table; it is used exclusively by the admin API for spec storage and
/// resource generation. Do NOT add it to `db_loader.rs`, any `IncrementalResult`
/// variant, or the CP broadcast channel.
///
/// # Storage
///
/// `spec_content` holds the **gzip-compressed** original document. The
/// uncompressed size and a SHA-256 hex digest of the uncompressed bytes are
/// stored alongside for integrity verification and size reporting without
/// requiring decompression. See [`crate::admin::spec_codec`] for the
/// compression + hashing helpers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiSpec {
    #[serde(default)]
    pub id: String,
    /// Namespace this resource belongs to. Defaults to "ferrum".
    #[serde(default = "default_namespace")]
    pub namespace: String,
    /// ID of the proxy created from this spec.
    pub proxy_id: String,
    /// OpenAPI / Swagger schema version string, e.g. `"2.0"`, `"3.0.3"`, `"3.1.0"`.
    pub spec_version: String,
    /// Original document format (JSON or YAML).
    pub spec_format: SpecFormat,
    /// Gzip-compressed spec document bytes.
    pub spec_content: Vec<u8>,
    /// Content encoding — always `"gzip"` for v1.
    pub content_encoding: String,
    /// Size of the spec document before compression, in bytes.
    pub uncompressed_size: u64,
    /// Lowercase hex SHA-256 digest of the **uncompressed** spec bytes.
    pub content_hash: String,
    /// Human-readable title from the spec's `info.title` field, if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Version string from the spec's `info.version` field, if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info_version: Option<String>,
    /// `info.description` from the spec, truncated to 4096 bytes at a UTF-8 boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// `info.contact.name` from the spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact_name: Option<String>,
    /// `info.contact.email` from the spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact_email: Option<String>,
    /// `info.license.name` from the spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_name: Option<String>,
    /// `info.license.identifier` (3.1+) or `info.license.url` fallback, or None.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_identifier: Option<String>,
    /// Top-level `tags[].name` entries, de-duplicated and sorted.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Server URLs: `servers[].url` for 3.x; constructed from `schemes + host + basePath` for 2.0.
    #[serde(default)]
    pub server_urls: Vec<String>,
    /// Count of HTTP method entries (`get`/`post`/`put`/`delete`/`options`/`head`/`patch`/`trace`)
    /// across all `paths.*` entries.
    #[serde(default)]
    pub operation_count: u32,
    /// SHA-256 hex of the serialised bundle resources (proxy + upstream + plugins), excluding
    /// metadata timestamps. Used to short-circuit idempotent PUT writes.
    #[serde(default)]
    pub resource_hash: String,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

/// Full gateway configuration snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    /// Configuration schema version.
    pub version: String,
    pub proxies: Vec<Proxy>,
    pub consumers: Vec<Consumer>,
    pub plugin_configs: Vec<PluginConfig>,
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    #[serde(default = "Utc::now")]
    pub loaded_at: DateTime<Utc>,
    /// All distinct namespaces discovered at config load time (before namespace
    /// filtering). Populated by file mode so `GET /namespaces` can return all
    /// namespaces even though the in-memory config only holds one namespace's
    /// resources. DB-backed modes use `list_namespaces()` instead.
    #[serde(default)]
    pub known_namespaces: Vec<String>,
    /// Optional proxy frontend TLS certificate source delivered with the
    /// namespace-scoped gateway config. Kubernetes Gateway listeners populate
    /// this from `certificateRefs` as `k8s://<namespace>/<secret>#tls.crt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontend_tls_cert_path: Option<String>,
    /// Optional proxy frontend TLS private-key source paired with
    /// `frontend_tls_cert_path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontend_tls_key_path: Option<String>,
    /// Namespace of the Gateway that materialized `frontend_tls_*`.
    ///
    /// The Secret itself can be cross-namespace when authorized by
    /// ReferenceGrant, so CP/DP namespace filtering must use this owner
    /// namespace instead of inferring ownership from a `k8s://secret-ns/...`
    /// source URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontend_tls_source_namespace: Option<String>,
    /// Gateway-managed frontend TLS material indexed by owning Gateway
    /// namespace. Multi-namespace CPs keep all Gateway TLS entries here until
    /// the per-DP namespace filter projects the matching entry into
    /// `frontend_tls_*`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frontend_tls_namespace_sources: Vec<FrontendTlsNamespaceSource>,
    /// Gateway-consumable mesh trust material delivered by CPs to DPs.
    ///
    /// This mirrors the mesh config trust-bundle shape, but sits at the
    /// gateway config top level so non-mesh gateway DPs can verify mesh peer
    /// certificates without loading the entire mesh model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_bundles: Option<Box<crate::modes::mesh::config::TrustBundleSet>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh: Option<Box<crate::modes::mesh::config::MeshConfig>>,
    /// Authoritative mesh config revision for this snapshot (issue #2473).
    ///
    /// DERIVED, CP-in-memory only: `#[serde(skip)]`, so it never rides the
    /// ConfigSync `config_json` wire (which is `deny_unknown_fields` on both
    /// peers) and cannot break a mixed-patch CP/DP rollout. The mesh CP stamps
    /// it from the durable `config_changes` sequence on every accepted full
    /// load and delta, and `MeshSlice::from_gateway_config` copies it onto the
    /// slice, which IS the wire contract the mesh data plane orders by.
    ///
    /// `None` means "this snapshot came from an authority with no shared
    /// monotonic sequence" (K8s CRD controller, file source, tests); slices
    /// built from it carry no revision and the DP gate stays inert unless it
    /// has already accepted a revisioned slice.
    #[serde(skip)]
    pub mesh_revision: Option<crate::modes::mesh::revision::MeshConfigRevision>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FrontendTlsNamespaceSource {
    pub namespace: String,
    pub cert_path: String,
    pub key_path: String,
}

/// The current config schema version. Increment this when adding config migrations.
pub const CURRENT_CONFIG_VERSION: &str = "1";

/// The default namespace for all resources when `FERRUM_NAMESPACE` is unset.
pub const DEFAULT_NAMESPACE: &str = "ferrum";

/// Maximum length for namespace identifiers.
pub const MAX_NAMESPACE_LENGTH: usize = 254;

/// Default namespace value for serde deserialization.
pub fn default_namespace() -> String {
    DEFAULT_NAMESPACE.to_string()
}

/// Validate a namespace string. Same rules as resource IDs.
pub fn validate_namespace(ns: &str) -> Result<(), String> {
    if ns.is_empty() {
        return Err("namespace must not be empty".to_string());
    }
    if ns.len() > MAX_NAMESPACE_LENGTH {
        return Err(format!(
            "namespace must be at most {} characters, got {}",
            MAX_NAMESPACE_LENGTH,
            ns.len()
        ));
    }
    if !ID_REGEX.is_match(ns) {
        return Err(format!(
            "namespace '{}' is invalid: must start with alphanumeric and contain only alphanumeric, dots, underscores, or hyphens",
            ns
        ));
    }
    Ok(())
}

/// Auto-anchor a regex listen_path pattern for full-path matching.
///
/// Parse a backend host as a literal IP, stripping URI brackets first.
///
/// `build_backend_url_with_target` preserves bracketed IPv6 literals
/// (`[fd00:ec2::254]`) and the runtime dial paths strip the brackets before
/// screening, so config/admin/API-spec admission must do the same — otherwise a
/// bracketed denied literal parses as a non-IP here and is admitted, only to be
/// blocked later at dispatch.
pub(crate) fn egress_literal_ip(host: &str) -> Option<std::net::IpAddr> {
    // The URL authority ends at the first '/', '?', or '#' — or '\' for the
    // special http/https schemes our backend URLs use, which the WHATWG parser
    // folds to '/'. Everything from that terminator on is path/query/fragment,
    // NOT the dialed host: `169.254.169.254/@evil` and `169.254.169.254\@evil`
    // both dial 169.254.169.254 (the '@' is in the PATH, not userinfo). Truncate
    // to the authority FIRST so the userinfo split below cannot reach past the
    // authority into the path and screen the wrong host. (ASCII tab/newline/CR
    // are stripped by the parser before parsing but are never authority
    // terminators, so scanning the raw string here still finds the first real
    // terminator.)
    let authority = match host.find(['/', '?', '#', '\\']) {
        Some(i) => &host[..i],
        None => host,
    };
    // Within the authority, the parser treats the substring after the LAST '@'
    // as the host (any userinfo precedes it), so `allowed@169.254.169.254` is
    // dialed as `169.254.169.254`. A real host never contains '@', so screening
    // only the post-'@' part just narrows malicious input — otherwise the literal
    // slips through the resolver behind userinfo.
    let host = authority.rsplit('@').next().unwrap_or(authority);

    // Canonical literal first (also covers bracketed IPv6).
    if let Some(ip) = stream_literal_ip(host) {
        return Some(ip);
    }

    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    // Match the URL parser's host-literal handling before deciding this is a DNS
    // hostname. The HTTP client stack (reqwest, the H2/gRPC/H3 pools, kafka broker
    // dials) parses authorities through `url`/getaddrinfo, which accept
    // non-canonical IPv4 literal forms (a 32-bit decimal, hex, or octal-component
    // address) and canonicalize them to an IPv4 address, skipping the
    // DnsCacheResolver. The URL parser also STRIPS ASCII tab/newline/CR from the
    // authority before parsing, so `169.254.169.\n254` (and a control-split IPv6
    // such as `fd00:ec2::\n254`) canonicalizes to a literal at dispatch; replicate
    // that strip here, then re-check `IpAddr::parse` so a control-stripped
    // canonical literal is still caught. Stream (`tcp`/`udp`/`dtls`) backends
    // resolve through `DnsCache::resolve` instead and must use
    // [`stream_literal_ip`].
    let stripped;
    let cleaned = if bare.contains(['\t', '\n', '\r']) {
        stripped = bare.replace(['\t', '\n', '\r'], "");
        if let Ok(ip) = stripped.parse::<std::net::IpAddr>() {
            return Some(ip);
        }
        stripped.as_str()
    } else {
        bare
    };

    // Hot-path guard: skip the allocating URL/IDNA parse only for an ordinary
    // ASCII hostname — all-ASCII, NO percent-encoding, AND not beginning with an
    // ASCII digit. Each excluded form is one the URL parser can still resolve to
    // an IPv4 literal, so it must NOT be skipped:
    //  - canonical literals (incl. IPv6) were already handled by `IpAddr::parse`;
    //  - a non-canonical IPv4 spelling (decimal/hex/octal) begins with a digit;
    //  - a NON-ASCII host may be an IDNA/UTS-46 form (e.g. fullwidth digits
    //    `１６９。２５４。１６９。２５４`) the parser maps to an IP;
    //  - a '%'-containing host may percent-DECODE to a digit-leading literal
    //    (`%31%36%39.%32%35%34.%31%36%39.%32%35%34` → `169.254.169.254`), which
    //    the URL parser decodes before IPv4 parsing.
    // For plain ASCII with none of those, the parser's IPv4 path requires the
    // first authority label to parse as a number, which can only start with a
    // digit — so an ASCII, '%'-free, non-digit-leading host is never a literal.
    // This keeps hostname-backed dispatch on the request path allocation-free.
    if cleaned.is_ascii()
        && !cleaned.contains('%')
        && !cleaned
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_digit())
    {
        return None;
    }

    match url::Host::parse(cleaned).ok()? {
        url::Host::Ipv4(ip) => Some(std::net::IpAddr::V4(ip)),
        url::Host::Ipv6(ip) => Some(std::net::IpAddr::V6(ip)),
        url::Host::Domain(_) => None,
    }
}

/// Canonical-literal-only screen (bracket strip + `IpAddr::parse`) for **stream**
/// (`tcp`/`udp`/`dtls`) backends. Their dial path resolves through
/// `DnsCache::resolve`, whose literal fast path is `IpAddr::parse` and which
/// otherwise performs real DNS and then policy-screens the *resolved* address. A
/// non-canonical numeric host (e.g. a service legitimately named `111`) is a DNS
/// NAME on that path, not the URL-canonicalized literal `0.0.0.111`, so it must
/// NOT be canonicalized here — doing so would wrongly reject it at admission even
/// though the stream path would resolve and policy-check the real DNS result. The
/// URL-canonicalizing sibling [`egress_literal_ip`] is for HTTP/URL-dispatched
/// backends.
pub(crate) fn stream_literal_ip(host: &str) -> Option<std::net::IpAddr> {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .parse::<std::net::IpAddr>()
        .ok()
}

/// Wraps the operator pattern in a non-capturing group and anchors the group,
/// ensuring alternation and other top-level regex operators still apply to the
/// full request path. Operators who need prefix-style matching can end their
/// pattern with `.*` to opt out of strict suffix matching.
pub fn anchor_regex_pattern(pattern: &str) -> String {
    let mut core = pattern;
    if let Some(stripped) = core.strip_prefix('^') {
        core = stripped;
    }
    if has_unescaped_trailing_dollar(core) {
        core = &core[..core.len() - 1];
    }
    let wrapped = format!("^(?:{})$", core);
    // In verbose mode `(?x)`, a trailing `#` line comment in the operator
    // pattern (e.g. `~(?x)/foo$ # exact route`) swallows the closing `)$` we
    // append, leaving the non-capturing group unclosed so the regex no longer
    // compiles. Only when the plain wrap fails to compile AND terminating the
    // comment with a newline before the close makes it compile do we use the
    // newline form. Non-verbose patterns always compile plainly, so they never
    // get the newline (which would otherwise be a literal `\n` that breaks
    // matching). A genuinely invalid pattern still fails both and is rejected
    // by the caller's compile check.
    if Regex::new(&wrapped).is_err() {
        let newline_wrapped = format!("^(?:{}\n)$", core);
        if Regex::new(&newline_wrapped).is_ok() {
            return newline_wrapped;
        }
    }
    wrapped
}

fn has_unescaped_trailing_dollar(pattern: &str) -> bool {
    let Some(before_dollar) = pattern.strip_suffix('$') else {
        return false;
    };

    let escaping_backslashes = before_dollar
        .as_bytes()
        .iter()
        .rev()
        .take_while(|&&byte| byte == b'\\')
        .count();
    escaping_backslashes % 2 == 0
}

/// Why a configured `listen_path` is not already a canonical policy path, or
/// `None` when it is usable as written.
///
/// Route lookup runs on the canonical request path
/// (`crate::policy_path::canonicalize_policy_path`), so a `listen_path` that
/// is not itself canonical can never match: either the runtime would reject
/// every request that spelled it that way (`/api%2Fadmin`, an encoded
/// separator) or the runtime path would canonicalize to different bytes
/// (`/%61dmin` -> `/admin`). Both are silently unreachable routes, which is
/// exactly the routing/auth asymmetry the canonical representation exists to
/// remove — so admission rejects them instead. Delegating to the runtime
/// canonicalizer keeps admission and request handling on one model rather
/// than two hand-maintained encoding tables.
///
/// The value is checked exactly as written, markers included, matching the
/// previous encoded-slash admission. `~` and `=` are ordinary path characters
/// to the canonicalizer, and a regex or exact literal carrying an escape the
/// runtime would refuse is unreachable for the same reason.
///
/// A `~regex` value is a *pattern*, not a literal path, so only the escape
/// half of the contract applies to it: `\` and `.` are regex syntax there
/// (`~^/v1\.0/.*` matches the reachable canonical path `/v1.0/x`), while the
/// canonical request path the pattern is evaluated against already cannot
/// contain a backslash or a dot segment. Exact (`=/…`) and prefix values are
/// compared byte-for-byte against that canonical path, so they are held to the
/// full contract.
fn non_canonical_listen_path_reason(path: &str) -> Option<&'static str> {
    if path.starts_with('~') {
        crate::policy_path::non_canonical_policy_path_pattern_reason(path)
    } else {
        crate::policy_path::non_canonical_policy_path_reason(path)
    }
}

/// Whether a proxy's retry policy can actually trigger for at least one request
/// the proxy can admit.
///
/// Mirrors the runtime gates so config validation does not reject combinations
/// that can never retry:
/// - `max_retries == 0` never retries.
/// - `retry_on_connect_failure` is method-agnostic (a connect failure never
///   reaches the HTTP layer), so it makes retry effective for *any* admitted
///   method.
/// - Status-code retries only fire for methods listed in `retryable_methods`,
///   and method admission (`allowed_methods`) runs before backend dispatch. So
///   status retries are only effective when `retryable_methods` overlaps the
///   methods the proxy is allowed to serve.
pub(crate) fn proxy_retry_is_effective(
    retry: Option<&RetryConfig>,
    allowed_methods: Option<&[String]>,
) -> bool {
    let Some(retry) = retry else {
        return false;
    };
    if retry.max_retries == 0 {
        return false;
    }
    if retry.retry_on_connect_failure {
        return true;
    }
    if retry.retryable_status_codes.is_empty() || retry.retryable_methods.is_empty() {
        return false;
    }
    match allowed_methods {
        // `allowed_methods == None` means "allow all", so any retryable method
        // can be admitted.
        None => true,
        Some(allowed) => retry.retryable_methods.iter().any(|retryable| {
            allowed
                .iter()
                .any(|served| served.eq_ignore_ascii_case(retryable))
        }),
    }
}

/// The DestinationRule `connectionPool.http.maxRetries` cap the runtime applies
/// to the SELECTED dispatch target's port, if any.
///
/// Mirrors [`crate::proxy::cap_proxy_retry_for_target`]'s field-level fallback:
/// the per-port `max_retries` wins when set, otherwise the service-discovery
/// top-level overlay (`dispatch_port_override_fallback`) is inherited — so a
/// per-port entry that sets only an unrelated field does not wipe the inherited
/// cap. Returns `None` when the port has no governing cap.
fn proxy_retry_cap_for_port(proxy: &Proxy, port: u16) -> Option<u32> {
    proxy
        .dispatch_port_overrides
        .as_ref()
        .and_then(|overrides| overrides.get(&port))
        .and_then(|o| o.max_retries)
        .or_else(|| {
            proxy
                .dispatch_port_override_fallback
                .as_ref()
                .and_then(|o| o.max_retries)
        })
}

/// Whether `retry` is still effective for a request dispatched to a mesh target,
/// after applying the per-port retry cap the runtime applies before deciding
/// whether retry disables HBONE / SVID-mTLS dispatch.
///
/// The conflicting target's dispatch port (`conflict.port`) drives the per-port
/// cap. It is `Some` for static targets and for mesh service-discovery upstreams
/// whose selected declared Service port is known at admission. It remains `None`
/// when admission cannot prove a concrete policy port, but the runtime's
/// [`crate::proxy::cap_proxy_retry_for_target`] still applies the top-level
/// service-discovery `connectionPool.http.maxRetries` overlay
/// (`Proxy.dispatch_port_override_fallback`) to every discovered target whose
/// per-port lookup misses. So a top-level DestinationRule `maxRetries = 0` on a
/// mesh SD upstream disarms retry for every discovered target at dispatch time
/// and must NOT be rejected here even when no concrete port is known yet.
pub(crate) fn retry_is_effective_for_mesh_target(
    proxy: &Proxy,
    retry: Option<&RetryConfig>,
    allowed_methods: Option<&[String]>,
    conflict: &MeshTransportConflict,
) -> bool {
    let Some(retry) = retry else {
        return false;
    };
    if !proxy_retry_is_effective(Some(retry), allowed_methods) {
        return false;
    }
    // Mirror `cap_proxy_retry_for_target`'s field-level fallback: the per-port
    // `max_retries` for the selected policy port wins when present, otherwise
    // the service-discovery top-level overlay (`dispatch_port_override_fallback`)
    // is inherited. When no policy port is known, only the top-level fallback can
    // be proven to govern — but it governs every discovered target, so honoring
    // it here matches the runtime.
    let cap = conflict
        .port
        .and_then(|port| proxy_retry_cap_for_port(proxy, port))
        .or_else(|| {
            proxy
                .dispatch_port_override_fallback
                .as_ref()
                .and_then(|fallback| fallback.max_retries)
        });
    match cap {
        // A cap of 0 disarms retry for this target at runtime, so the HBONE/mTLS
        // dispatch path is preserved and there is no 502.
        Some(cap) => cap > 0,
        None => true,
    }
}

fn mesh_sd_policy_port(
    upstream: &Upstream,
    mesh_model: Option<&crate::modes::mesh::config::MeshConfig>,
) -> Option<u16> {
    let mesh_sd = upstream.service_discovery.as_ref()?.mesh.as_ref()?;
    if let Some(port) = mesh_sd.port {
        return Some(port);
    }
    let namespace = mesh_sd.namespace.as_deref().unwrap_or(&upstream.namespace);
    mesh_model?
        .services
        .iter()
        .find(|service| {
            service.name.as_str() == mesh_sd.service_name.as_str()
                && service.namespace.as_str() == namespace
        })
        .and_then(|service| service.ports.first())
        .map(|port| port.port)
}

/// Every mesh transport an upstream's selected targets require.
///
/// Returns one [`MeshTransportConflict`] per selectable target that needs a mesh
/// transport (`"mesh.hbone"` / `"mesh.mtls"`), each carrying a human-readable
/// detail and the target's dispatch port. Uses the *runtime* tag predicates
/// ([`crate::proxy::hbone_pool::target_hbone_enabled`] /
/// [`crate::proxy::mesh_mtls_pool::target_mesh_mtls_enabled`]) so it matches the
/// boolish truthiness (`true`/`yes`/`on`/`1`) the dispatch path actually honors.
///
/// Every selectable mesh target is returned (not just the first) because the load
/// balancer can pick any of them, and each target's policy port carries its own
/// `cap_proxy_retry_for_target` cap: a config that zeroes retry on one mesh
/// target's port but leaves another mesh target uncapped still 502s when the LB
/// selects the uncapped one. Callers pair this with
/// [`retry_is_effective_for_mesh_target`] per entry.
///
/// Mesh service-discovery upstreams (`service_discovery.provider = Mesh`) are
/// treated as mesh-transport-requiring even with no static targets, because
/// discovered targets are stamped with the configured topology's transport tag
/// by the mesh discoverer (`mesh.hbone` for `ambient`, `mesh.mtls` for
/// `sidecar`).
fn upstream_required_mesh_transports(
    upstream: &Upstream,
    selected_subset: Option<&str>,
    mesh_model: Option<&crate::modes::mesh::config::MeshConfig>,
) -> Vec<MeshTransportConflict> {
    // Mesh service-discovery upstreams publish mesh-transport-required targets
    // dynamically; their static `targets` list is typically empty at admission.
    if let Some(sd) = upstream
        .service_discovery
        .as_ref()
        .filter(|sd| sd.provider == SdProvider::Mesh)
    {
        let topology = sd
            .mesh
            .as_ref()
            .map(|mesh| mesh.topology)
            .unwrap_or_default();
        let transport = match topology {
            MeshSdTopology::Ambient => "mesh.hbone",
            MeshSdTopology::Sidecar => "mesh.mtls",
        };
        let policy_port = mesh_sd_policy_port(upstream, mesh_model);
        return vec![MeshTransportConflict {
            transport,
            detail: "mesh service discovery".to_string(),
            // Mirror mesh service discovery: explicit `mesh.port` wins, otherwise
            // the first declared Service port owns the discovered targets. If no
            // mesh model is available here, fall back to top-level SD policy only.
            port: policy_port,
        }];
    }

    let subset = selected_subset.and_then(|subset_name| {
        upstream
            .subsets
            .as_ref()
            .and_then(|subsets| subsets.iter().find(|subset| subset.name == subset_name))
    });
    let target_selected = |target: &UpstreamTarget| match subset {
        Some(subset) => subset
            .labels
            .iter()
            .all(|(key, value)| target.tags.get(key).is_some_and(|tag| tag == value)),
        None => true,
    };

    let mut conflicts = Vec::new();
    for target in upstream.targets.iter().filter(|t| target_selected(t)) {
        let transport = if crate::proxy::hbone_pool::target_hbone_enabled(target) {
            Some("mesh.hbone")
        } else if crate::proxy::mesh_mtls_pool::target_mesh_mtls_enabled(target) {
            Some("mesh.mtls")
        } else {
            None
        };
        if let Some(transport) = transport {
            conflicts.push(MeshTransportConflict {
                transport,
                detail: format!("target '{}:{}'", target.host, target.port),
                port: Some(target.dispatch_policy_port()),
            });
        }
    }
    conflicts
}

/// The first selectable mesh target of `upstream` whose required transport still
/// conflicts with `retry` after that target's own per-port cap is applied, or
/// `None` if no selectable mesh target keeps retry effective (so runtime never
/// 502s).
///
/// This is the admission-time equivalent of the runtime sequence: the load
/// balancer selects one target, [`crate::proxy::cap_proxy_retry_for_target`]
/// caps retry for that target's port, and only then does an effective retry
/// disable HBONE/SVID-mTLS dispatch. Because the LB may select *any* mesh target,
/// the conflict is reported when *any* selectable mesh target survives its cap.
pub(crate) fn first_effective_mesh_transport_conflict_with_mesh(
    proxy: &Proxy,
    upstream: &Upstream,
    selected_subset: Option<&str>,
    retry: Option<&RetryConfig>,
    allowed_methods: Option<&[String]>,
    mesh_model: Option<&crate::modes::mesh::config::MeshConfig>,
) -> Option<MeshTransportConflict> {
    upstream_required_mesh_transports(upstream, selected_subset, mesh_model)
        .into_iter()
        .find(|conflict| {
            retry_is_effective_for_mesh_target(proxy, retry, allowed_methods, conflict)
        })
}

/// Project a single referenced upstream's per-port / top-level retry caps onto a
/// throwaway proxy clone so the per-resource admission paths
/// (`Proxy::after_validate`, API-spec import, batch import) model the same
/// `cap_proxy_retry_for_target` cap the runtime applies before deciding whether
/// retry disables HBONE/SVID-mTLS dispatch.
///
/// `Proxy.dispatch_port_overrides` / `Proxy.dispatch_port_override_fallback` are
/// `#[serde(skip)]` DR-derived projections that only
/// [`GatewayConfig::resolve_dispatch_port_overrides`] populates over a full
/// config. A proxy that arrives straight off the admin request body therefore has
/// both fields `None`, so without this projection
/// [`retry_is_effective_for_mesh_target`] cannot see a `maxRetries = 0` cap on the
/// mesh port and would over-reject a config the runtime serves correctly. Mirrors
/// the per-upstream projection in `resolve_dispatch_port_overrides`.
pub(crate) fn proxy_with_resolved_port_caps(proxy: &Proxy, upstream: &Upstream) -> Proxy {
    let mut resolved = proxy.clone();
    resolved.dispatch_port_overrides = if upstream.port_overrides.is_empty() {
        None
    } else {
        let ports: HashMap<u16, ResolvedPortOverride> = upstream
            .port_overrides
            .iter()
            .filter_map(|(port, ovr)| {
                ResolvedPortOverride::from_upstream_override(ovr).map(|r| (*port, r))
            })
            .collect();
        (!ports.is_empty()).then_some(ports)
    };
    resolved.dispatch_port_override_fallback =
        dispatch_port_override_fallback_from_upstream(upstream);
    resolved
}

/// A mesh-transport requirement that conflicts with an effective retry policy.
pub(crate) struct MeshTransportConflict {
    /// The conflicting transport tag (`"mesh.hbone"` / `"mesh.mtls"`).
    transport: &'static str,
    /// Human-readable source of the requirement (a target or `mesh service
    /// discovery`).
    detail: String,
    /// The dispatch policy port of the conflicting target, when known. Mesh
    /// service discovery can provide this before targets exist when admission
    /// has the selected declared Service port. Callers use this to apply the
    /// same per-port retry cap the runtime applies via
    /// [`crate::proxy::cap_proxy_retry_for_target`] before treating retry as
    /// effective for this target.
    port: Option<u16>,
}

/// A `mesh_route_dispatch` upstream override destination paired with the
/// effective retry policy the runtime applies when that rule matches.
struct MeshRouteOverrideDest {
    /// The override `upstream_id` (`route_override_upstream_id`).
    upstream_id: String,
    /// The retry policy in force for requests this rule routes: the rule's own
    /// `retry`, `None` when the rule disables retry, or the proxy's base retry
    /// when the rule leaves retry untouched.
    effective_retry: Option<RetryConfig>,
    /// The upstream subset the runtime selects for this override. A rule that
    /// keeps the proxy's default upstream preserves `proxy.upstream_subset`
    /// (`apply_route_overrides_inner` only clears it when the upstream changes);
    /// a different-upstream rule drops the subset (the new upstream has its own
    /// targets), so this is `None` there. Used so the conflict check filters the
    /// same target set the load balancer would.
    selected_subset: Option<String>,
}

/// Build the canonical retry/mesh-transport conflict error message.
pub(crate) fn mesh_transport_retry_conflict_message(
    proxy_id: &str,
    upstream_id: &str,
    conflict: &MeshTransportConflict,
) -> String {
    format!(
        "Proxy '{}' enables retry but upstream_id '{}' {} requires {} dispatch; retry over required mesh transports is not supported",
        proxy_id, upstream_id, conflict.detail, conflict.transport
    )
}

/// Outcome of screening one enabled plugin config for backend-TLS SNI
/// request-body-buffering admission.
///
/// `shadows_same_named_global` mirrors `PluginCache` merge rules: a disabled
/// config never shadows; a successfully constructed local (or a
/// custom/unknown/`Ok(None)` name) does; a built-in whose configuration fails
/// to construct does not — the cache's `Err` arm leaves the global in place.
struct SniBufferingScreenEffect {
    forces_buffering: bool,
    shadows_same_named_global: bool,
}

/// Screen one plugin config for SNI buffering admission.
///
/// The buffering answer comes from the authoritative
/// [`crate::plugins::Plugin::requires_request_body_buffering`] implementation
/// on an instance built from the SAME parsed configuration the runtime
/// `PluginCache` builds — there is no second, config-shaped re-implementation
/// of the predicate to drift out of sync. See
/// [`crate::plugins::RequestBodyBufferingScreener`] for the side-effect
/// guarantees of that construction.
///
/// A plugin the screen cannot evaluate (custom / unknown plugin, or a
/// configuration that does not construct) is admitted with a value-redacted
/// warning, preserving the documented residual: those requests still fail
/// closed at runtime with a `502` and
/// `gateway-error-reason: backend_tls_sni_requires_direct_h2`.
fn screen_plugin_config_for_sni_buffering(
    proxy_id: &str,
    pc: &PluginConfig,
    screener: &OnceCell<crate::plugins::RequestBodyBufferingScreener>,
) -> SniBufferingScreenEffect {
    if !pc.enabled {
        return SniBufferingScreenEffect {
            forces_buffering: false,
            shadows_same_named_global: false,
        };
    }
    // Built on first use: a proxy whose effective plugin configs are all
    // disabled (or absent) never constructs the screener's HTTP client.
    let screener = screener.get_or_init(crate::plugins::RequestBodyBufferingScreener::new);
    match screener.screen(&pc.plugin_name, &pc.config) {
        crate::plugins::RequestBodyBufferingScreen::Buffers => SniBufferingScreenEffect {
            forces_buffering: true,
            shadows_same_named_global: true,
        },
        crate::plugins::RequestBodyBufferingScreen::Streams => SniBufferingScreenEffect {
            forces_buffering: false,
            shadows_same_named_global: true,
        },
        crate::plugins::RequestBodyBufferingScreen::Indeterminate(gap) => {
            tracing::warn!(
                proxy_id = %proxy_id,
                plugin_config_id = %pc.id,
                plugin_name = %pc.plugin_name,
                reason = gap.as_str(),
                "Backend TLS SNI admission could not evaluate request-body buffering for this \
                 plugin; admitting the proxy. Direct HTTP/2 SNI dispatch still fails closed at \
                 runtime (502, gateway-error-reason: backend_tls_sni_requires_direct_h2) if the \
                 plugin buffers request bodies"
            );
            // `NotBuiltin` covers custom/unknown names and retired aliases
            // (`Ok(None)`): PluginCache still removes the same-named global in
            // those arms. Prefer shadowing (and the documented admit residual)
            // over a false SNI rejection. `ConstructionFailed` mirrors the
            // cache's `Err` arm and must not shadow.
            let shadows_same_named_global = matches!(
                gap,
                crate::plugins::RequestBodyBufferingScreenGap::NotBuiltin
            );
            SniBufferingScreenEffect {
                forces_buffering: false,
                shadows_same_named_global,
            }
        }
    }
}

/// Source description for a backend TLS SNI override that forces direct-H2.
fn proxy_plain_https_sni_sources<'a>(
    proxy: &'a Proxy,
    upstream: Option<&'a Upstream>,
) -> Vec<(&'a str, String)> {
    let mut sources = Vec::new();
    if let Some(sni) = proxy.resolved_tls.sni.as_deref() {
        sources.push((sni, "resolved backend TLS SNI".to_string()));
    }
    if let Some(overrides) = proxy.dispatch_port_overrides.as_ref() {
        for (port, ovr) in overrides {
            if let Some(sni) = ovr.tls.as_ref().and_then(|tls| tls.sni.as_deref()) {
                sources.push((
                    sni,
                    format!("DestinationRule per-port TLS SNI on port {port}"),
                ));
            }
        }
    } else if let Some(upstream) = upstream {
        // Admin/single-resource paths may not have projected
        // `dispatch_port_overrides` yet; still catch Upstream.port_overrides.
        for (port, ovr) in &upstream.port_overrides {
            if let Some(sni) = ovr.tls.as_ref().and_then(|tls| tls.sni.as_deref()) {
                sources.push((
                    sni,
                    format!("DestinationRule per-port TLS SNI on port {port}"),
                ));
            }
        }
        if let Some(sni) = upstream.backend_tls_sni.as_deref()
            && proxy.resolved_tls.sni.is_none()
        {
            sources.push((sni, "upstream backend_tls_sni".to_string()));
        }
    }
    sources
}

/// Reject plain-HTTPS proxies whose backend TLS SNI override cannot dispatch
/// on the direct-H2 pool (retry body replay, request-body buffering plugins,
/// or `pool_enable_http2: false`). Covers proxy-level and DestinationRule
/// per-port TLS overlays so `validate` catches guaranteed total outages.
///
/// The buffering leg is derived from the runtime
/// [`crate::plugins::Plugin::requires_request_body_buffering`] answer of a
/// plugin built from the same parsed config (see
/// [`screen_plugin_config_for_sni_buffering`]), so it tracks every
/// conditional buffering plugin exactly and needs no per-plugin maintenance.
/// Plugin construction happens only for proxies that actually carry a plain
/// HTTPS SNI override, and only for that proxy's effective plugin configs.
pub(crate) fn backend_tls_sni_direct_h2_conflict_messages(
    proxy: &Proxy,
    upstream: Option<&Upstream>,
    plugin_configs: &[PluginConfig],
) -> Vec<String> {
    // gRPC / native H3 own the TLS handshake and support SNI on their pools;
    // the reqwest incompatibility is specific to plain HTTPS (HttpsPool).
    if proxy.dispatch_kind != DispatchKind::HttpsPool {
        return Vec::new();
    }
    let sources = proxy_plain_https_sni_sources(proxy, upstream);
    if sources.is_empty() {
        return Vec::new();
    }
    let sni_desc = sources
        .iter()
        .map(|(sni, source)| format!("'{sni}' ({source})"))
        .collect::<Vec<_>>()
        .join(", ");

    let mut errors = Vec::new();
    if proxy.pool_enable_http2 == Some(false) {
        errors.push(format!(
            "Proxy '{}' sets backend TLS SNI override ({sni_desc}) but pool_enable_http2 is false; \
             plain HTTPS SNI overrides require the direct HTTP/2 backend pool",
            proxy.id
        ));
    }
    if proxy_retry_is_effective(proxy.retry.as_ref(), proxy.allowed_methods.as_deref()) {
        errors.push(format!(
            "Proxy '{}' enables retry with backend TLS SNI override ({sni_desc}); \
             request-body replay for retries is incompatible with direct HTTP/2 SNI dispatch",
            proxy.id
        ));
    }

    // Effective plugins for this proxy: associations + globals in the proxy's
    // namespace (unless a local instance shadows that plugin name — mirror
    // PluginCache tenancy and merge rules for the buffering screen only).
    // Associations resolve by `(namespace, id)` so reused plugin ids in other
    // tenants cannot false-reject this proxy.
    //
    // The screener owns an HTTP client, so build it lazily: proxies without an
    // effective plugin config never pay for one, and non-SNI proxies already
    // returned above.
    let screener: OnceCell<crate::plugins::RequestBodyBufferingScreener> = OnceCell::new();
    let mut local_names: HashSet<&str> = HashSet::new();
    for assoc in &proxy.plugins {
        let Some(pc) = plugin_configs
            .iter()
            .find(|pc| pc.namespace == proxy.namespace && pc.id == assoc.plugin_config_id)
        else {
            continue;
        };
        match pc.scope {
            PluginScope::Global => continue,
            PluginScope::Proxy if pc.proxy_id.as_deref() != Some(proxy.id.as_str()) => continue,
            PluginScope::Proxy | PluginScope::ProxyGroup => {}
        }
        let effect = screen_plugin_config_for_sni_buffering(&proxy.id, pc, &screener);
        // Mirror PluginCache: only locals that would enter (or deliberately
        // clear) the merge list shadow a same-named global. Disabled
        // configs and construction failures do not.
        if effect.shadows_same_named_global {
            local_names.insert(pc.plugin_name.as_str());
        }
        if effect.forces_buffering {
            errors.push(format!(
                "Proxy '{}' attaches request-body-buffering plugin '{}' with backend TLS SNI override ({sni_desc}); \
                 request-body buffering is incompatible with direct HTTP/2 SNI dispatch",
                proxy.id, pc.id
            ));
        }
    }
    for pc in plugin_configs {
        if pc.scope != PluginScope::Global || pc.namespace != proxy.namespace {
            continue;
        }
        if local_names.contains(pc.plugin_name.as_str()) {
            continue;
        }
        let effect = screen_plugin_config_for_sni_buffering(&proxy.id, pc, &screener);
        if effect.forces_buffering {
            errors.push(format!(
                "Proxy '{}' inherits global request-body-buffering plugin '{}' with backend TLS SNI override ({sni_desc}); \
                 request-body buffering is incompatible with direct HTTP/2 SNI dispatch",
                proxy.id, pc.id
            ));
        }
    }
    errors
}

impl GatewayConfig {
    /// Validate that all proxy (host, listen_path) combinations are unique.
    ///
    /// HTTP-family proxies can conflict in two ways:
    /// - Path-carrying proxies share a `listen_path` and have overlapping
    ///   `hosts` (or both use an empty/catch-all host list).
    /// - Host-only proxies (`listen_path.is_none()`) share any host with
    ///   another host-only proxy. Host-only proxies cannot have empty
    ///   `hosts` — that combination is rejected by `validate_fields_inner`.
    ///
    /// Stream proxies are skipped (they route on `listen_port`, not path).
    pub fn validate_unique_listen_paths(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Split proxies into namespace-scoped buckets: those with an explicit
        // listen_path and host-only proxies. Only proxies in the same namespace,
        // the same bucket, AND the same path (for the path bucket) can conflict.
        let mut by_path: HashMap<(&str, &str), Vec<&Proxy>> = HashMap::new();
        let mut host_only: HashMap<&str, Vec<&Proxy>> = HashMap::new();
        for proxy in &self.proxies {
            if proxy.dispatch_kind.is_stream() {
                continue;
            }
            match proxy.listen_path.as_deref() {
                Some(path) => by_path
                    .entry((proxy.namespace.as_str(), path))
                    .or_default()
                    .push(proxy),
                None => host_only
                    .entry(proxy.namespace.as_str())
                    .or_default()
                    .push(proxy),
            }
        }

        // Materialized mesh per-port siblings of ONE service AND ONE
        // direction intentionally share hosts + `/`: the route table inserts
        // a single lowest-port representative per (service, direction) and
        // the request path disambiguates by the captured
        // original-destination port (outbound) or by inbound orig-dst /
        // authority port (sidecar inbound + Sidecar `ingress[]`), so they
        // never route non-deterministically. Map each expected sibling id to
        // its owning (direction, service) pair (derived FORWARD from the mesh
        // block by the same helpers the router grouping uses — id parsing
        // would be lossy across the `{ns}-{name}` join and could conflate
        // distinct services); pairs with equal owners are exempt below. The
        // owner key is DIRECTION-DISTINCT on purpose: an inbound and an
        // outbound route of the same service must never legitimately coexist
        // (the outbound materializer yields to existing inbound routes), so
        // their coexistence is a materializer bug that should keep failing
        // validation. Direction codes: 0 = outbound, 1 = service-port inbound,
        // 2 = Sidecar `ingress[]` (its listeners replace the service-port
        // defaults, so the two never coexist for one workload — but they get
        // distinct codes so a stray pair still fails closed). Operator configs
        // cannot reach this: resource-id validation rejects ids starting with
        // `_`, so `__mesh-*` ids exist only via mesh materialization. Different
        // services' routes still conflict normally. Empty (and zero-cost)
        // outside mesh mode.
        let mut mesh_sibling_owner: HashMap<String, HashMap<String, (u8, usize)>> = HashMap::new();
        if let Some(mesh) = self.mesh.as_deref() {
            let mut add_groups =
                |direction, groups: Vec<crate::modes::mesh::MeshOutboundServiceGroup>| {
                    for (service_index, group) in groups.into_iter().enumerate() {
                        let by_id = mesh_sibling_owner.entry(group.namespace).or_default();
                        for (_, id) in group.siblings {
                            by_id.insert(id, (direction, service_index));
                        }
                    }
                };
            add_groups(0, crate::modes::mesh::mesh_outbound_service_groups(mesh));
            add_groups(1, crate::modes::mesh::mesh_inbound_service_groups(mesh));
            add_groups(2, crate::modes::mesh::mesh_ingress_listener_groups(mesh));
        }

        for ((_, path), group) in &by_path {
            if group.len() < 2 {
                continue;
            }
            for (i, proxy_a) in group.iter().enumerate() {
                for proxy_b in group.iter().skip(i + 1) {
                    if let (Some(owner_a), Some(owner_b)) = (
                        mesh_sibling_owner
                            .get(proxy_a.namespace.as_str())
                            .and_then(|by_id| by_id.get(proxy_a.id.as_str())),
                        mesh_sibling_owner
                            .get(proxy_b.namespace.as_str())
                            .and_then(|by_id| by_id.get(proxy_b.id.as_str())),
                    ) && owner_a == owner_b
                    {
                        continue;
                    }
                    if ambiguous_path_host_overlap(&proxy_a.hosts, &proxy_b.hosts) {
                        if proxy_a.hosts.is_empty() && proxy_b.hosts.is_empty() {
                            errors.push(format!(
                                "Duplicate listen_path '{}' found in proxy '{}' (conflicts with '{}')",
                                path, proxy_b.id, proxy_a.id
                            ));
                        } else {
                            errors.push(format!(
                                "Overlapping host+listen_path for '{}' in proxy '{}' (conflicts with '{}')",
                                path, proxy_b.id, proxy_a.id
                            ));
                        }
                    }
                }
            }
        }

        for group in host_only.values() {
            for (i, proxy_a) in group.iter().enumerate() {
                for proxy_b in group.iter().skip(i + 1) {
                    if hosts_overlap(&proxy_a.hosts, &proxy_b.hosts) {
                        errors.push(format!(
                            "Overlapping host-only proxies '{}' and '{}' — each host can route to at most one host-only proxy",
                            proxy_b.id, proxy_a.id
                        ));
                    }
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate that every effective `mtls_auth` instance can receive a verified
    /// client certificate on the proxy transport where it will execute.
    pub fn validate_mtls_auth_compatibility(&self) -> Result<(), Vec<String>> {
        let errors = self.mtls_auth_compatibility_errors();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Resolve the enabled `mtls_auth` configurations that the plugin cache
    /// would install for each proxy. Any local proxy/proxy-group instance
    /// shadows all global instances of the same plugin type on that proxy.
    fn effective_mtls_auth_plugins_by_proxy(&self) -> Vec<(&Proxy, Vec<&PluginConfig>)> {
        // Association plugin_config_id values are namespace-local to the
        // proxy. A bare-id index would bind a proxy to another tenant's
        // same-id mtls_auth config.
        let plugin_by_key: HashMap<(&str, &str), &PluginConfig> = self
            .plugin_configs
            .iter()
            .map(|plugin| ((plugin.namespace.as_str(), plugin.id.as_str()), plugin))
            .collect();
        let global_mtls: Vec<&PluginConfig> = self
            .plugin_configs
            .iter()
            .filter(|plugin| {
                plugin.enabled
                    && plugin.scope == PluginScope::Global
                    && plugin.plugin_name == "mtls_auth"
            })
            .collect();

        self.proxies
            .iter()
            .map(|proxy| {
                let local_mtls: Vec<&PluginConfig> = proxy
                    .plugins
                    .iter()
                    .filter_map(|association| {
                        let plugin = *plugin_by_key.get(&(
                            proxy.namespace.as_str(),
                            association.plugin_config_id.as_str(),
                        ))?;
                        let scope_applies = match plugin.scope {
                            PluginScope::Proxy => {
                                plugin.namespace == proxy.namespace
                                    && plugin.proxy_id.as_deref() == Some(proxy.id.as_str())
                            }
                            PluginScope::ProxyGroup => {
                                plugin.namespace == proxy.namespace && plugin.proxy_id.is_none()
                            }
                            PluginScope::Global => false,
                        };
                        (plugin.enabled && plugin.plugin_name == "mtls_auth" && scope_applies)
                            .then_some(plugin)
                    })
                    .collect();
                let effective = if local_mtls.is_empty() {
                    // Globals are gateway-wide at runtime (`PluginCache` merges
                    // the single global list into every proxy in every
                    // namespace), so this must NOT be namespace-filtered —
                    // only the association lookup above is namespace-local.
                    global_mtls.clone()
                } else {
                    local_mtls
                };
                (proxy, effective)
            })
            .collect()
    }

    /// Whether the named proxy has at least one enabled `mtls_auth` instance
    /// after resolving local association shadowing against global instances.
    pub(crate) fn has_effective_mtls_auth_for_proxy(&self, proxy_id: &str) -> bool {
        self.effective_mtls_auth_plugins_by_proxy()
            .into_iter()
            .any(|(proxy, plugins)| proxy.id == proxy_id && !plugins.is_empty())
    }

    fn mtls_auth_compatibility_errors(&self) -> Vec<String> {
        let mut errors = Vec::new();

        for (proxy, effective_plugins) in self.effective_mtls_auth_plugins_by_proxy() {
            let scheme = proxy.effective_scheme();
            if !scheme.is_stream() {
                continue;
            }

            for plugin in effective_plugins {
                if !proxy.frontend_tls || proxy.passthrough {
                    errors.push(format!(
                        "Proxy '{}' cannot use mtls_auth PluginConfig '{}': stream mTLS authentication requires frontend_tls=true with TLS/DTLS termination (passthrough=false)",
                        proxy.id, plugin.id
                    ));
                }
            }
        }

        errors
    }

    /// Validate host entries on all proxies.
    ///
    /// Each host must be either a valid lowercase hostname or a wildcard
    /// pattern `*.domain.tld`. No scheme, no port, no path component.
    pub fn validate_hosts(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        for proxy in &self.proxies {
            for host in &proxy.hosts {
                if let Err(msg) = validate_host_entry(host) {
                    errors.push(format!("Proxy '{}': {}", proxy.id, msg));
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate that regex listen_paths compile correctly.
    ///
    /// Listen paths starting with `~` are treated as regex patterns. The `~`
    /// prefix is stripped and the remainder is compiled as a regex (auto-anchored
    /// with `^` and `$` if not already present for full-path matching).
    /// Compilation errors are reported here at config
    /// load time rather than silently skipping routes at runtime.
    pub fn validate_regex_listen_paths(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        for proxy in &self.proxies {
            if proxy.dispatch_kind.is_stream() {
                continue;
            }
            let Some(path) = proxy.listen_path.as_deref() else {
                continue;
            };
            if let Some(pattern) = path.strip_prefix('~') {
                if pattern.is_empty() {
                    errors.push(format!(
                        "Proxy '{}': regex listen_path '~' has empty pattern",
                        proxy.id
                    ));
                    continue;
                }
                let anchored = anchor_regex_pattern(pattern);
                if let Err(e) = Regex::new(&anchored) {
                    errors.push(format!(
                        "Proxy '{}': invalid regex listen_path '{}': {}",
                        proxy.id, path, e
                    ));
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Reject any proxy whose `listen_path` is not already a canonical policy
    /// path (`crate::policy_path`).
    ///
    /// Runs as a dedicated rejecting validator on every load/reload path
    /// because the catch-all `validate_all_fields_with_ip_policy()` is wired
    /// as warn-only for SQL/DP loads (to tolerate per-DP missing files like
    /// TLS certs and `.mmdb` databases). Without this dedicated check, a
    /// `listen_path = "/api%2Fadmin"` row written directly into the DB or
    /// returned by a Mongo backend would still be served and silently
    /// unreachable — the routing/auth bypass the admission rejection in
    /// `Proxy::validate_fields()` is meant to eliminate. Paired with
    /// `non_canonical_listen_path_reason()` in this module and
    /// `canonicalize_policy_path()` in `src/policy_path.rs`.
    pub fn validate_listen_path_encodings(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        for proxy in &self.proxies {
            if proxy.dispatch_kind.is_stream() {
                continue;
            }
            let Some(path) = proxy.listen_path.as_deref() else {
                continue;
            };
            if let Some(reason) = non_canonical_listen_path_reason(path) {
                errors.push(format!(
                    "Proxy '{}': listen_path '{}' is not a canonical policy path ({}); request paths are canonicalized before route lookup, so a non-canonical listen_path is unreachable and creates a routing/auth bypass",
                    proxy.id, path, reason
                ));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Normalize all proxy host entries to lowercase.
    pub fn normalize_hosts(&mut self) {
        for proxy in &mut self.proxies {
            proxy.normalize_fields();
        }
    }

    /// Normalize all resource fields that have canonical in-memory forms and
    /// refresh derived runtime projections skipped by serde.
    pub fn normalize_fields(&mut self) {
        self.frontend_tls_namespace_sources
            .sort_by(|left, right| left.namespace.cmp(&right.namespace));
        self.frontend_tls_namespace_sources
            .dedup_by(|left, right| left.namespace == right.namespace);
        self.normalize_hosts();
        for consumer in &mut self.consumers {
            consumer.normalize_fields();
        }
        for plugin_config in &mut self.plugin_configs {
            plugin_config.normalize_fields();
        }
        for upstream in &mut self.upstreams {
            upstream.normalize_fields();
        }
        // Pre-compute dispatch classification for every proxy — O(1) per
        // proxy at load time, so the request hot path never does any
        // scheme branching.
        self.resolve_dispatch_kind();
        // Rebuild TLS projections after serde or admin/incremental mutations.
        // `Proxy.resolved_tls` is skipped on the wire, so normalization must
        // repopulate it before any runtime snapshot can serve traffic.
        self.resolve_upstream_tls();
        // Project per-port `connect_timeout_ms` overrides from each proxy's
        // upstream onto a flat `Proxy.dispatch_port_overrides` map so the
        // request hot path skips the `ArcSwap` + `DashMap` lookup. No-op for
        // the non-mesh common case (all `Upstream.port_overrides` empty →
        // every proxy gets `None`).
        self.resolve_dispatch_port_overrides();
    }

    /// Resolve each proxy's `dispatch_kind` from `backend_scheme`, applying
    /// the HTTP-family default when the scheme field is absent. Also
    /// canonicalizes `backend_scheme` to `Some(...)` post-normalization so
    /// downstream code (logging, pool keys) can read a concrete scheme
    /// without re-running defaulting.
    ///
    /// Must be called after loading/mutating config and before any proxy
    /// traffic flows. Invoked automatically by `normalize_fields()`; admin
    /// mutation handlers and incremental-apply paths must call it too
    /// (mirrors `resolve_upstream_tls` in that respect).
    pub fn resolve_dispatch_kind(&mut self) {
        for proxy in &mut self.proxies {
            proxy.resolve_dispatch_kind_fields();
        }
    }

    /// Resolve each proxy's `resolved_tls` from its upstream (if any) or its own fields.
    ///
    /// Called by `normalize_fields()` after loading/mutating config and before
    /// any proxy traffic flows. Direct calls are still valid for narrow mutation
    /// paths that only need to refresh TLS projection.
    ///
    /// Proxies with `upstream_subset` set consult the upstream's
    /// `resolved_subset_tls` map first; when the named subset has a resolved
    /// TLS overlay, it replaces the upstream-level TLS as the proxy's
    /// `resolved_tls`. A subset reference that doesn't resolve (unknown
    /// subset, or subset present but carrying no TLS overlay) falls back to
    /// the upstream-level TLS — same behaviour as a proxy with no
    /// `upstream_subset` at all.
    pub fn resolve_upstream_tls(&mut self) {
        // Build a map of (namespace, upstream_id) → TLS config for O(1)
        // lookups. Bare-id maps would last-win across tenants that share an
        // upstream id and project the wrong TLS onto every referencing proxy.
        let upstream_tls: HashMap<(&str, &str), BackendTlsConfig> = self
            .upstreams
            .iter()
            .map(|u| {
                (
                    (u.namespace.as_str(), u.id.as_str()),
                    BackendTlsConfig::from_upstream(u),
                )
            })
            .collect();

        // Parallel map of (namespace, upstream_id, subset_name) → subset-
        // resolved TLS, populated only for subsets that produced a non-empty
        // TLS overlay at mesh apply time. Empty in the non-mesh /
        // no-per-subset-TLS common case, so the per-proxy projection below
        // pays at most one HashMap miss when `upstream_subset` is set.
        let subset_tls: HashMap<(&str, &str, &str), &BackendTlsConfig> = self
            .upstreams
            .iter()
            .flat_map(|u| {
                u.resolved_subset_tls
                    .iter()
                    .filter_map(move |(subset_name, resolved)| {
                        resolved.tls.as_ref().map(|tls| {
                            (
                                (u.namespace.as_str(), u.id.as_str(), subset_name.as_str()),
                                tls,
                            )
                        })
                    })
            })
            .collect();

        for proxy in &mut self.proxies {
            proxy.resolved_tls = if let Some(ref uid) = proxy.upstream_id {
                let ns = proxy.namespace.as_str();
                let subset_override = proxy
                    .upstream_subset
                    .as_deref()
                    .and_then(|name| subset_tls.get(&(ns, uid.as_str(), name)).copied().cloned());
                subset_override
                    .or_else(|| upstream_tls.get(&(ns, uid.as_str())).cloned())
                    .unwrap_or_else(BackendTlsConfig::default_verify)
            } else {
                BackendTlsConfig::from_proxy(proxy)
            };
        }
    }

    /// Project per-port overrides from each proxy's referenced upstream onto
    /// `Proxy.dispatch_port_overrides` for O(1) hot-path resolution.
    ///
    /// Must be called AFTER `apply_destination_rules` has populated
    /// `Upstream.port_overrides`. With this precomputed map on `Proxy`,
    /// `resolve_effective_proxy_for_target` does a single field read instead
    /// of an `ArcSwap` load + `DashMap` traversal per request.
    ///
    /// Same pattern as `resolve_upstream_tls` — derived projection cached on
    /// the proxy so the request path never re-derives it.
    pub fn resolve_dispatch_port_overrides(&mut self) {
        let by_upstream: HashMap<(&str, &str), HashMap<u16, ResolvedPortOverride>> = self
            .upstreams
            .iter()
            .filter(|u| !u.port_overrides.is_empty())
            .map(|u| {
                let ports: HashMap<u16, ResolvedPortOverride> = u
                    .port_overrides
                    .iter()
                    .filter_map(|(port, ovr)| {
                        ResolvedPortOverride::from_upstream_override(ovr)
                            .map(|resolved| (*port, resolved))
                    })
                    .collect();
                ((u.namespace.as_str(), u.id.as_str()), ports)
            })
            .filter(|(_, m)| !m.is_empty())
            .collect();

        // Service-discovery top-level `connectionPool.http` fallback, applied by
        // the LB-selected port at dispatch when that port has no explicit
        // per-port override. Keyed by (namespace, upstream id), separate from
        // the per-port map above so an explicit `portLevelSettings` entry
        // still wins.
        let fallback_by_upstream: HashMap<(&str, &str), ResolvedPortOverride> = self
            .upstreams
            .iter()
            .filter_map(|u| {
                dispatch_port_override_fallback_from_upstream(u)
                    .map(|resolved| ((u.namespace.as_str(), u.id.as_str()), resolved))
            })
            .collect();

        for proxy in &mut self.proxies {
            let key = proxy
                .upstream_id
                .as_deref()
                .map(|uid| (proxy.namespace.as_str(), uid));
            proxy.dispatch_port_overrides = key.and_then(|key| by_upstream.get(&key)).cloned();
            proxy.dispatch_port_override_fallback =
                key.and_then(|key| fallback_by_upstream.get(&key)).cloned();
        }
    }

    /// Validate that consumer ids, usernames, and custom_ids share one identity
    /// namespace.
    ///
    /// In database mode the DB enforces this via UNIQUE constraints. In file
    /// mode there's no DB, so this catches duplicates at config load time
    /// and prevents the gateway from starting with ambiguous identity mappings
    /// that would cause incorrect JWKS/JWT authentication.
    pub fn validate_unique_consumer_identities(&self) -> Result<(), Vec<String>> {
        let mut seen_identities: HashMap<&str, (&str, &'static str)> = HashMap::new();
        let mut duplicates = Vec::new();

        for consumer in &self.consumers {
            for (field, value) in [
                ("id", consumer.id.as_str()),
                ("username", consumer.username.as_str()),
            ] {
                record_consumer_identity(
                    &mut seen_identities,
                    &mut duplicates,
                    &consumer.id,
                    field,
                    value,
                );
            }
            if let Some(ref custom_id) = consumer.custom_id {
                record_consumer_identity(
                    &mut seen_identities,
                    &mut duplicates,
                    &consumer.id,
                    "custom_id",
                    custom_id,
                );
            }
        }

        if duplicates.is_empty() {
            Ok(())
        } else {
            Err(duplicates)
        }
    }

    /// Fail-closed handling of consumer identity collisions at full-load time
    /// (issue #2121): remove every consumer whose id/username/custom_id
    /// collides with the merged identity keyspace of an earlier-loaded
    /// consumer, instead of letting `ConsumerIndex` warn-and-overwrite one
    /// identity mapping (which mis-routes JWKS/JWT authentication).
    ///
    /// First-loaded consumer wins. Callers must load consumers in a stable
    /// order (the SQL and Mongo full loaders sort by id). Self-collisions (a
    /// consumer whose own custom_id equals its own id/username) are allowed, matching
    /// [`Self::validate_unique_consumer_identities`].
    ///
    /// Returns one human-readable message per quarantined consumer; callers
    /// log these at `error!` severity. Persistence-level enforcement (the
    /// `consumer_identity_index` table/collection) prevents *new* collisions
    /// from being committed; this guard covers pre-existing rows.
    pub fn quarantine_colliding_consumer_identities(&mut self) -> Vec<String> {
        let mut claimed: HashMap<String, (String, &'static str)> = HashMap::new();
        let mut messages = Vec::new();

        self.consumers.retain(|consumer| {
            let mut values: Vec<(&'static str, &str)> = vec![
                ("id", consumer.id.as_str()),
                ("username", consumer.username.as_str()),
            ];
            if let Some(ref custom_id) = consumer.custom_id {
                values.push(("custom_id", custom_id.as_str()));
            }
            // Self-collisions within one consumer are fine — dedupe values.
            values.sort_by_key(|(_, value)| *value);
            values.dedup_by_key(|(_, value)| *value);

            let conflict = values.iter().find_map(|(field, value)| {
                claimed
                    .get(*value)
                    .map(|(other_id, other_field)| (*field, *value, other_id.clone(), *other_field))
            });

            match conflict {
                Some((field, value, other_id, other_field)) => {
                    messages.push(format!(
                        "Quarantined consumer '{}': its {} '{}' collides with the {} of \
                         consumer '{}' — the consumer is excluded from this config load to \
                         prevent incorrect JWKS/JWT authentication. Repair the stored \
                         consumer records to restore it.",
                        consumer.id, field, value, other_field, other_id
                    ));
                    false
                }
                None => {
                    for (field, value) in values {
                        claimed.insert(value.to_string(), (consumer.id.clone(), field));
                    }
                    true
                }
            }
        });

        messages
    }

    fn mtls_credential_uniqueness_errors(&self) -> Vec<String> {
        let mut seen_mtls: HashMap<&str, &str> = HashMap::new();
        let mut duplicates = Vec::new();

        for consumer in &self.consumers {
            // Check all mTLS entries.
            for entry in consumer.credential_entries("mtls_auth") {
                if let Some(identity) = entry.get("identity").and_then(|s| s.as_str())
                    && let Some(existing_id) = seen_mtls.insert(identity, &consumer.id)
                {
                    duplicates.push(format!(
                        "Duplicate mtls_auth identity '{}' in consumer '{}' (conflicts with consumer '{}')",
                        identity, consumer.id, existing_id
                    ));
                }
            }
        }

        if let Err(dns_duplicates) = self.validate_unique_mtls_dns_identities() {
            duplicates.extend(dns_duplicates);
        }

        duplicates
    }

    /// Cross-Consumer hmac_auth shared-secret collisions within each
    /// namespace. HMAC signs the credential identity, but a secret reused by
    /// two Consumers in one namespace would still collapse their trust
    /// boundary. Reuse across namespaces and intra-consumer reuse (rotation
    /// entries sharing one secret) are allowed; the secret value itself is
    /// never included in the error message.
    fn hmac_credential_uniqueness_errors(&self) -> Vec<String> {
        let mut seen_hmac: HashMap<(&str, &str), &str> = HashMap::new();
        let mut duplicates = Vec::new();

        for consumer in &self.consumers {
            for entry in consumer.credential_entries("hmac_auth") {
                if let Some(secret) = entry.get("secret").and_then(|s| s.as_str())
                    && let Some(existing_id) = seen_hmac
                        .insert((consumer.namespace.as_str(), secret), consumer.id.as_str())
                    && existing_id != consumer.id
                {
                    duplicates.push(format!(
                        "Duplicate hmac_auth shared secret in consumer '{}' (conflicts with consumer '{}' in namespace '{}')",
                        consumer.id, existing_id, consumer.namespace
                    ));
                }
            }
        }

        duplicates
    }

    /// Validate only the cross-Consumer hmac_auth shared-secret constraint.
    /// Admin candidate checks use this narrower surface so unrelated legacy
    /// keyauth/basicauth collisions do not block HMAC configuration repairs.
    pub fn validate_unique_hmac_credentials(&self) -> Result<(), Vec<String>> {
        let duplicates = self.hmac_credential_uniqueness_errors();

        if duplicates.is_empty() {
            Ok(())
        } else {
            Err(duplicates)
        }
    }

    /// Fail-closed handling of hmac_auth credential policy at full-load time:
    /// strip the `hmac_auth` credential from every consumer whose stored
    /// entries violate the secret policy (non-array credential, empty array,
    /// malformed entry, missing/non-string secret, or fewer than
    /// [`MIN_HMAC_SECRET_LENGTH`] non-whitespace characters) or whose secret
    /// is already claimed by an earlier-loaded consumer in the same namespace
    /// (first-loaded consumer wins; the SQL and Mongo full loaders sort by
    /// id). The same secret may be reused in a different namespace.
    ///
    /// Admin write-time validation rejects NEW violations; this guard covers
    /// pre-existing and out-of-band rows, mirroring
    /// [`Self::quarantine_colliding_consumer_identities`]. A stripped
    /// credential fails closed: the hmac_auth plugin returns 401 for a
    /// consumer with no hmac_auth entries. Returns one human-readable message
    /// per quarantined credential (never containing the secret); callers log
    /// these at `error!` severity.
    pub fn quarantine_invalid_hmac_credentials(&mut self) -> Vec<String> {
        let mut claimed: HashMap<String, HashMap<String, String>> = HashMap::new();
        let mut messages = Vec::new();

        for consumer in &mut self.consumers {
            let Some(value) = consumer.credentials.get("hmac_auth") else {
                continue;
            };
            let secrets: Option<Vec<String>> = match value.as_array() {
                Some(entries) if !entries.is_empty() => entries
                    .iter()
                    .map(|entry| {
                        entry
                            .as_object()
                            .filter(|obj| obj.len() == 1)
                            .and_then(|obj| obj.get("secret"))
                            .and_then(|secret| secret.as_str())
                            .filter(|secret| hmac_secret_strength(secret) >= MIN_HMAC_SECRET_LENGTH)
                            .map(str::to_owned)
                    })
                    .collect(),
                _ => None,
            };
            let Some(secrets) = secrets else {
                consumer.credentials.remove("hmac_auth");
                messages.push(format!(
                    "Quarantined hmac_auth credential of consumer '{}': a stored entry \
                     is malformed or its secret has fewer than {} non-whitespace \
                     characters — the credential is excluded from this config load so \
                     the weak secret cannot authenticate. Repair the stored credential \
                     to restore it.",
                    consumer.id, MIN_HMAC_SECRET_LENGTH
                ));
                continue;
            };
            let namespace_claims = claimed.entry(consumer.namespace.clone()).or_default();
            match secrets
                .iter()
                .find_map(|secret| namespace_claims.get(secret))
            {
                Some(other_id) => {
                    let other_id = other_id.clone();
                    consumer.credentials.remove("hmac_auth");
                    messages.push(format!(
                        "Quarantined hmac_auth credential of consumer '{}': its shared \
                         secret is also claimed by consumer '{}' in namespace '{}' — the credential is \
                         excluded from this config load to prevent cross-Consumer \
                         signature forgery. Rotate one of the secrets to restore it.",
                        consumer.id, other_id, consumer.namespace
                    ));
                }
                None => {
                    for secret in secrets {
                        namespace_claims
                            .entry(secret)
                            .or_insert_with(|| consumer.id.clone());
                    }
                }
            }
        }

        messages
    }

    /// Validate only the exact and effective-DNS mTLS identity constraints.
    /// Admin candidate checks use this narrower surface so unrelated legacy
    /// keyauth/basicauth collisions do not block mTLS configuration repairs.
    pub fn validate_unique_mtls_credentials(&self) -> Result<(), Vec<String>> {
        let duplicates = self.mtls_credential_uniqueness_errors();

        if duplicates.is_empty() {
            Ok(())
        } else {
            Err(duplicates)
        }
    }

    /// Validate that consumer credentials are unique across all consumers.
    ///
    /// Checks keyauth API keys, basicauth usernames, HMAC shared secrets, and
    /// mTLS identities.
    /// mTLS identities are exact by default and additionally ASCII-case-folded
    /// when an effective `san_dns` mTLS policy can consume the DNS lookup index.
    /// If two consumers share the same credential, the ConsumerIndex silently
    /// overwrites one, causing the wrong consumer to be authenticated.
    pub fn validate_unique_consumer_credentials(&self) -> Result<(), Vec<String>> {
        let mut seen_keyauth: HashMap<&str, &str> = HashMap::new();
        let mut seen_basicauth: HashMap<&str, &str> = HashMap::new();
        let mut duplicates = Vec::new();

        for consumer in &self.consumers {
            // Check all keyauth entries.
            for entry in consumer.credential_entries("keyauth") {
                if let Some(key) = entry.get("key").and_then(|s| s.as_str())
                    && let Some(existing_id) = seen_keyauth.insert(key, &consumer.id)
                {
                    // Do NOT include the API key value in the error message for security
                    duplicates.push(format!(
                        "Duplicate keyauth API key in consumer '{}' (conflicts with consumer '{}')",
                        consumer.id, existing_id
                    ));
                }
            }

            // basicauth consumers are indexed by username — duplicates cause silent overwrite
            if consumer.has_credential("basicauth")
                && let Some(existing_id) = seen_basicauth.insert(&consumer.username, &consumer.id)
            {
                duplicates.push(format!(
                    "Duplicate basicauth username '{}' in consumer '{}' (conflicts with consumer '{}')",
                    consumer.username, consumer.id, existing_id
                ));
            }
        }

        duplicates.extend(self.hmac_credential_uniqueness_errors());
        duplicates.extend(self.mtls_credential_uniqueness_errors());

        if duplicates.is_empty() {
            Ok(())
        } else {
            Err(duplicates)
        }
    }

    /// Reject case-variant identities before publishing the lower-cased DNS
    /// lookup index. Exact-match mTLS policies remain case-sensitive.
    pub fn validate_unique_mtls_dns_identities(&self) -> Result<(), Vec<String>> {
        if !self.has_effective_mtls_dns_identity_policy() {
            return Ok(());
        }

        let mut seen_exact: HashMap<&str, &str> = HashMap::new();
        let mut seen_dns: HashMap<String, &str> = HashMap::new();
        let mut duplicates = Vec::new();
        for consumer in &self.consumers {
            for entry in consumer.credential_entries("mtls_auth") {
                let Some(identity) = entry.get("identity").and_then(|value| value.as_str()) else {
                    continue;
                };
                if seen_exact.insert(identity, &consumer.id).is_some() {
                    // The general credential validator reports exact duplicates.
                    continue;
                }
                if let Some(existing_id) =
                    seen_dns.insert(identity.to_ascii_lowercase(), &consumer.id)
                {
                    duplicates.push(format!(
                        "Duplicate mtls_auth DNS identity '{}' (ASCII case-insensitive) in consumer '{}' (conflicts with consumer '{}')",
                        identity, consumer.id, existing_id
                    ));
                }
            }
        }

        if duplicates.is_empty() {
            Ok(())
        } else {
            Err(duplicates)
        }
    }

    /// Whether the proxy/plugin graph can consume the case-folded DNS identity
    /// index. Persistence uses this policy-only predicate before loading the
    /// namespace's Consumers, which keeps ordinary guarded CRUD O(policy graph)
    /// when no enabled `san_dns` policy exists.
    pub(crate) fn has_effective_mtls_dns_identity_policy(&self) -> bool {
        let is_dns_identity_plugin = |plugin: &PluginConfig| {
            plugin.enabled
                && plugin.plugin_name == "mtls_auth"
                && plugin
                    .config
                    .get("cert_field")
                    .and_then(|value| value.as_str())
                    == Some("san_dns")
        };
        // The plugin cache keeps globals as the fallback for every proxy ID
        // absent from its association map, including synthesized mesh relays.
        // Local associations can shadow a global on registered proxies, but
        // cannot make that global dormant for unknown proxy IDs.
        self.plugin_configs
            .iter()
            .any(|plugin| plugin.scope == PluginScope::Global && is_dns_identity_plugin(plugin))
            || self
                .effective_mtls_auth_plugins_by_proxy()
                .into_iter()
                .flat_map(|(_, plugins)| plugins)
                .any(&is_dns_identity_plugin)
    }

    /// Canonical DNS identity owners for every currently ambiguous key.
    ///
    /// Delete admission compares the post-delete map with the pre-delete map.
    /// A delete may retain or reduce restored/out-of-band ambiguity, but it may
    /// not add a canonical key or a new Consumer owner to one. This permits
    /// repair-oriented and unrelated deletes without allowing an identity
    /// collision to be enabled by a policy-graph change.
    pub(crate) fn mtls_dns_identity_conflicts(&self) -> BTreeMap<String, BTreeSet<String>> {
        if !self.has_effective_mtls_dns_identity_policy() {
            return BTreeMap::new();
        }

        let mut owners: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for consumer in &self.consumers {
            for entry in consumer.credential_entries("mtls_auth") {
                let Some(identity) = entry.get("identity").and_then(|value| value.as_str()) else {
                    continue;
                };
                owners
                    .entry(identity.to_ascii_lowercase())
                    .or_default()
                    .insert(consumer.id.clone());
            }
        }
        owners.retain(|_, consumers| consumers.len() > 1);
        owners
    }

    pub(crate) fn introduces_new_mtls_dns_identity_conflict(
        &self,
        prior: &BTreeMap<String, BTreeSet<String>>,
    ) -> bool {
        self.mtls_dns_identity_conflicts()
            .iter()
            .any(|(identity, owners)| {
                !prior
                    .get(identity)
                    .is_some_and(|prior_owners| owners.is_subset(prior_owners))
            })
    }

    /// Validate that upstream names are unique when present.
    ///
    /// The `name` field is optional — multiple upstreams with `None` names
    /// are allowed. Only non-empty names must be unique.
    pub fn validate_unique_upstream_names(&self) -> Result<(), Vec<String>> {
        let mut seen: HashMap<&str, &str> = HashMap::new();
        let mut duplicates = Vec::new();

        for upstream in &self.upstreams {
            if let Some(ref name) = upstream.name
                && let Some(existing_id) = seen.insert(name.as_str(), &upstream.id)
            {
                duplicates.push(format!(
                    "Duplicate upstream name '{}' in upstream '{}' (conflicts with '{}')",
                    name, upstream.id, existing_id
                ));
            }
        }

        if duplicates.is_empty() {
            Ok(())
        } else {
            Err(duplicates)
        }
    }

    /// Validate that proxy names are unique when present.
    ///
    /// The `name` field is optional — multiple proxies with `None` names
    /// are allowed. Only non-empty names must be unique.
    pub fn validate_unique_proxy_names(&self) -> Result<(), Vec<String>> {
        let mut seen: HashMap<&str, &str> = HashMap::new();
        let mut duplicates = Vec::new();

        for proxy in &self.proxies {
            if let Some(ref name) = proxy.name
                && let Some(existing_id) = seen.insert(name.as_str(), &proxy.id)
            {
                duplicates.push(format!(
                    "Duplicate proxy name '{}' in proxy '{}' (conflicts with '{}')",
                    name, proxy.id, existing_id
                ));
            }
        }

        if duplicates.is_empty() {
            Ok(())
        } else {
            Err(duplicates)
        }
    }

    /// Validate that proxy upstream_id references point to existing upstreams.
    ///
    /// In database mode the DB enforces this via foreign key constraints.
    /// In file mode there's no DB, so this catches dangling references
    /// at config load time.
    ///
    /// This also rejects retry-enabled proxies whose effective upstream targets
    /// require a mesh transport (`mesh.hbone` / `mesh.mtls`). At runtime the
    /// dispatch path forces those transports off whenever retry is effective and
    /// then fails closed with a 502 (see issue #1669), so the combination is a
    /// silent reachability gap that we reject at admission instead.
    ///
    /// Plain-HTTPS proxies with a backend TLS SNI override are likewise screened
    /// for combinations that cannot use the direct-H2 pool (effective retry,
    /// request-body-buffering plugins, `pool_enable_http2: false`), including
    /// DestinationRule per-port TLS overlays (issue #2954).
    pub fn validate_upstream_references(&self) -> Result<(), Vec<String>> {
        // Upstream references are namespace-local. A bare-id index would accept
        // a dangling same-namespace reference whenever another tenant owns
        // that id, and would run mesh-transport / subset checks against the
        // wrong upstream.
        let upstreams_by_key: HashMap<(&str, &str), &Upstream> = self
            .upstreams
            .iter()
            .map(|u| ((u.namespace.as_str(), u.id.as_str()), u))
            .collect();
        let mut errors = Vec::new();

        for proxy in &self.proxies {
            if let Some(ref uid) = proxy.upstream_id {
                match upstreams_by_key.get(&(proxy.namespace.as_str(), uid.as_str())) {
                    Some(upstream) => {
                        if let Some(subset_name) = proxy.upstream_subset.as_deref() {
                            let subset_exists = upstream.subsets.as_ref().is_some_and(|subsets| {
                                subsets.iter().any(|s| s.name == subset_name)
                            });
                            if !subset_exists {
                                errors.push(format!(
                                    "Proxy '{}' references upstream_subset '{}' that is not defined on upstream_id '{}'",
                                    proxy.id, subset_name, uid
                                ));
                            }
                        }
                        if let Some(required) = first_effective_mesh_transport_conflict_with_mesh(
                            proxy,
                            upstream,
                            proxy.upstream_subset.as_deref(),
                            proxy.retry.as_ref(),
                            proxy.allowed_methods.as_deref(),
                            self.mesh.as_deref(),
                        ) {
                            errors.push(mesh_transport_retry_conflict_message(
                                &proxy.id, uid, &required,
                            ));
                        }
                    }
                    None => {
                        errors.push(format!(
                            "Proxy '{}' references non-existent upstream_id '{}'",
                            proxy.id, uid
                        ));
                    }
                }
            }

            // Route-level upstream overrides (mesh_route_dispatch) can send
            // matched traffic to a *different* upstream than `proxy.upstream_id`.
            // A retry-enabled proxy whose default upstream is plain but whose
            // route rules target a mesh-tagged upstream would otherwise load and
            // then 502 those matched requests. Validate the override
            // destinations against the same conflict check, using each rule's
            // EFFECTIVE retry (the rule can add/replace/disable retry, which the
            // runtime applies via `route_override_retry` before dispatch).
            for override_dest in self.mesh_route_dispatch_override_destinations(proxy) {
                if let Some(upstream) = upstreams_by_key
                    .get(&(proxy.namespace.as_str(), override_dest.upstream_id.as_str()))
                    && let Some(required) = first_effective_mesh_transport_conflict_with_mesh(
                        // The runtime recomputes `dispatch_port_overrides` from the
                        // OVERRIDE destination upstream when a rule swaps the
                        // upstream (`apply_route_overrides_inner`), so the per-port
                        // retry cap must come from that upstream, not the proxy's
                        // default-upstream-derived caps.
                        &proxy_with_resolved_port_caps(proxy, upstream),
                        upstream,
                        override_dest.selected_subset.as_deref(),
                        override_dest.effective_retry.as_ref(),
                        proxy.allowed_methods.as_deref(),
                        self.mesh.as_deref(),
                    )
                {
                    errors.push(mesh_transport_retry_conflict_message(
                        &proxy.id,
                        override_dest.upstream_id.as_str(),
                        &required,
                    ));
                }
            }

            // Backend TLS SNI on plain HTTPS requires direct-H2; reject
            // combinations that cannot dispatch (retry / body-buffering /
            // pool_enable_http2=false), including DestinationRule per-port
            // TLS overlays projected onto this proxy.
            let upstream = proxy.upstream_id.as_deref().and_then(|uid| {
                upstreams_by_key
                    .get(&(proxy.namespace.as_str(), uid))
                    .copied()
            });
            errors.extend(backend_tls_sni_direct_h2_conflict_messages(
                proxy,
                upstream,
                &self.plugin_configs,
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Collect the upstream overrides this proxy's enabled `mesh_route_dispatch`
    /// plugin instances can route matched traffic to (via
    /// `route_override_upstream_id`), each paired with the EFFECTIVE retry the
    /// runtime applies for that rule.
    ///
    /// Both proxy-scoped/proxy_group associations (`proxy.plugins`) and **global**
    /// `mesh_route_dispatch` plugin configs are considered, because the plugin
    /// cache merges global plugins into every proxy's chain — a global dispatch
    /// rule routes matched requests even when the proxy has no local association.
    /// The one exception: when this proxy attaches its own enabled
    /// `mesh_route_dispatch` instance, `PluginCache::build_cache` shadows the
    /// globals of the same name, so they never run for this proxy and their rules
    /// must NOT be collected (otherwise a conflict in a shadowed global produces a
    /// spurious admission rejection).
    ///
    /// The rule's effective retry mirrors `MeshRouteDispatchPlugin`'s
    /// `route_override_retry` semantics: a rule with `retry` replaces the base
    /// policy, `retry_disabled` clears it, and an unset rule inherits the proxy's
    /// base `retry`. A rule that names the proxy's own default upstream is skipped
    /// *only* when it leaves retry untouched (the default-upstream check already
    /// covers that base retry); a same-upstream rule that adds or replaces retry
    /// is still collected, because the runtime applies `route_override_retry`
    /// before dispatch regardless of whether the upstream changed. Returns an
    /// empty vec when no rule contributes a conflict to check.
    fn mesh_route_dispatch_override_destinations(
        &self,
        proxy: &Proxy,
    ) -> Vec<MeshRouteOverrideDest> {
        let mut overrides: Vec<MeshRouteOverrideDest> = Vec::new();
        let default_uid = proxy.upstream_id.as_deref().unwrap_or("");
        let mut collect = |plugin: &PluginConfig| {
            if !plugin.enabled || plugin.plugin_name != "mesh_route_dispatch" {
                return;
            }
            let Ok(dispatch) =
                crate::plugins::mesh_route_dispatch::MeshRouteDispatchConfig::from_value(
                    &plugin.config,
                )
            else {
                return;
            };
            for rule in &dispatch.rules {
                // A redirect rule answers the request itself
                // (`build_redirect_response` short-circuits before any
                // `route_override_upstream_id` is set), so it never dispatches to
                // `destination.upstream_id` even when one is present. Collecting it
                // would spuriously reject a retry-enabled proxy whose redirect rule
                // names a mesh upstream that no matched request ever reaches.
                if rule.redirect.is_some() {
                    continue;
                }
                let Some(override_uid) = rule.destination.upstream_id.as_deref() else {
                    continue;
                };
                // A rule that points at the proxy's own default upstream but
                // leaves retry untouched is already covered by the
                // default-upstream conflict check; skip it to avoid a duplicate.
                // When the rule changes retry (adds its own or disables it),
                // runtime still overwrites `proxy.retry` via `route_override_retry`
                // before dispatch, so it must be evaluated even for the default
                // upstream.
                let rule_changes_retry = rule.retry.is_some() || rule.retry_disabled;
                if override_uid == default_uid && !rule_changes_retry {
                    continue;
                }
                // Effective retry the runtime would apply for this matched rule.
                //
                // Residual (accepted): a rule's own request-method predicate
                // (`rule.match.methods`) is intentionally NOT modeled here, so two
                // narrow over-rejections remain. (1) When the rule restricts itself
                // to methods outside its own `retryable_methods` (status-code
                // retries only), no request reaching the override can retry. (2)
                // When the rule's method predicate is disjoint from the proxy's
                // `allowed_methods` (e.g. proxy allows only POST, rule matches only
                // GET), method admission rejects every such request before plugins
                // run, so the override is unreachable. Both could be filtered by
                // intersecting the rule's method predicate, but `match.methods`
                // supports prefix/regex matchers (see `MethodMatcher`) that cannot
                // be statically intersected with the concrete `allowed_methods`
                // list, and the lenient case-insensitive `allowed_methods` admission
                // vs the rule's case-sensitive `Exact` matching makes even an
                // exact-only model unsafe (it would introduce fresh under-rejection).
                // `proxy_retry_is_effective` still gates on `allowed_methods`, so the
                // residual is confined to these method-gated mesh-override rules.
                let effective_retry = if rule.retry.is_some() {
                    rule.retry.clone()
                } else if rule.retry_disabled {
                    None
                } else {
                    proxy.retry.clone()
                };
                // Runtime preserves `proxy.upstream_subset` only when the rule
                // keeps the default upstream; a different-upstream override drops
                // it.
                let selected_subset = if override_uid == default_uid {
                    proxy.upstream_subset.clone()
                } else {
                    None
                };
                if !overrides.iter().any(|existing| {
                    existing.upstream_id == override_uid
                        && existing.effective_retry == effective_retry
                        && existing.selected_subset == selected_subset
                }) {
                    overrides.push(MeshRouteOverrideDest {
                        upstream_id: override_uid.to_string(),
                        effective_retry,
                        selected_subset,
                    });
                }
            }
        };
        // A proxy-scoped or proxy_group-scoped `mesh_route_dispatch` instance
        // attached via `proxy.plugins` shadows every global of the same name
        // (`PluginCache::build_cache` removes globals whose `name()` matches a
        // local instance), so the globals' rules never run for this proxy.
        let mut shadows_global_dispatch = false;
        for assoc in &proxy.plugins {
            if let Some(plugin) = self
                .plugin_configs
                .iter()
                .find(|pc| pc.namespace == proxy.namespace && pc.id == assoc.plugin_config_id)
            {
                if plugin.enabled && plugin.plugin_name == "mesh_route_dispatch" {
                    shadows_global_dispatch = true;
                }
                collect(plugin);
            }
        }
        if !shadows_global_dispatch {
            for plugin in &self.plugin_configs {
                // Deliberately NOT namespace-filtered: the association lookup
                // above is namespace-local, but globals run on every proxy in
                // every namespace at runtime. Skipping other tenants' globals
                // here would hide their override destinations from
                // `validate_upstream_references`' mesh-transport screen.
                if plugin.scope == PluginScope::Global {
                    collect(plugin);
                }
            }
        }
        overrides
    }

    /// Validate plugin resource invariants and proxy/plugin associations.
    pub fn validate_plugin_references(&self) -> Result<(), Vec<String>> {
        // Proxy and plugin identities are namespace-local. Bare-id indexes
        // would accept a dangling same-namespace proxy_id whenever another
        // tenant owns that id, and would resolve associations onto the wrong
        // tenant's PluginConfig.
        let proxy_keys: HashSet<(&str, &str)> = self
            .proxies
            .iter()
            .map(|p| (p.namespace.as_str(), p.id.as_str()))
            .collect();
        let plugin_by_key: HashMap<(&str, &str), &PluginConfig> = self
            .plugin_configs
            .iter()
            .map(|pc| ((pc.namespace.as_str(), pc.id.as_str()), pc))
            .collect();
        let mut errors = Vec::new();

        let enabled_prometheus_metrics: Vec<&str> = self
            .plugin_configs
            .iter()
            .filter(|plugin| plugin.enabled && plugin.plugin_name == "prometheus_metrics")
            .map(|plugin| plugin.id.as_str())
            .collect();
        if enabled_prometheus_metrics.len() > 1 {
            errors.push(format!(
                "prometheus_metrics permits at most one enabled global instance; found: {}",
                enabled_prometheus_metrics.join(", ")
            ));
        }

        if let Err(chargeback_errors) = crate::plugins::api_chargeback::validate_composition(self) {
            errors.extend(chargeback_errors);
        }

        if let Err(dedup_errors) = crate::plugins::request_deduplication::validate_composition(self)
        {
            errors.extend(dedup_errors);
        }

        for plugin in &self.plugin_configs {
            // `transaction_log_schema` is process-global by design (it
            // registers named schemas into a single registry); reject
            // proxy / proxy_group scopes explicitly so the error is clear.
            if plugin.plugin_name == "transaction_log_schema" && plugin.scope != PluginScope::Global
            {
                errors.push(format!(
                    "PluginConfig '{}' (transaction_log_schema) must have scope 'global'",
                    plugin.id
                ));
            }
            if plugin.plugin_name == "prometheus_metrics" && plugin.scope != PluginScope::Global {
                errors.push(format!(
                    "PluginConfig '{}' (prometheus_metrics) must have scope 'global'",
                    plugin.id
                ));
            }
            match plugin.scope {
                PluginScope::Global => {
                    if plugin.proxy_id.is_some() {
                        errors.push(format!(
                            "PluginConfig '{}' with scope 'global' must not have proxy_id",
                            plugin.id
                        ));
                    }
                }
                PluginScope::Proxy => match plugin.proxy_id.as_deref() {
                    Some(proxy_id) => {
                        if !proxy_keys.contains(&(plugin.namespace.as_str(), proxy_id)) {
                            errors.push(format!(
                                "PluginConfig '{}' references non-existent proxy_id '{}'",
                                plugin.id, proxy_id
                            ));
                        }
                    }
                    None => errors.push(format!(
                        "PluginConfig '{}' with scope 'proxy' must have proxy_id",
                        plugin.id
                    )),
                },
                PluginScope::ProxyGroup => {
                    if plugin.proxy_id.is_some() {
                        errors.push(format!(
                            "PluginConfig '{}' with scope 'proxy_group' must not have proxy_id (associations are managed via proxy.plugins)",
                            plugin.id
                        ));
                    }
                }
            }
        }

        for proxy in &self.proxies {
            let mut seen_assoc_ids: HashSet<&str> = HashSet::new();
            for assoc in &proxy.plugins {
                if !seen_assoc_ids.insert(assoc.plugin_config_id.as_str()) {
                    errors.push(format!(
                        "Proxy '{}' references plugin_config '{}' more than once",
                        proxy.id, assoc.plugin_config_id
                    ));
                }

                match plugin_by_key
                    .get(&(proxy.namespace.as_str(), assoc.plugin_config_id.as_str()))
                {
                    Some(plugin) => match plugin.scope {
                        PluginScope::Global => {
                            errors.push(format!(
                                "Proxy '{}' references plugin_config '{}' with scope 'global' — proxy associations may only reference proxy-scoped or proxy_group-scoped plugin configs",
                                proxy.id, plugin.id,
                            ));
                        }
                        PluginScope::Proxy => {
                            if plugin.proxy_id.as_deref() != Some(proxy.id.as_str()) {
                                errors.push(format!(
                                    "Proxy '{}' references plugin_config '{}' targeted to proxy '{}'",
                                    proxy.id,
                                    plugin.id,
                                    plugin.proxy_id.as_deref().unwrap_or("<none>")
                                ));
                            }
                        }
                        PluginScope::ProxyGroup => {
                            // ProxyGroup plugins have no proxy_id — any proxy can
                            // reference them via its plugins association list.
                        }
                    },
                    None => errors.push(format!(
                        "Proxy '{}' references non-existent plugin_config '{}'",
                        proxy.id, assoc.plugin_config_id
                    )),
                }
            }
        }

        errors.extend(self.mtls_auth_compatibility_errors());

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate that all resource IDs and namespaces are well-formed.
    ///
    /// Composite runtime keys use a delimiter that is excluded by the shared
    /// ID/namespace grammar. Validate both halves at the config boundary so a
    /// corrupt database row or untrusted file cannot make two tenant
    /// identities collide after encoding.
    pub fn validate_resource_ids(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        for proxy in &self.proxies {
            if let Err(msg) = validate_resource_id(&proxy.id) {
                errors.push(format!("Proxy ID: {}", msg));
            }
            if let Err(msg) = validate_namespace(&proxy.namespace) {
                errors.push(format!("Proxy '{}': {}", proxy.id, msg));
            }
        }
        for consumer in &self.consumers {
            if let Err(msg) = validate_resource_id(&consumer.id) {
                errors.push(format!("Consumer ID: {}", msg));
            }
            if let Err(msg) = validate_namespace(&consumer.namespace) {
                errors.push(format!("Consumer '{}': {}", consumer.id, msg));
            }
        }
        for pc in &self.plugin_configs {
            if let Err(msg) = validate_resource_id(&pc.id) {
                errors.push(format!("PluginConfig ID: {}", msg));
            }
            if let Err(msg) = validate_namespace(&pc.namespace) {
                errors.push(format!("PluginConfig '{}': {}", pc.id, msg));
            }
        }
        for upstream in &self.upstreams {
            if let Err(msg) = validate_resource_id(&upstream.id) {
                errors.push(format!("Upstream ID: {}", msg));
            }
            if let Err(msg) = validate_namespace(&upstream.namespace) {
                errors.push(format!("Upstream '{}': {}", upstream.id, msg));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate that all resource IDs are unique within their type.
    ///
    /// In database mode the DB PRIMARY KEY / UNIQUE `(namespace, id)`
    /// constraint enforces this. In file mode there's no DB, so this catches
    /// duplicate IDs at config load time. Proxies, consumers, plugin configs,
    /// and upstreams are all unique within a namespace — the same id may exist
    /// in two tenants.
    pub fn validate_unique_resource_ids(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        let mut seen_proxy_ids: HashSet<(&str, &str)> = HashSet::new();
        for proxy in &self.proxies {
            if !seen_proxy_ids.insert((&proxy.namespace, &proxy.id)) {
                errors.push(format!(
                    "Duplicate proxy ID '{}' in namespace '{}'",
                    proxy.id, proxy.namespace
                ));
            }
        }

        let mut seen_consumer_ids: HashSet<(&str, &str)> = HashSet::new();
        for consumer in &self.consumers {
            if !seen_consumer_ids.insert((&consumer.namespace, &consumer.id)) {
                errors.push(format!(
                    "Duplicate consumer ID '{}' in namespace '{}'",
                    consumer.id, consumer.namespace
                ));
            }
        }

        let mut seen_plugin_ids: HashSet<(&str, &str)> = HashSet::new();
        for pc in &self.plugin_configs {
            if !seen_plugin_ids.insert((&pc.namespace, &pc.id)) {
                errors.push(format!(
                    "Duplicate plugin_config ID '{}' in namespace '{}'",
                    pc.id, pc.namespace
                ));
            }
        }

        let mut seen_upstream_ids: HashSet<(&str, &str)> = HashSet::new();
        for upstream in &self.upstreams {
            if !seen_upstream_ids.insert((&upstream.namespace, &upstream.id)) {
                errors.push(format!(
                    "Duplicate upstream ID '{}' in namespace '{}'",
                    upstream.id, upstream.namespace
                ));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate stream proxy (TCP/UDP) configuration.
    ///
    /// - Stream proxies must have a `listen_port` in range 1024-65535.
    /// - `listen_port` must be unique across all stream proxies, **unless** all
    ///   proxies sharing the port have `passthrough: true` (SNI-based routing).
    /// - HTTP proxies must not set `listen_port`.
    /// - Passthrough proxies sharing a port must have non-overlapping `hosts`
    ///   and at most one may have empty `hosts` (catch-all/default).
    pub fn validate_stream_proxies(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        // Retain the exact proxy entries for each shared port. Proxy IDs are
        // unique only within a namespace, so resolving these entries later by
        // bare ID can select the wrong tenant and let an invalid mixed
        // passthrough/PROXY-protocol/host configuration pass validation.
        let mut port_proxies: HashMap<u16, Vec<&Proxy>> = HashMap::new();

        for proxy in &self.proxies {
            if proxy.dispatch_kind.is_stream() {
                match proxy.listen_port {
                    None => {
                        errors.push(format!(
                            "Stream proxy '{}' (scheme {}) must have a listen_port",
                            proxy.id,
                            proxy.scheme_display()
                        ));
                    }
                    Some(port) if port < 1 => {
                        errors.push(format!(
                            "Stream proxy '{}' has invalid listen_port {} (must be >= 1)",
                            proxy.id, port
                        ));
                    }
                    Some(port) => {
                        port_proxies.entry(port).or_default().push(proxy);
                    }
                }
            } else if proxy.listen_port.is_some() {
                errors.push(format!(
                    "HTTP proxy '{}' (scheme {}) must not set listen_port",
                    proxy.id,
                    proxy.scheme_display()
                ));
            }
            // stream_proxy_protocol is only valid for TCP/TCP-TLS stream
            // proxies. UDP/DTLS cannot carry a PROXY protocol header (it is
            // TCP-borne), and HTTP proxies use XFF instead.
            if proxy.stream_proxy_protocol == Some(true) {
                let is_tcp_stream = matches!(
                    proxy.dispatch_kind,
                    DispatchKind::TcpRaw | DispatchKind::TcpTls
                );
                if !is_tcp_stream {
                    errors.push(format!(
                        "Proxy '{}' (scheme {}) sets stream_proxy_protocol but PROXY protocol \
                         is only valid for tcp/tcp_tls stream proxies",
                        proxy.id,
                        proxy.scheme_display()
                    ));
                }
            }
        }

        // Validate port sharing rules
        for (port, proxies_on_port) in &port_proxies {
            if proxies_on_port.len() <= 1 {
                continue; // No conflict for single-proxy ports
            }

            // All proxies sharing a port must have passthrough: true
            let all_passthrough = proxies_on_port.iter().all(|p| p.passthrough);
            if !all_passthrough {
                let non_pt: Vec<&str> = proxies_on_port
                    .iter()
                    .filter(|p| !p.passthrough)
                    .map(|p| p.id.as_str())
                    .collect();
                errors.push(format!(
                    "Duplicate listen_port {} — all proxies sharing a port must have passthrough: true, \
                     but {} do not",
                    port,
                    non_pt.join(", ")
                ));
                continue;
            }

            // All proxies sharing a port must agree on stream_proxy_protocol:
            // the PROXY header is read from the raw stream BEFORE the TLS
            // ClientHello, so SNI-based proxy resolution has not happened yet
            // and the accept loop can only apply one per-listener decision.
            let pp_enabled: Vec<&str> = proxies_on_port
                .iter()
                .filter(|p| p.stream_proxy_protocol == Some(true))
                .map(|p| p.id.as_str())
                .collect();
            if !pp_enabled.is_empty() && pp_enabled.len() != proxies_on_port.len() {
                errors.push(format!(
                    "Shared listen_port {} mixes stream_proxy_protocol settings ({} enable it) — \
                     the PROXY header is parsed before SNI resolution, so every proxy sharing a \
                     port must agree on stream_proxy_protocol",
                    port,
                    pp_enabled.join(", ")
                ));
            }

            // At most one proxy per port may have empty hosts (catch-all)
            let catch_all_count = proxies_on_port
                .iter()
                .filter(|p| p.hosts.is_empty())
                .count();
            if catch_all_count > 1 {
                errors.push(format!(
                    "Passthrough port {} has {} proxies with empty hosts — at most one catch-all is allowed",
                    port, catch_all_count
                ));
            }

            // Check for host overlap between every pair
            for (i, a) in proxies_on_port.iter().enumerate() {
                for b in &proxies_on_port[i + 1..] {
                    if hosts_overlap(&a.hosts, &b.hosts) {
                        errors.push(format!(
                            "Passthrough proxies '{}' and '{}' on port {} have overlapping hosts — \
                             each SNI hostname must route to exactly one proxy",
                            a.id, b.id, port
                        ));
                    }
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate that stream proxy ports do not conflict with gateway reserved ports.
    ///
    /// Reserved ports are the gateway's own listener ports (proxy HTTP/HTTPS,
    /// admin HTTP/HTTPS, CP gRPC). A stream proxy binding to one of these would
    /// shadow the gateway listener and cause startup failures or undefined behavior.
    pub fn validate_stream_proxy_port_conflicts(
        &self,
        reserved_ports: &std::collections::HashSet<u16>,
    ) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        for proxy in &self.proxies {
            if proxy.dispatch_kind.is_stream()
                && let Some(port) = proxy.listen_port
                && reserved_ports.contains(&port)
            {
                errors.push(format!(
                    "Stream proxy '{}' listen_port {} conflicts with a gateway reserved port \
                     (proxy/admin/gRPC listener)",
                    proxy.id, port
                ));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_connect_timeout() -> u64 {
    5000
}

fn default_read_timeout() -> u64 {
    30000
}

fn default_write_timeout() -> u64 {
    30000
}

fn default_udp_idle_timeout() -> u64 {
    60
}

/// Validate a single host entry.
///
/// Valid formats:
/// - Exact hostname: `api.example.com` (lowercase, no scheme/port/path)
/// - Wildcard: `*.example.com` (DNS suffix wildcard prefix)
pub fn validate_host_entry(host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err("host entry must not be empty".to_string());
    }
    if host.len() > MAX_HOST_LENGTH {
        return Err(format!(
            "host '{}' must not exceed {} characters (got {})",
            host,
            MAX_HOST_LENGTH,
            host.len()
        ));
    }
    if host.trim() != host {
        return Err(format!(
            "host '{}' must not have leading or trailing whitespace",
            host
        ));
    }
    if host.contains("://") {
        return Err(format!(
            "host '{}' must not contain a scheme (e.g., 'http://')",
            host
        ));
    }
    if host.contains(':') && !host.starts_with('*') {
        return Err(format!("host '{}' must not contain a port number", host));
    }
    if host.contains('/') {
        return Err(format!("host '{}' must not contain a path", host));
    }
    if host != host.to_lowercase() {
        return Err(format!(
            "host '{}' must be lowercase (got mixed case)",
            host
        ));
    }
    if let Some(wildcard_suffix) = host.strip_prefix("*.") {
        if !WILDCARD_HOST_REGEX.is_match(host) {
            return Err(format!(
                "wildcard host '{}' is invalid: must be '*.domain.tld' format",
                host
            ));
        }
        validate_hostname_labels(wildcard_suffix, host)?;
    } else if host.contains('*') {
        return Err(format!(
            "host '{}' has invalid wildcard: '*' is only allowed as prefix '*.domain'",
            host
        ));
    } else if !HOST_REGEX.is_match(host) {
        return Err(format!(
            "host '{}' is invalid: must be a valid hostname (lowercase letters, digits, dots, hyphens)",
            host
        ));
    } else {
        validate_hostname_labels(host, host)?;
    }
    Ok(())
}

fn validate_hostname_labels(hostname: &str, original: &str) -> Result<(), String> {
    for label in hostname.split('.') {
        if label.is_empty() {
            return Err(format!("host '{}' must not contain empty labels", original));
        }
        if label.len() > 63 {
            return Err(format!(
                "host '{}' contains a label longer than 63 characters",
                original
            ));
        }
        let starts_alnum = label
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_alphanumeric());
        let ends_alnum = label
            .as_bytes()
            .last()
            .is_some_and(|b| b.is_ascii_alphanumeric());
        if !starts_alnum || !ends_alnum {
            return Err(format!(
                "host '{}' labels must start and end with an alphanumeric character",
                original
            ));
        }
    }
    Ok(())
}

/// Check whether two host lists overlap.
///
/// Empty hosts means "match all" (catch-all), which overlaps with everything.
/// Otherwise, checks for any shared exact host or wildcard-to-exact match.
pub fn hosts_overlap(a: &[String], b: &[String]) -> bool {
    // Empty = catch-all, overlaps with everything
    if a.is_empty() || b.is_empty() {
        return true;
    }

    let a_set: HashSet<&str> = a.iter().map(|s| s.as_str()).collect();
    let b_set: HashSet<&str> = b.iter().map(|s| s.as_str()).collect();

    // Check exact overlaps
    if a_set.intersection(&b_set).next().is_some() {
        return true;
    }

    // Check wildcard-to-exact and wildcard-to-wildcard overlaps
    for host_a in a {
        for host_b in b {
            if wildcard_matches(host_a, host_b) || wildcard_matches(host_b, host_a) {
                return true;
            }
        }
    }

    false
}

fn ambiguous_path_host_overlap(a: &[String], b: &[String]) -> bool {
    // Empty = catch-all. The catch-all tier sits behind exact and wildcard
    // routes, but two same-path catch-all/specific routes are still ambiguous
    // for configuration ownership and should fail closed.
    if a.is_empty() || b.is_empty() {
        return true;
    }

    let a_set: HashSet<&str> = a.iter().map(|s| s.as_str()).collect();
    let b_set: HashSet<&str> = b.iter().map(|s| s.as_str()).collect();
    if a_set.intersection(&b_set).next().is_some() {
        return true;
    }

    for host_a in a {
        for host_b in b {
            let wildcard_a = host_a.starts_with("*.");
            let wildcard_b = host_b.starts_with("*.");
            if wildcard_a != wildcard_b {
                // Exact-host routes are checked before wildcard-host routes in
                // RouterCache, so this overlap is deterministic.
                continue;
            }
            if wildcard_matches(host_a, host_b) || wildcard_matches(host_b, host_a) {
                return true;
            }
        }
    }

    false
}

// ---- Field-level validation ----

/// Check if a string contains ASCII control characters (excluding common whitespace).
/// Rejects null bytes, backspace, escape, etc. that could cause log injection.
/// Human-readable JSON value type name for error messages.
fn elem_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn contains_control_chars(s: &str) -> bool {
    s.bytes()
        .any(|b| b < 0x20 && b != b'\t' && b != b'\n' && b != b'\r')
}

/// Validate a string field length and reject control characters.
/// Returns `Err(message)` if the value exceeds `max_len` or contains control characters.
fn validate_string_field(field_name: &str, value: &str, max_len: usize) -> Result<(), String> {
    if value.len() > max_len {
        return Err(format!(
            "{} must not exceed {} characters (got {})",
            field_name,
            max_len,
            value.len()
        ));
    }
    if contains_control_chars(value) {
        return Err(format!(
            "{} must not contain control characters",
            field_name
        ));
    }
    Ok(())
}

fn validate_tls_material_source_field(
    field_name: &str,
    value: &str,
    kind: crate::tls::source::MaterialKind,
) -> Result<(), String> {
    match crate::tls::source::CertSource::parse(value, kind) {
        crate::tls::source::CertSource::InlinePem(_) => {
            validate_string_field(field_name, value, MAX_TLS_INLINE_PEM_LENGTH)
        }
        _ => validate_string_field(field_name, value, MAX_FILE_PATH_LENGTH),
    }
}

/// Validate that a PEM certificate source is readable and every declared
/// certificate record parses successfully.
pub fn validate_pem_cert_file(field_name: &str, path: &str) -> Result<(), String> {
    let source =
        crate::tls::source::CertSource::parse(path, crate::tls::source::MaterialKind::Cert);
    let material = match crate::tls::source::load_material_blocking(
        &source,
        crate::tls::source::MaterialKind::Cert,
    ) {
        Ok(material) => material,
        Err(crate::tls::source::MaterialError::UnsupportedScheme { .. }) => return Ok(()),
        Err(e) => {
            return Err(format!(
                "{}: failed to load certificate source '{}': {}",
                field_name,
                source.redacted_source_id(),
                e
            ));
        }
    };
    crate::tls::parse_pem_certificate_bundle(
        material.bytes.expose_secret(),
        field_name,
        &material.display_source_id,
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

/// Validate that a PEM CA source is readable and every declared certificate is
/// admissible as a trust anchor. Syntax-only success is insufficient for a
/// selected exclusive custom store.
pub fn validate_pem_ca_file(field_name: &str, path: &str) -> Result<(), String> {
    let source =
        crate::tls::source::CertSource::parse(path, crate::tls::source::MaterialKind::CaBundle);
    let material = match crate::tls::source::load_material_blocking(
        &source,
        crate::tls::source::MaterialKind::CaBundle,
    ) {
        Ok(material) => material,
        Err(crate::tls::source::MaterialError::UnsupportedScheme { .. }) => return Ok(()),
        Err(e) => {
            return Err(format!(
                "{}: failed to load CA source '{}': {}",
                field_name,
                source.redacted_source_id(),
                e
            ));
        }
    };
    crate::tls::root_cert_store_from_pem_bundle(
        material.bytes.expose_secret(),
        field_name,
        &material.display_source_id,
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

/// Validate that a private key source is usable for backend mTLS.
///
/// Materializable sources must contain a PEM private key. PKCS#11 sources are
/// validated through the token when the `pkcs11` feature is enabled.
pub fn validate_pem_key_file(field_name: &str, path: &str) -> Result<(), String> {
    let source = crate::tls::source::CertSource::parse(path, crate::tls::source::MaterialKind::Key);
    if let crate::tls::source::CertSource::Uri(uri) = &source
        && uri.scheme == crate::tls::source::SourceScheme::Pkcs11
    {
        return validate_pkcs11_key_source(field_name, uri);
    }
    let material = match crate::tls::source::load_material_blocking(
        &source,
        crate::tls::source::MaterialKind::Key,
    ) {
        Ok(material) => material,
        Err(crate::tls::source::MaterialError::UnsupportedScheme { .. }) => return Ok(()),
        Err(e) => {
            return Err(format!(
                "{}: failed to load key source '{}': {}",
                field_name,
                source.redacted_source_id(),
                e
            ));
        }
    };
    crate::tls::parse_pem_private_key(
        material.bytes.expose_secret(),
        field_name,
        &material.display_source_id,
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn tls_validation_cache_key(kind: crate::tls::source::MaterialKind, path: &str) -> String {
    format!("{}:{path}", kind.as_str())
}

#[cfg(feature = "pkcs11")]
fn validate_pkcs11_key_source(
    field_name: &str,
    uri: &crate::tls::source::CertSourceUri,
) -> Result<(), String> {
    crate::tls::pkcs11::validate_key_source_uri(uri).map_err(|error| {
        format!(
            "{}: failed to validate PKCS#11 key source '{}': {}",
            field_name,
            uri.source_id(),
            error
        )
    })
}

#[cfg(not(feature = "pkcs11"))]
fn validate_pkcs11_key_source(
    field_name: &str,
    uri: &crate::tls::source::CertSourceUri,
) -> Result<(), String> {
    Err(format!(
        "{}: PKCS#11 key source '{}' requires building ferrum-edge with the 'pkcs11' Cargo feature",
        field_name,
        uri.source_id()
    ))
}

/// Failure class for a country MMDB dependency.
///
/// A node-local file that is absent or unreadable remains eligible for the
/// configured request-time lookup-failure policy. A file that was read but is
/// corrupt, the wrong MaxMind product, or incompatible with country lookups is
/// rejected instead of being published as an apparently working policy.
#[derive(Clone, Debug)]
pub enum CountryMmdbLoadError {
    Unavailable(String),
    Invalid(String),
}

type CountryMmdbReader = maxminddb::Reader<Vec<u8>>;
type CountryMmdbDigest = [u8; 32];

#[derive(Debug, Eq, PartialEq)]
struct CountryMmdbFileVersion {
    path: PathBuf,
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
}

impl CountryMmdbFileVersion {
    fn from_metadata(path: &str, metadata: &std::fs::Metadata) -> Self {
        Self {
            path: PathBuf::from(path),
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: std::os::unix::fs::MetadataExt::dev(metadata),
            #[cfg(unix)]
            inode: std::os::unix::fs::MetadataExt::ino(metadata),
            #[cfg(unix)]
            changed_seconds: std::os::unix::fs::MetadataExt::ctime(metadata),
            #[cfg(unix)]
            changed_nanoseconds: std::os::unix::fs::MetadataExt::ctime_nsec(metadata),
        }
    }
}

/// Immutable, fully validated country MMDB snapshot shared by live plugins.
pub struct CountryMmdbSnapshot {
    reader: CountryMmdbReader,
    size_bytes: u64,
}

impl CountryMmdbSnapshot {
    pub(crate) fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

impl std::ops::Deref for CountryMmdbSnapshot {
    type Target = maxminddb::Reader<Vec<u8>>;

    fn deref(&self) -> &Self::Target {
        &self.reader
    }
}

struct CountryMmdbGenerationHandoff {
    expected_paths: HashSet<PathBuf>,
    snapshots: HashMap<PathBuf, Arc<CountryMmdbSnapshot>>,
    failures: HashMap<PathBuf, CountryMmdbLoadError>,
    aggregate_budget: CountryMmdbAggregateBudget,
}

#[derive(Default)]
struct CountryMmdbAggregateBudget {
    // The content cache retains one snapshot per digest, so aggregate
    // accounting uses that same stable identity. Equivalent path spellings
    // (relative/absolute, symlink aliases, or redundant components) cannot
    // double-charge bytes that ultimately resolve to one immutable snapshot.
    admitted_snapshots: HashMap<CountryMmdbDigest, u64>,
    admitted_bytes: u64,
}

impl CountryMmdbAggregateBudget {
    fn admit(
        &mut self,
        path: &str,
        digest: CountryMmdbDigest,
        size: u64,
    ) -> Result<(), CountryMmdbLoadError> {
        if let Some(admitted_size) = self.admitted_snapshots.get(&digest) {
            if *admitted_size == size {
                return Ok(());
            }
            return Err(CountryMmdbLoadError::Invalid(format!(
                "MaxMind database content for '{path}' changed size from {admitted_size} to {size} bytes during aggregate admission"
            )));
        }

        let next_bytes = self.admitted_bytes.checked_add(size).ok_or_else(|| {
            CountryMmdbLoadError::Invalid(format!(
                "MaxMind database aggregate snapshot size overflow while admitting '{path}'"
            ))
        })?;
        if next_bytes > MAX_COUNTRY_MMDB_AGGREGATE_SIZE_BYTES {
            return Err(CountryMmdbLoadError::Invalid(format!(
                "MaxMind database aggregate snapshot budget exceeded: loading '{path}' ({size} bytes) would bring this generation/load session to {next_bytes} bytes; maximum aggregate size is {MAX_COUNTRY_MMDB_AGGREGATE_SIZE_BYTES} bytes"
            )));
        }

        self.admitted_snapshots.insert(digest, size);
        self.admitted_bytes = next_bytes;
        Ok(())
    }
}

fn validate_country_mmdb_snapshot_peak(
    path: &str,
    live_bytes: u64,
    inflight_bytes: u64,
    candidate_bytes: u64,
) -> Result<u64, CountryMmdbLoadError> {
    let retained_bytes = live_bytes.checked_add(inflight_bytes).ok_or_else(|| {
        CountryMmdbLoadError::Invalid(
            "MaxMind database retained snapshot size overflow".to_string(),
        )
    })?;
    let peak_bytes = retained_bytes.checked_add(candidate_bytes).ok_or_else(|| {
        CountryMmdbLoadError::Invalid(format!(
            "MaxMind database peak snapshot size overflow while admitting '{path}'"
        ))
    })?;
    if peak_bytes > MAX_COUNTRY_MMDB_AGGREGATE_SIZE_BYTES {
        return Err(CountryMmdbLoadError::Invalid(format!(
            "MaxMind database peak snapshot budget exceeded: loading '{path}' ({candidate_bytes} bytes) while retaining {live_bytes} live and {inflight_bytes} in-flight bytes would require {peak_bytes} bytes; maximum aggregate size is {MAX_COUNTRY_MMDB_AGGREGATE_SIZE_BYTES} bytes. If this changes a live database, it cannot be hot-replaced under the bounded overlap budget and requires a gateway restart after the replacement is installed; otherwise the resulting configuration itself exceeds the aggregate budget"
        )));
    }
    Ok(peak_bytes)
}

#[derive(Default)]
struct CountryMmdbCache {
    by_digest: HashMap<CountryMmdbDigest, Weak<CountryMmdbSnapshot>>,
    /// Candidate buffers that passed peak admission but have not yet become
    /// content-addressed snapshots. Tracking them globally prevents concurrent
    /// reloads from each admitting against the same live-only baseline.
    inflight_snapshot_bytes: u64,
    /// Generation-owned strong references bridge dependency validation to the
    /// immediately following plugin-cache build. A failed validation pipeline
    /// aborts its generation; an accepted generation supersedes the previous
    /// unclaimed generation atomically, and construction claims every snapshot
    /// into a build-scoped session.
    validation_handoffs: HashMap<u64, CountryMmdbGenerationHandoff>,
    active_validation_generations: HashSet<u64>,
    accepted_validation_generation: Option<u64>,
    next_validation_generation: u64,
}

impl CountryMmdbCache {
    fn retain_live(&mut self) {
        self.by_digest.retain(|_, reader| reader.strong_count() > 0);
    }

    fn get_by_digest(&self, digest: &CountryMmdbDigest) -> Option<Arc<CountryMmdbSnapshot>> {
        self.by_digest.get(digest).and_then(Weak::upgrade)
    }

    fn live_snapshot_bytes(&self) -> Result<u64, CountryMmdbLoadError> {
        self.by_digest
            .values()
            .filter_map(Weak::upgrade)
            .try_fold(0_u64, |total, snapshot| {
                total.checked_add(snapshot.size_bytes()).ok_or_else(|| {
                    CountryMmdbLoadError::Invalid(
                        "MaxMind database live snapshot size overflow".to_string(),
                    )
                })
            })
    }

    fn reserve_snapshot_allocation(
        &mut self,
        path: &str,
        candidate_bytes: u64,
    ) -> Result<(), CountryMmdbLoadError> {
        let live_bytes = self.live_snapshot_bytes()?;
        validate_country_mmdb_snapshot_peak(
            path,
            live_bytes,
            self.inflight_snapshot_bytes,
            candidate_bytes,
        )?;
        self.inflight_snapshot_bytes = self
            .inflight_snapshot_bytes
            .checked_add(candidate_bytes)
            .ok_or_else(|| {
                CountryMmdbLoadError::Invalid(
                    "MaxMind database in-flight snapshot size overflow".to_string(),
                )
            })?;
        Ok(())
    }

    fn release_snapshot_allocation(&mut self, candidate_bytes: u64) {
        if let Some(remaining) = self.inflight_snapshot_bytes.checked_sub(candidate_bytes) {
            self.inflight_snapshot_bytes = remaining;
        } else {
            tracing::error!(
                candidate_bytes,
                inflight_bytes = self.inflight_snapshot_bytes,
                "MaxMind database snapshot allocation accounting underflow"
            );
            self.inflight_snapshot_bytes = 0;
        }
    }

    fn prepare_snapshot_return(
        &mut self,
        path: &str,
        snapshot: Arc<CountryMmdbSnapshot>,
        validation_generation: Option<u64>,
    ) -> Arc<CountryMmdbSnapshot> {
        if let Some(generation) = validation_generation
            && let Some(handoff) = self.validation_handoffs.get_mut(&generation)
        {
            handoff
                .snapshots
                .insert(PathBuf::from(path), Arc::clone(&snapshot));
        }

        snapshot
    }

    fn admit_validation_snapshot(
        &mut self,
        generation: u64,
        path: &str,
        digest: CountryMmdbDigest,
        size: u64,
    ) -> Result<(), CountryMmdbLoadError> {
        let handoff = self
            .validation_handoffs
            .get_mut(&generation)
            .ok_or_else(|| {
                CountryMmdbLoadError::Invalid(
                    "MaxMind database validation generation is no longer active".to_string(),
                )
            })?;
        handoff.aggregate_budget.admit(path, digest, size)
    }

    fn record_validation_failure(
        &mut self,
        generation: u64,
        path: &str,
        error: CountryMmdbLoadError,
    ) -> Result<(), CountryMmdbLoadError> {
        let handoff = self
            .validation_handoffs
            .get_mut(&generation)
            .ok_or_else(|| {
                CountryMmdbLoadError::Invalid(
                    "MaxMind database validation generation is no longer active".to_string(),
                )
            })?;
        handoff.failures.insert(PathBuf::from(path), error);
        Ok(())
    }

    fn abort_validation_generation(&mut self, generation: u64) {
        self.active_validation_generations.remove(&generation);
        self.validation_handoffs.remove(&generation);
        if self.accepted_validation_generation == Some(generation) {
            self.accepted_validation_generation = None;
        }
    }

    fn commit_validation_generation(&mut self, generation: u64) {
        self.active_validation_generations.remove(&generation);
        if let Some(previous) = self.accepted_validation_generation.replace(generation)
            && previous != generation
        {
            self.validation_handoffs.remove(&previous);
        }
        let active_generations = &self.active_validation_generations;
        self.validation_handoffs.retain(|candidate, _| {
            *candidate == generation || active_generations.contains(candidate)
        });
    }

    fn claim_validation_handoffs(
        &mut self,
        paths: &HashSet<PathBuf>,
    ) -> Option<CountryMmdbGenerationHandoff> {
        let generation = self.accepted_validation_generation.take()?;
        let matching_generation = self
            .validation_handoffs
            .get(&generation)
            .is_some_and(|handoff| &handoff.expected_paths == paths);
        if !matching_generation {
            self.accepted_validation_generation = Some(generation);
            return None;
        }
        self.validation_handoffs.remove(&generation)
    }
}

/// RAII reservation for one not-yet-published MMDB snapshot buffer. Error
/// paths release the global peak-memory charge automatically; successful
/// publication converts the reservation to a weak-cache entry while holding
/// the same cache lock.
struct CountryMmdbAllocationReservation {
    size_bytes: u64,
    active: bool,
}

impl CountryMmdbAllocationReservation {
    fn reserve(path: &str, size_bytes: u64) -> Result<Self, CountryMmdbLoadError> {
        let mut cache = country_mmdb_snapshot_cache().lock().map_err(|_| {
            CountryMmdbLoadError::Invalid(
                "MaxMind database snapshot cache is unavailable".to_string(),
            )
        })?;
        cache.retain_live();
        cache.reserve_snapshot_allocation(path, size_bytes)?;
        Ok(Self {
            size_bytes,
            active: true,
        })
    }

    fn release_with_cache(&mut self, cache: &mut CountryMmdbCache) {
        if self.active {
            cache.release_snapshot_allocation(self.size_bytes);
            self.active = false;
        }
    }
}

impl Drop for CountryMmdbAllocationReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        match country_mmdb_snapshot_cache().lock() {
            Ok(mut cache) => self.release_with_cache(&mut cache),
            Err(poisoned) => {
                let mut cache = poisoned.into_inner();
                self.release_with_cache(&mut cache);
            }
        }
    }
}

fn country_mmdb_snapshot_cache() -> &'static Mutex<CountryMmdbCache> {
    static CACHE: OnceLock<Mutex<CountryMmdbCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(CountryMmdbCache::default()))
}

fn lock_country_mmdb_cache_recovering_poison(
    cache: &Mutex<CountryMmdbCache>,
) -> std::sync::MutexGuard<'_, CountryMmdbCache> {
    match cache.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// RAII owner for one plugin-file validation generation. The pipeline commits
/// only after every later validation step succeeds; any early return drops the
/// guard and releases every strong MMDB handoff owned by the rejected config.
pub(crate) struct CountryMmdbValidationGeneration {
    id: u64,
    committed: bool,
}

impl CountryMmdbValidationGeneration {
    pub(crate) fn begin(expected_paths: HashSet<PathBuf>) -> Result<Self, String> {
        let mut cache = country_mmdb_snapshot_cache()
            .lock()
            .map_err(|_| "MaxMind database snapshot cache is unavailable".to_string())?;
        cache.next_validation_generation = cache.next_validation_generation.wrapping_add(1);
        if cache.next_validation_generation == 0 {
            cache.next_validation_generation = 1;
        }
        let id = cache.next_validation_generation;
        cache.active_validation_generations.insert(id);
        cache.validation_handoffs.insert(
            id,
            CountryMmdbGenerationHandoff {
                expected_paths,
                snapshots: HashMap::new(),
                failures: HashMap::new(),
                aggregate_budget: CountryMmdbAggregateBudget::default(),
            },
        );
        Ok(Self {
            id,
            committed: false,
        })
    }

    fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn commit(mut self) -> Result<(), String> {
        let mut cache = country_mmdb_snapshot_cache()
            .lock()
            .map_err(|_| "MaxMind database snapshot cache is unavailable".to_string())?;
        cache.commit_validation_generation(self.id);
        self.committed = true;
        Ok(())
    }
}

impl Drop for CountryMmdbValidationGeneration {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let mut cache = lock_country_mmdb_cache_recovering_poison(country_mmdb_snapshot_cache());
        cache.abort_validation_generation(self.id);
    }
}

/// One plugin-cache build's MMDB ownership. The accepted validation generation
/// seeds this per-path map, so every geo instance consumes the exact snapshot
/// that passed dependency validation without another read or record scan.
#[derive(Default)]
struct CountryMmdbLoadSessionState {
    snapshots: HashMap<PathBuf, Arc<CountryMmdbSnapshot>>,
    failures: HashMap<PathBuf, CountryMmdbLoadError>,
    aggregate_budget: CountryMmdbAggregateBudget,
}

pub(crate) struct CountryMmdbLoadSession {
    state: Mutex<CountryMmdbLoadSessionState>,
    refresh_country_mmdb_plugins: bool,
    allow_synchronous_load: bool,
    /// Last-known-good snapshots from the live plugin-cache generation, keyed
    /// by the `db_path` each was loaded from. Only a node-local refresh
    /// populates this: it is the one path where the configuration source (CP)
    /// deliberately skipped node-local validation, so a file that is merely
    /// *temporarily* unavailable on this node must not silently downgrade an
    /// already-enforcing geo instance to its `on_lookup_failure` fallback.
    retained_snapshots: HashMap<PathBuf, Arc<CountryMmdbSnapshot>>,
}

impl Default for CountryMmdbLoadSession {
    fn default() -> Self {
        Self {
            state: Mutex::new(CountryMmdbLoadSessionState::default()),
            refresh_country_mmdb_plugins: false,
            allow_synchronous_load: true,
            retained_snapshots: HashMap::new(),
        }
    }
}

impl CountryMmdbLoadSession {
    pub(crate) fn claim(paths: &HashSet<PathBuf>) -> Result<Self, String> {
        let handoff = {
            let mut cache = country_mmdb_snapshot_cache()
                .lock()
                .map_err(|_| "MaxMind database snapshot cache is unavailable".to_string())?;
            cache.retain_live();
            cache.claim_validation_handoffs(paths)
        };
        let refresh_country_mmdb_plugins = handoff.is_some();
        let state = handoff
            .map(|handoff| CountryMmdbLoadSessionState {
                snapshots: handoff.snapshots,
                failures: handoff.failures,
                aggregate_budget: handoff.aggregate_budget,
            })
            .unwrap_or_default();
        Ok(Self {
            state: Mutex::new(state),
            refresh_country_mmdb_plugins,
            allow_synchronous_load: true,
            retained_snapshots: HashMap::new(),
        })
    }

    /// Claim an off-thread validation handoff for an incremental cache stage.
    /// If cache construction reaches an unvalidated path, fail closed instead
    /// of synchronously opening and scanning an MMDB on the async caller.
    pub(crate) fn claim_preloaded(paths: &HashSet<PathBuf>) -> Result<Self, String> {
        let mut session = Self::claim(paths)?;
        session.allow_synchronous_load = false;
        Ok(session)
    }

    /// Build a load session for a node-local refresh when the configuration
    /// source intentionally skipped file validation (DP full snapshots). Any
    /// matching handoff is still consumed, but its absence must not suppress
    /// the refresh: each path is loaded directly under the same aggregate
    /// budget before the replacement cache generation can publish.
    ///
    /// `retained_snapshots` carries the live generation's already-validated
    /// snapshots keyed by `db_path`. A path that is temporarily unreadable on
    /// this node falls back to its retained snapshot instead of producing a
    /// reader-less instance, so an enforcing geo gate survives a transient file
    /// outage. A *readable but invalid* file still rejects the generation, and
    /// a path with no retained entry — a first load, or a `db_path` the
    /// configuration just repointed — keeps the documented
    /// `on_lookup_failure` fallback.
    pub(crate) fn for_node_local_refresh(
        paths: &HashSet<PathBuf>,
        retained_snapshots: HashMap<PathBuf, Arc<CountryMmdbSnapshot>>,
    ) -> Result<Self, String> {
        let mut session = Self::claim(paths)?;
        session.refresh_country_mmdb_plugins = true;
        session.retained_snapshots = retained_snapshots;
        Ok(session)
    }

    pub(crate) fn refresh_country_mmdb_plugins(&self) -> bool {
        self.refresh_country_mmdb_plugins
    }

    pub(crate) fn load(
        &self,
        path: &str,
    ) -> Result<Arc<CountryMmdbSnapshot>, CountryMmdbLoadError> {
        let path = path.trim();
        let path_key = PathBuf::from(path);
        let mut state = self.state.lock().map_err(|_| {
            CountryMmdbLoadError::Invalid(
                "MaxMind database build-session cache is unavailable".to_string(),
            )
        })?;
        if let Some(snapshot) = state.snapshots.get(&path_key) {
            return Ok(Arc::clone(snapshot));
        }
        if let Some(error) = state.failures.get(&path_key).cloned() {
            return match self.retain_last_known_good(&mut state, &path_key, path, &error) {
                Some(snapshot) => Ok(snapshot),
                None => Err(error),
            };
        }
        if !self.allow_synchronous_load {
            return Err(CountryMmdbLoadError::Invalid(format!(
                "MaxMind database file '{path}' was not preloaded before incremental plugin-cache staging"
            )));
        }

        let loaded = match load_validated_country_mmdb_inner(
            path,
            None,
            Some(&mut state.aggregate_budget),
        ) {
            Ok(loaded) => loaded,
            Err(error) => {
                return match self.retain_last_known_good(&mut state, &path_key, path, &error) {
                    Some(snapshot) => Ok(snapshot),
                    None => Err(error),
                };
            }
        };
        Ok(Arc::clone(
            state.snapshots.entry(path_key).or_insert(loaded),
        ))
    }

    /// Substitute the live generation's snapshot for a path that is
    /// *temporarily unavailable* on this node, memoizing it so every geo
    /// instance sharing the path resolves identically within one build and the
    /// operator warning is emitted at most once per path per refresh.
    ///
    /// Returns `None` — leaving the caller to propagate the original error —
    /// for a `CountryMmdbLoadError::Invalid`, which is a readable but corrupt,
    /// wrong-type, or budget-exceeding database and must still reject the
    /// generation, and for any path with no retained snapshot.
    fn retain_last_known_good(
        &self,
        state: &mut CountryMmdbLoadSessionState,
        path_key: &Path,
        path: &str,
        error: &CountryMmdbLoadError,
    ) -> Option<Arc<CountryMmdbSnapshot>> {
        if !matches!(error, CountryMmdbLoadError::Unavailable(_)) {
            return None;
        }
        let retained = self.retained_snapshots.get(path_key)?;
        tracing::warn!(
            db_path = %path,
            error = %error,
            plugin = "geo_restriction",
            retained_snapshot_bytes = retained.size_bytes(),
            "MaxMind database temporarily unavailable during node-local refresh; retaining the last known good snapshot so geo enforcement is not downgraded to the on_lookup_failure fallback"
        );
        let snapshot = Arc::clone(retained);
        state
            .snapshots
            .insert(path_key.to_path_buf(), Arc::clone(&snapshot));
        Some(snapshot)
    }
}

impl std::fmt::Display for CountryMmdbLoadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(message) | Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

fn is_supported_country_mmdb_type(database_type: &str) -> bool {
    matches!(
        database_type,
        "GeoIP2-Country"
            | "GeoLite2-Country"
            | "GeoIP2-City"
            | "GeoLite2-City"
            | "GeoIP2-Enterprise"
    )
}

fn is_mmdb_country_code(code: &str) -> bool {
    code.len() == 2 && code.bytes().all(|byte| byte.is_ascii_alphabetic())
}

fn is_supported_mmdb_country_code(code: &str) -> bool {
    let bytes = code.as_bytes();
    if bytes.len() != 2 || !bytes.iter().all(u8::is_ascii_alphabetic) {
        return false;
    }
    let normalized = [bytes[0].to_ascii_uppercase(), bytes[1].to_ascii_uppercase()];
    SUPPORTED_GEO_COUNTRY_CODES
        .chunks_exact(2)
        .any(|supported| supported == normalized.as_slice())
}

#[cfg(unix)]
fn open_country_mmdb_path(path: &str) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .read(true)
        // A regular-file path can be replaced with a FIFO/device after the
        // pre-open metadata check. Non-blocking open makes that race safe; the
        // opened-handle file-type/identity checks below still reject it.
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(not(unix))]
fn open_country_mmdb_path(path: &str) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

fn verify_country_mmdb_path_still_matches(
    path: &str,
    opened_version: &CountryMmdbFileVersion,
) -> Result<(), CountryMmdbLoadError> {
    let path_metadata = std::fs::metadata(path).map_err(|error| {
        CountryMmdbLoadError::Invalid(format!(
            "MaxMind database path '{path}' could not be re-statted after loading: {error}"
        ))
    })?;
    let path_version = CountryMmdbFileVersion::from_metadata(path, &path_metadata);
    if !path_metadata.is_file() || &path_version != opened_version {
        return Err(CountryMmdbLoadError::Invalid(format!(
            "MaxMind database path target '{path}' changed while it was being loaded"
        )));
    }
    Ok(())
}

/// Platforms without a stable std file-identity API re-open the configured
/// path and stream its digest without retaining a second snapshot buffer. A
/// metadata-equivalent atomic replacement therefore cannot preserve stale
/// bytes in the candidate generation.
#[cfg(not(unix))]
fn verify_country_mmdb_path_digest(
    path: &str,
    opened_version: &CountryMmdbFileVersion,
    expected_digest: &CountryMmdbDigest,
) -> Result<(), CountryMmdbLoadError> {
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;

    let mut path_file = std::fs::File::open(path).map_err(|error| {
        CountryMmdbLoadError::Invalid(format!(
            "MaxMind database path '{path}' could not be re-opened after loading: {error}"
        ))
    })?;
    let metadata_before = path_file.metadata().map_err(|error| {
        CountryMmdbLoadError::Invalid(format!(
            "MaxMind database path '{path}' metadata not readable during portable identity verification: {error}"
        ))
    })?;
    let path_version_before = CountryMmdbFileVersion::from_metadata(path, &metadata_before);
    if !metadata_before.is_file() || &path_version_before != opened_version {
        return Err(CountryMmdbLoadError::Invalid(format!(
            "MaxMind database path target '{path}' changed before portable identity verification"
        )));
    }

    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    let mut total_bytes = 0_u64;
    {
        let mut bounded_reader = (&mut path_file).take(opened_version.len + 1);
        loop {
            let read = bounded_reader.read(&mut buffer).map_err(|error| {
                CountryMmdbLoadError::Invalid(format!(
                    "MaxMind database path '{path}' not readable during portable identity verification: {error}"
                ))
            })?;
            if read == 0 {
                break;
            }
            total_bytes = total_bytes.checked_add(read as u64).ok_or_else(|| {
                CountryMmdbLoadError::Invalid(format!(
                    "MaxMind database path '{path}' size overflow during portable identity verification"
                ))
            })?;
            if total_bytes > opened_version.len {
                return Err(CountryMmdbLoadError::Invalid(format!(
                    "MaxMind database path target '{path}' grew during portable identity verification"
                )));
            }
            hasher.update(&buffer[..read]);
        }
    }
    if total_bytes != opened_version.len {
        return Err(CountryMmdbLoadError::Invalid(format!(
            "MaxMind database path target '{path}' changed size during portable identity verification"
        )));
    }

    let metadata_after = path_file.metadata().map_err(|error| {
        CountryMmdbLoadError::Invalid(format!(
            "MaxMind database path '{path}' metadata not readable after portable identity verification: {error}"
        ))
    })?;
    let path_version_after = CountryMmdbFileVersion::from_metadata(path, &metadata_after);
    if &path_version_after != opened_version {
        return Err(CountryMmdbLoadError::Invalid(format!(
            "MaxMind database path target '{path}' changed during portable identity verification"
        )));
    }
    verify_country_mmdb_path_still_matches(path, opened_version)?;

    let observed_digest: CountryMmdbDigest = hasher.finalize().into();
    if &observed_digest != expected_digest {
        return Err(CountryMmdbLoadError::Invalid(format!(
            "MaxMind database path target '{path}' was replaced while it was being loaded"
        )));
    }
    Ok(())
}

/// Load and comprehensively validate a MaxMind country-capable database into
/// an owned immutable buffer.
///
/// Owning the bytes keeps live readers independent from external in-place file
/// rewrites and truncation. Verification traverses the complete search tree and
/// data section, while the record scan proves that the advertised product is
/// structurally compatible with the fields used by `geo_restriction`. Every
/// load digests the bounded contents because portable filesystem metadata does
/// not prove content identity. A weak content-addressed cache then skips repeat
/// verification and record enumeration for identical bytes.
pub fn load_validated_country_mmdb(
    path: &str,
) -> Result<Arc<CountryMmdbSnapshot>, CountryMmdbLoadError> {
    load_validated_country_mmdb_inner(path, None, None)
}

fn load_validated_country_mmdb_inner(
    path: &str,
    validation_generation: Option<u64>,
    aggregate_budget: Option<&mut CountryMmdbAggregateBudget>,
) -> Result<Arc<CountryMmdbSnapshot>, CountryMmdbLoadError> {
    use sha2::{Digest as _, Sha256};
    use std::io::{Read as _, Seek as _, SeekFrom};

    // Reject FIFOs, devices, sockets, and directories before opening. On Unix
    // the open itself is also non-blocking so a regular path replaced after
    // this check cannot wedge startup/reload before the opened-handle fstat.
    let path_metadata_before_open = std::fs::metadata(path).map_err(|e| {
        CountryMmdbLoadError::Unavailable(format!(
            "MaxMind database file '{path}' not accessible before open: {e}"
        ))
    })?;
    if !path_metadata_before_open.is_file() {
        return Err(CountryMmdbLoadError::Invalid(format!(
            "'{path}' exists but is not a regular file"
        )));
    }
    let path_version_before_open =
        CountryMmdbFileVersion::from_metadata(path, &path_metadata_before_open);

    let mut file = open_country_mmdb_path(path).map_err(|e| {
        CountryMmdbLoadError::Unavailable(format!(
            "MaxMind database file '{path}' not accessible: {e}"
        ))
    })?;
    let metadata = file.metadata().map_err(|e| {
        CountryMmdbLoadError::Unavailable(format!(
            "MaxMind database file '{path}' metadata not readable: {e}"
        ))
    })?;
    if !metadata.is_file() {
        return Err(CountryMmdbLoadError::Invalid(format!(
            "'{path}' exists but is not a regular file"
        )));
    }
    let file_version = CountryMmdbFileVersion::from_metadata(path, &metadata);
    if file_version != path_version_before_open {
        return Err(CountryMmdbLoadError::Invalid(format!(
            "MaxMind database path target '{path}' changed before it was opened"
        )));
    }

    if metadata.len() > MAX_COUNTRY_MMDB_SIZE_BYTES {
        return Err(CountryMmdbLoadError::Invalid(format!(
            "MaxMind database file '{path}' is {} bytes; maximum supported size is {} bytes",
            metadata.len(),
            MAX_COUNTRY_MMDB_SIZE_BYTES
        )));
    }
    // Stream the content identity before allocating a candidate snapshot. An
    // unchanged reload can then reuse its live content-addressed snapshot with
    // only a fixed-size digest buffer, while changed content must pass the
    // global live + in-flight + candidate peak-memory admission below.
    let mut hasher = Sha256::new();
    let mut digest_buffer = [0_u8; 16 * 1024];
    let mut digested_bytes = 0_u64;
    {
        let mut bounded_reader = (&mut file).take(metadata.len() + 1);
        loop {
            let read = bounded_reader.read(&mut digest_buffer).map_err(|e| {
                CountryMmdbLoadError::Invalid(format!(
                    "MaxMind database file '{path}' could not be hashed consistently: {e}"
                ))
            })?;
            if read == 0 {
                break;
            }
            digested_bytes = digested_bytes.checked_add(read as u64).ok_or_else(|| {
                CountryMmdbLoadError::Invalid(format!(
                    "MaxMind database file '{path}' size overflow while hashing"
                ))
            })?;
            if digested_bytes > metadata.len() {
                return Err(CountryMmdbLoadError::Invalid(format!(
                    "MaxMind database file '{path}' grew while it was being hashed"
                )));
            }
            hasher.update(&digest_buffer[..read]);
        }
    }
    if digested_bytes != metadata.len() {
        return Err(CountryMmdbLoadError::Invalid(format!(
            "MaxMind database file '{path}' changed size while it was being hashed"
        )));
    }
    let metadata_after_digest = file.metadata().map_err(|e| {
        CountryMmdbLoadError::Invalid(format!(
            "MaxMind database file '{path}' metadata not readable after hashing: {e}"
        ))
    })?;
    if CountryMmdbFileVersion::from_metadata(path, &metadata_after_digest) != file_version {
        return Err(CountryMmdbLoadError::Invalid(format!(
            "MaxMind database file '{path}' changed while it was being hashed"
        )));
    }
    verify_country_mmdb_path_still_matches(path, &file_version)?;

    let digest: CountryMmdbDigest = hasher.finalize().into();
    #[cfg(not(unix))]
    verify_country_mmdb_path_digest(path, &file_version, &digest)?;
    // Charge the same content identity used by the snapshot cache. This runs
    // after a bounded, fixed-buffer digest and before any candidate Vec
    // allocation, so equivalent path spellings deduplicate without weakening
    // the aggregate memory gate or introducing path-canonicalization TOCTOU.
    if let Some(aggregate_budget) = aggregate_budget {
        aggregate_budget.admit(path, digest, metadata.len())?;
    } else if let Some(generation) = validation_generation {
        let mut cache = country_mmdb_snapshot_cache().lock().map_err(|_| {
            CountryMmdbLoadError::Invalid(
                "MaxMind database snapshot cache is unavailable".to_string(),
            )
        })?;
        cache.admit_validation_snapshot(generation, path, digest, metadata.len())?;
    }
    {
        let mut cache = country_mmdb_snapshot_cache().lock().map_err(|_| {
            CountryMmdbLoadError::Invalid(
                "MaxMind database snapshot cache is unavailable".to_string(),
            )
        })?;
        cache.retain_live();
        if let Some(reader) = cache.get_by_digest(&digest) {
            return Ok(cache.prepare_snapshot_return(path, reader, validation_generation));
        }
    }

    let mut allocation_reservation =
        CountryMmdbAllocationReservation::reserve(path, metadata.len())?;
    let initial_capacity = usize::try_from(metadata.len()).map_err(|_| {
        CountryMmdbLoadError::Invalid(format!(
            "MaxMind database file '{path}' is too large for this platform"
        ))
    })?;
    file.seek(SeekFrom::Start(0)).map_err(|e| {
        CountryMmdbLoadError::Invalid(format!(
            "MaxMind database file '{path}' could not be rewound after hashing: {e}"
        ))
    })?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(initial_capacity).map_err(|e| {
        CountryMmdbLoadError::Invalid(format!(
            "MaxMind database file '{path}' cannot reserve its bounded snapshot buffer: {e}"
        ))
    })?;
    {
        let mut bounded_reader = (&mut file).take(metadata.len() + 1);
        bounded_reader.read_to_end(&mut bytes).map_err(|e| {
            CountryMmdbLoadError::Invalid(format!(
                "MaxMind database file '{path}' could not be read consistently: {e}"
            ))
        })?;
    }
    if bytes.len() as u64 != metadata.len() {
        return Err(CountryMmdbLoadError::Invalid(format!(
            "MaxMind database file '{path}' changed size while it was being loaded"
        )));
    }
    let metadata_after_read = file.metadata().map_err(|e| {
        CountryMmdbLoadError::Invalid(format!(
            "MaxMind database file '{path}' metadata not readable after load: {e}"
        ))
    })?;
    if CountryMmdbFileVersion::from_metadata(path, &metadata_after_read) != file_version {
        return Err(CountryMmdbLoadError::Invalid(format!(
            "MaxMind database file '{path}' changed while it was being loaded"
        )));
    }
    verify_country_mmdb_path_still_matches(path, &file_version)?;

    let loaded_digest: CountryMmdbDigest = Sha256::digest(&bytes).into();
    if loaded_digest != digest {
        return Err(CountryMmdbLoadError::Invalid(format!(
            "MaxMind database file '{path}' changed between identity and snapshot reads"
        )));
    }
    #[cfg(not(unix))]
    verify_country_mmdb_path_digest(path, &file_version, &digest)?;

    let reader = maxminddb::Reader::from_source(bytes).map_err(|e| {
        CountryMmdbLoadError::Invalid(format!(
            "MaxMind database file '{path}' is not a valid readable .mmdb: {e}"
        ))
    })?;

    reader.verify().map_err(|e| {
        CountryMmdbLoadError::Invalid(format!(
            "MaxMind database file '{path}' failed comprehensive verification: {e}"
        ))
    })?;

    if !is_supported_country_mmdb_type(&reader.metadata.database_type) {
        return Err(CountryMmdbLoadError::Invalid(format!(
            "MaxMind database file '{path}' has unsupported database type '{}'; expected a GeoIP2/GeoLite2 Country or City database, or GeoIP2 Enterprise",
            reader.metadata.database_type
        )));
    }

    let mut found_country_code = false;
    let networks = reader.networks(Default::default()).map_err(|e| {
        CountryMmdbLoadError::Invalid(format!(
            "MaxMind database file '{path}' cannot enumerate country records: {e}"
        ))
    })?;
    for network in networks {
        let lookup = network.map_err(|e| {
            CountryMmdbLoadError::Invalid(format!(
                "MaxMind database file '{path}' contains an invalid network record: {e}"
            ))
        })?;
        let country: Option<&str> = lookup
            .decode_path(&maxminddb::path!["country", "iso_code"])
            .map_err(|e| {
                CountryMmdbLoadError::Invalid(format!(
                    "MaxMind database file '{path}' has an incompatible country record: {e}"
                ))
            })?;
        let registered_country: Option<&str> = lookup
            .decode_path(&maxminddb::path!["registered_country", "iso_code"])
            .map_err(|e| {
                CountryMmdbLoadError::Invalid(format!(
                    "MaxMind database file '{path}' has an incompatible registered-country record: {e}"
                ))
            })?;

        for code in [country, registered_country].into_iter().flatten() {
            if !is_mmdb_country_code(code) {
                return Err(CountryMmdbLoadError::Invalid(format!(
                    "MaxMind database file '{path}' contains an invalid country code {code:?}"
                )));
            }
            if !is_supported_mmdb_country_code(code) {
                return Err(CountryMmdbLoadError::Invalid(format!(
                    "MaxMind database file '{path}' contains unsupported country code {code:?}"
                )));
            }
            found_country_code = true;
        }
    }

    if !found_country_code {
        return Err(CountryMmdbLoadError::Invalid(format!(
            "MaxMind database file '{path}' contains no country or registered-country ISO codes"
        )));
    }

    let reader = Arc::new(CountryMmdbSnapshot {
        reader,
        size_bytes: metadata.len(),
    });
    let mut cache = country_mmdb_snapshot_cache().lock().map_err(|_| {
        CountryMmdbLoadError::Invalid("MaxMind database snapshot cache is unavailable".to_string())
    })?;
    cache.retain_live();
    if let Some(cached) = cache.get_by_digest(&digest) {
        // The concurrently published snapshot wins. Drop our duplicate owned
        // buffer before releasing its reservation so another loader cannot
        // admit against bytes that are still physically retained.
        drop(reader);
        allocation_reservation.release_with_cache(&mut cache);
        return Ok(cache.prepare_snapshot_return(path, cached, validation_generation));
    }
    cache.by_digest.insert(digest, Arc::downgrade(&reader));
    allocation_reservation.release_with_cache(&mut cache);
    Ok(cache.prepare_snapshot_return(path, reader, validation_generation))
}

/// Validate that a MaxMind `.mmdb` database file exists, is fully intact, and
/// contains a supported country record shape. Per-mode callers decide whether
/// a failure is fatal (file mode) or a warning/fallback (database mode). CP
/// skips node-local files; DP invokes the same validation during node-local
/// plugin refresh and rejects readable invalid candidates.
pub fn validate_mmdb_file(field_name: &str, path: &str) -> Result<(), String> {
    load_validated_country_mmdb(path)
        .map(|_| ())
        .map_err(|error| format!("{field_name}: {error}"))
}

fn validate_mmdb_file_for_generation(
    field_name: &str,
    path: &str,
    generation: &CountryMmdbValidationGeneration,
) -> Result<(), String> {
    match load_validated_country_mmdb_inner(path, Some(generation.id()), None) {
        Ok(_) => Ok(()),
        Err(error) => {
            let mut cache = country_mmdb_snapshot_cache()
                .lock()
                .map_err(|_| "MaxMind database snapshot cache is unavailable".to_string())?;
            cache
                .record_validation_failure(generation.id(), path, error.clone())
                .map_err(|record_error| record_error.to_string())?;
            Err(format!("{field_name}: {error}"))
        }
    }
}

/// Shared FileDescriptorSet load used by mode-aware plugin file-dependency
/// validation. Distinguishes absent/unreadable from present-but-invalid so
/// each plugin family can emit its own redacted diagnostic while the bytes
/// are still read and decoded only once per path.
#[derive(Clone, Copy)]
enum SharedProtobufDescriptorLoadError {
    Unavailable,
    Invalid,
}

impl SharedProtobufDescriptorLoadError {
    fn body_validator_message(self) -> &'static str {
        match self {
            Self::Unavailable => "body_validator: failed to read protobuf descriptor file",
            Self::Invalid => "body_validator: failed to parse protobuf descriptor",
        }
    }

    fn ai_response_guard_message(self) -> &'static str {
        match self {
            Self::Unavailable => "ai_response_guard: failed to read protobuf descriptor file",
            Self::Invalid => "ai_response_guard: failed to parse protobuf descriptor",
        }
    }
}

fn load_shared_protobuf_descriptor_pool(
    path: &str,
) -> Result<prost_reflect::DescriptorPool, SharedProtobufDescriptorLoadError> {
    let bytes = std::fs::read(path).map_err(|_| SharedProtobufDescriptorLoadError::Unavailable)?;
    prost_reflect::DescriptorPool::decode(bytes.as_slice())
        .map_err(|_| SharedProtobufDescriptorLoadError::Invalid)
}

// Testing-policy exception: peak-budget, digest-identity, and poisoned-lock
// bookkeeping is private by design and cannot be exercised externally without
// widening the runtime API. Public MMDB behavior remains covered externally.
#[cfg(test)]
mod country_mmdb_admission_tests {
    use super::*;

    #[test]
    fn aggregate_budget_rejects_before_exceeding_the_generation_limit() {
        let mut budget = CountryMmdbAggregateBudget::default();
        budget
            .admit(
                "first.mmdb",
                [1; 32],
                MAX_COUNTRY_MMDB_AGGREGATE_SIZE_BYTES - 1,
            )
            .expect("the first snapshot fits");

        let error = budget
            .admit("second.mmdb", [2; 32], 2)
            .expect_err("the aggregate must reject before retaining a second snapshot");
        assert!(
            error
                .to_string()
                .contains("aggregate snapshot budget exceeded")
        );
        assert_eq!(
            budget.admitted_bytes,
            MAX_COUNTRY_MMDB_AGGREGATE_SIZE_BYTES - 1
        );
        assert!(!budget.admitted_snapshots.contains_key(&[2; 32]));
    }

    #[test]
    fn aggregate_budget_deduplicates_equivalent_path_spellings_by_digest() {
        let mut budget = CountryMmdbAggregateBudget::default();
        let snapshot_size = (MAX_COUNTRY_MMDB_AGGREGATE_SIZE_BYTES / 2) + 1;
        budget
            .admit("country.mmdb", [1; 32], snapshot_size)
            .expect("the first snapshot fits");
        budget
            .admit("./country.mmdb", [1; 32], snapshot_size)
            .expect("the same content must not be charged twice");

        assert_eq!(budget.admitted_bytes, snapshot_size);
        assert_eq!(budget.admitted_snapshots.len(), 1);
        assert!(budget.admit("other.mmdb", [2; 32], snapshot_size).is_err());
    }

    #[test]
    fn peak_budget_diagnoses_large_live_snapshot_as_restart_required() {
        let snapshot_size = (MAX_COUNTRY_MMDB_AGGREGATE_SIZE_BYTES / 2) + 1;
        let error =
            validate_country_mmdb_snapshot_peak("country.mmdb", snapshot_size, 0, snapshot_size)
                .expect_err("two overlapping large snapshots exceed the peak bound");

        assert!(error.to_string().contains("requires a gateway restart"));
    }

    #[test]
    fn poisoned_cache_lock_is_recovered_for_generation_cleanup() {
        let cache = Mutex::new(CountryMmdbCache::default());
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut guard = cache.lock().expect("cache lock");
            guard.active_validation_generations.insert(7);
            panic!("poison the private cache lock");
        }));
        assert!(panic.is_err());

        let mut guard = lock_country_mmdb_cache_recovering_poison(&cache);
        guard.abort_validation_generation(7);
        assert!(!guard.active_validation_generations.contains(&7));
    }

    #[cfg(unix)]
    #[test]
    fn path_restat_rejects_an_atomic_replacement_of_the_opened_file() {
        let directory = tempfile::TempDir::new().expect("temporary directory");
        let path = directory.path().join("country.mmdb");
        let replacement = directory.path().join("replacement.mmdb");
        std::fs::write(&path, b"opened snapshot").expect("write original");
        std::fs::write(&replacement, b"new path target").expect("write replacement");

        let opened_file = std::fs::File::open(&path).expect("open original path target");
        let path_text = path.to_str().expect("temporary path is UTF-8");
        let opened_version = CountryMmdbFileVersion::from_metadata(
            path_text,
            &opened_file.metadata().expect("opened metadata"),
        );
        std::fs::rename(&replacement, &path).expect("atomically replace configured path");

        let error = verify_country_mmdb_path_still_matches(path_text, &opened_version)
            .expect_err("the configured path must still target the opened inode");
        assert!(error.to_string().contains("path target"));
    }
}

/// Validate a u64 field is within a range.
fn validate_u64_range(field_name: &str, value: u64, min: u64, max: u64) -> Result<(), String> {
    if value < min || value > max {
        return Err(format!(
            "{} must be between {} and {} (got {})",
            field_name, min, max, value
        ));
    }
    Ok(())
}

/// Validate a u32 field is within a range.
fn validate_u32_range(field_name: &str, value: u32, min: u32, max: u32) -> Result<(), String> {
    if value < min || value > max {
        return Err(format!(
            "{} must be between {} and {} (got {})",
            field_name, min, max, value
        ));
    }
    Ok(())
}

/// Validate a list of HTTP status codes.
fn validate_status_codes(field_name: &str, codes: &[u16]) -> Result<(), String> {
    if codes.len() > MAX_STATUS_CODES {
        return Err(format!(
            "{} must not have more than {} entries (got {})",
            field_name,
            MAX_STATUS_CODES,
            codes.len()
        ));
    }
    for &code in codes {
        if !(100..=599).contains(&code) {
            return Err(format!(
                "{} contains invalid HTTP status code {} (must be 100-599)",
                field_name, code
            ));
        }
    }
    Ok(())
}

impl Proxy {
    /// Resolve the pre-computed dispatch classification and canonicalize the
    /// stored backend scheme when HTTP-family defaults apply.
    fn resolve_dispatch_kind_fields(&mut self) {
        let scheme = self.effective_scheme();
        self.dispatch_kind = DispatchKind::from(scheme);
        // Canonicalize the stored field for HTTP-family proxies so logging,
        // pool keys, and incremental serialization read a concrete scheme.
        // Stream proxies without an explicit scheme are deliberately left
        // as `None` so validation can emit a clear "missing scheme" error.
        if self.backend_scheme.is_none() && !self.dispatch_kind.is_stream() {
            self.backend_scheme = Some(scheme);
        }
    }

    /// Effective WebSocket relay idle timeout in seconds for this proxy: the
    /// per-proxy override when set, otherwise the global default
    /// (`FERRUM_WEBSOCKET_IDLE_TIMEOUT_SECONDS`). `0` means disabled. Mirrors the
    /// `tcp_idle_timeout_seconds.unwrap_or(global)` resolution used by the TCP relay.
    #[inline]
    pub fn effective_websocket_idle_timeout_seconds(&self, global_default: u64) -> u64 {
        self.websocket_idle_timeout_seconds
            .unwrap_or(global_default)
    }

    /// Whether the reqwest-backed HTTP backend client for this (effective)
    /// proxy must be restricted to HTTP/1.1 on the wire — i.e. the
    /// DestinationRule `connectionPool.http.h2UpgradePolicy` resolved to
    /// `DO_NOT_UPGRADE`.
    ///
    /// `DoNotUpgrade` first makes the dispatch fork skip the direct-H2 pool
    /// (`should_dispatch_direct_h2`), routing the request through the reqwest
    /// pool. But for a TLS backend that advertises h2, the reqwest client must
    /// ALSO not ALPN-negotiate h2, or `DO_NOT_UPGRADE` would not actually
    /// prevent HTTP/2. So the reqwest client built for such a dial restricts
    /// its rustls ALPN to `http/1.1` (and additionally sets reqwest's
    /// `http1_only()` preference). Because that produces a DIFFERENT client
    /// from the default (h2-capable) one, this discriminator is part of the
    /// reqwest pool key — a protocol/ALPN distinction (legitimate pool-key
    /// content per `.claude/rules/proxy-protocols.md`), NOT a policy field.
    ///
    /// `Default` / `Upgrade` / absent all return `false` (probe-driven; the
    /// h2c-plaintext case is already H1-only via reqwest's lack of h2c).
    pub fn forces_backend_http1_only(&self) -> bool {
        matches!(self.h2_upgrade_policy, Some(H2UpgradePolicy::DoNotUpgrade))
    }

    /// Normalize proxy fields to their canonical in-memory form.
    ///
    /// Also populates `dispatch_kind` from `backend_scheme` so per-proxy call
    /// sites (admin CRUD validation, incremental config apply, single-row DB
    /// reads) get a correct dispatch classification without depending on the
    /// `GatewayConfig::resolve_dispatch_kind` batch pass.
    pub fn normalize_fields(&mut self) {
        for host in &mut self.hosts {
            *host = host.to_lowercase();
        }
        // RFC 1035: DNS names are case-insensitive. Normalize backend_host so
        // downstream consumers (DNS cache, connection pool keys) never create
        // duplicate entries for mixed-case variants of the same hostname.
        self.backend_host = self.backend_host.to_ascii_lowercase();

        self.resolve_dispatch_kind_fields();
    }

    /// Human-readable scheme for error messages. Returns `"<unset>"` before
    /// normalization has resolved the default, so errors point operators at
    /// the missing field without pretending a value exists.
    pub fn scheme_display(&self) -> &'static str {
        match self.backend_scheme {
            Some(s) => s.to_scheme_str(),
            None => "<unset>",
        }
    }

    /// Effective wire scheme — returns the operator-set scheme, or the
    /// normalization default (`Https` for HTTP family, `Tcp` sentinel for
    /// stream family when missing — validation will reject the latter).
    ///
    /// Called by `GatewayConfig::resolve_dispatch_kind()`; also usable by
    /// admin API preview logic that needs the effective scheme before the
    /// full normalize pass has run.
    #[inline]
    pub fn effective_scheme(&self) -> BackendScheme {
        self.backend_scheme.unwrap_or_else(|| {
            if self.listen_port.is_some() {
                // Sentinel — validation rejects stream proxies that omit
                // the scheme, so this value is never actually dispatched on.
                BackendScheme::Tcp
            } else {
                BackendScheme::Https
            }
        })
    }
}

impl Proxy {
    /// Screen this proxy's literal-IP backend fields (`backend_host`,
    /// `dns_override`) against the backend egress policy. Hostnames are not
    /// resolvable at config time and are screened at DNS-resolution time
    /// instead. Returns prefix-free messages so each caller can attribute them.
    pub fn validate_backend_egress_ips(
        &self,
        backend_allow_ips: &crate::config::BackendEgressPolicy,
    ) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        // Stream (`tcp`/`udp`/`dtls`) backends resolve through `DnsCache::resolve`
        // (canonical literals only; everything else is real DNS, then the
        // resolved address is policy-screened), so a numeric host is a DNS name —
        // screen them with `stream_literal_ip`. HTTP-family backends are dialed
        // through `url`/reqwest, which canonicalizes non-canonical IPv4 spellings
        // into literals that skip the resolver — screen those with
        // `egress_literal_ip`.
        let parse_literal = |host: &str| {
            if self.effective_scheme().is_stream() {
                stream_literal_ip(host)
            } else {
                egress_literal_ip(host)
            }
        };
        if let Some(ip) = parse_literal(&self.backend_host)
            && let Some(reason) = backend_allow_ips.deny_reason(&ip)
        {
            errors.push(format!(
                "backend_host IP {ip} denied by backend egress policy: {reason}"
            ));
        }
        if let Some(ref dns_override) = self.dns_override
            && let Some(ip) = parse_literal(dns_override)
            && let Some(reason) = backend_allow_ips.deny_reason(&ip)
        {
            errors.push(format!(
                "dns_override IP {ip} denied by backend egress policy: {reason}"
            ));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate all fields of a proxy for correctness and safe lengths.
    ///
    /// This validates field values only — uniqueness checks (listen_path conflicts,
    /// name uniqueness, upstream_id existence) are done separately in the admin handlers.
    pub fn validate_fields(&self) -> Result<(), Vec<String>> {
        self.validate_fields_inner(None, crate::tls::DEFAULT_CERT_EXPIRY_WARNING_DAYS)
    }

    /// Validate fields with a shared cache of already-validated TLS file paths.
    /// When multiple proxies reference the same cert/key/CA file, each path is
    /// opened and parsed only once — subsequent proxies skip the I/O.
    pub fn validate_fields_with_cache(
        &self,
        validated_tls_paths: &mut std::collections::HashSet<String>,
        cert_expiry_warning_days: u64,
    ) -> Result<(), Vec<String>> {
        self.validate_fields_inner(Some(validated_tls_paths), cert_expiry_warning_days)
    }

    fn validate_fields_inner(
        &self,
        mut validated_tls_paths: Option<&mut std::collections::HashSet<String>>,
        cert_expiry_warning_days: u64,
    ) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        // `validate_fields_inner` runs on a serde-deserialized Proxy BEFORE
        // `normalize_fields()` populates `dispatch_kind` (file_loader's
        // pipeline orders field validation first, normalization second).
        // Use `effective_scheme()` to apply the same Https-default-for-HTTP
        // rule at validation time without depending on dispatch_kind.
        let effective_scheme = self.effective_scheme();
        let is_stream_proxy = effective_scheme.is_stream();

        // Inbound PROXY protocol is TCP-borne: valid only on tcp/tcps stream
        // proxies. Enforced here (single-proxy admin writes: POST/PUT
        // /proxies and the API-spec proxy path) in addition to
        // `GatewayConfig::validate_stream_proxies`, so a bad row can never
        // persist and then wedge the next full-config load/reconcile.
        if self.stream_proxy_protocol == Some(true)
            && !matches!(effective_scheme, BackendScheme::Tcp | BackendScheme::Tcps)
        {
            errors.push(
                "stream_proxy_protocol is only valid for tcp/tcps stream proxies                  (PROXY protocol is TCP-borne)"
                    .to_string(),
            );
        }

        // Passthrough mode validation
        if self.passthrough {
            if !is_stream_proxy {
                errors.push(
                    "passthrough is only supported for stream proxies (tcp, tcps, udp, dtls)"
                        .to_string(),
                );
            }
            if self.frontend_tls {
                errors.push(
                    "passthrough and frontend_tls are mutually exclusive — passthrough forwards raw encrypted bytes without terminating TLS/DTLS".to_string(),
                );
            }
        }

        // Name
        if let Some(ref name) = self.name
            && let Err(e) = validate_string_field("name", name, MAX_NAME_LENGTH)
        {
            errors.push(e);
        }

        // Hosts
        if self.hosts.len() > MAX_HOSTS_PER_PROXY {
            errors.push(format!(
                "hosts must not have more than {} entries (got {})",
                MAX_HOSTS_PER_PROXY,
                self.hosts.len()
            ));
        }
        for host in &self.hosts {
            if host.len() > MAX_HOST_LENGTH {
                errors.push(format!(
                    "host entry '{}...' must not exceed {} characters",
                    host.chars().take(40).collect::<String>(),
                    MAX_HOST_LENGTH
                ));
            }
        }

        // listen_path
        //
        // Contract:
        // - Stream proxies MUST have `listen_path.is_none()`.
        // - HTTP-family proxies require `hosts.is_non_empty() || listen_path.is_some()`.
        // - `listen_path == Some("")` is invalid input (rejected here rather than
        //   silently normalized to None) — catches mis-written fixtures loudly.
        if is_stream_proxy {
            if self.listen_path.is_some() {
                errors.push(format!(
                    "Stream proxy '{}' (scheme {}) must not set listen_path — stream proxies route on listen_port",
                    self.id,
                    self.scheme_display()
                ));
            }
        } else {
            match self.listen_path.as_deref() {
                None => {
                    if self.hosts.is_empty() {
                        errors.push(
                            "HTTP proxy requires at least one of `hosts` or `listen_path` — a proxy with neither is a catch-all for every request and collides with every other catch-all".to_string(),
                        );
                    }
                }
                Some(path) => {
                    if path.len() > MAX_LISTEN_PATH_LENGTH {
                        errors.push(format!(
                            "listen_path must not exceed {} characters (got {})",
                            MAX_LISTEN_PATH_LENGTH,
                            path.len()
                        ));
                    }
                    if contains_control_chars(path) {
                        errors.push("listen_path must not contain control characters".to_string());
                    }
                    if path.is_empty() {
                        errors.push(
                            "listen_path must not be an empty string — omit the field entirely for host-only routing"
                                .to_string(),
                        );
                    } else if let Some(pattern) = path.strip_prefix('~') {
                        if pattern.is_empty() {
                            errors.push("regex listen_path '~' has empty pattern".to_string());
                        }
                    } else if let Some(exact) = path.strip_prefix('=') {
                        if !exact.starts_with('/') {
                            errors.push(
                                "exact listen_path must start with '=/' (for example, '=/api')"
                                    .to_string(),
                            );
                        }
                    } else if !path.starts_with('/') {
                        errors.push(
                            "listen_path must start with '/', '~' (regex), or '=/' (exact)"
                                .to_string(),
                        );
                    }
                    if let Some(reason) = non_canonical_listen_path_reason(path) {
                        errors.push(format!(
                            "listen_path must already be a canonical policy path ({reason}); \
                             request paths are canonicalized before route lookup, so a \
                             non-canonical listen_path is unreachable and creates a routing/auth bypass"
                        ));
                    }
                }
            }
        }

        // backend_host
        if let Err(e) =
            validate_string_field("backend_host", &self.backend_host, MAX_BACKEND_HOST_LENGTH)
        {
            errors.push(e);
        }
        if self.backend_host.contains("://") {
            errors.push("backend_host must not contain a scheme (e.g., 'http://')".to_string());
        }
        if self.upstream_id.is_none() && self.backend_host.is_empty() {
            errors.push("backend_host must be non-empty (or set upstream_id)".to_string());
        }
        if self.upstream_id.is_none() && self.backend_port == 0 {
            errors.push("backend_port must be greater than 0 (or set upstream_id)".to_string());
        }

        // backend_path
        if let Some(ref path) = self.backend_path
            && let Err(e) = validate_string_field("backend_path", path, MAX_BACKEND_PATH_LENGTH)
        {
            errors.push(e);
        }

        // Timeout ranges
        if let Err(e) = validate_u64_range(
            "backend_connect_timeout_ms",
            self.backend_connect_timeout_ms,
            1,
            MAX_TIMEOUT_MS,
        ) {
            errors.push(e);
        }
        if let Err(e) = validate_u64_range(
            "backend_read_timeout_ms",
            self.backend_read_timeout_ms,
            0,
            MAX_TIMEOUT_MS,
        ) {
            errors.push(e);
        }
        if let Err(e) = validate_u64_range(
            "backend_write_timeout_ms",
            self.backend_write_timeout_ms,
            0,
            MAX_TIMEOUT_MS,
        ) {
            errors.push(e);
        }

        // Pool timeout overrides
        if let Some(v) = self.pool_idle_timeout_seconds
            && let Err(e) =
                validate_u64_range("pool_idle_timeout_seconds", v, 1, MAX_POOL_IDLE_TIMEOUT)
        {
            errors.push(e);
        }
        if let Some(v) = self.pool_tcp_keepalive_seconds
            && let Err(e) =
                validate_u64_range("pool_tcp_keepalive_seconds", v, 1, MAX_TIMEOUT_SECONDS)
        {
            errors.push(e);
        }
        if let Some(v) = self.pool_http2_keep_alive_interval_seconds
            && let Err(e) = validate_u64_range(
                "pool_http2_keep_alive_interval_seconds",
                v,
                1,
                MAX_TIMEOUT_SECONDS,
            )
        {
            errors.push(e);
        }
        if let Some(v) = self.pool_http2_keep_alive_timeout_seconds
            && let Err(e) = validate_u64_range(
                "pool_http2_keep_alive_timeout_seconds",
                v,
                1,
                MAX_TIMEOUT_SECONDS,
            )
        {
            errors.push(e);
        }

        // DNS cache TTL
        if let Some(v) = self.dns_cache_ttl_seconds
            && let Err(e) = validate_u64_range("dns_cache_ttl_seconds", v, 1, MAX_DNS_CACHE_TTL)
        {
            errors.push(e);
        }

        // UDP idle timeout
        if let Err(e) = validate_u64_range(
            "udp_idle_timeout_seconds",
            self.udp_idle_timeout_seconds,
            1,
            MAX_UDP_IDLE_TIMEOUT,
        ) {
            errors.push(e);
        }

        // TCP idle timeout (0 means disabled, so only reject values above the max)
        if let Some(v) = self.tcp_idle_timeout_seconds
            && v > MAX_TCP_IDLE_TIMEOUT
        {
            errors.push(format!(
                "tcp_idle_timeout_seconds must be between 0 and {} (got {})",
                MAX_TCP_IDLE_TIMEOUT, v
            ));
        }

        // WebSocket idle timeout (0 means disabled, so only reject values above the max)
        if let Some(v) = self.websocket_idle_timeout_seconds
            && v > MAX_WEBSOCKET_IDLE_TIMEOUT
        {
            errors.push(format!(
                "websocket_idle_timeout_seconds must be between 0 and {} (got {})",
                MAX_WEBSOCKET_IDLE_TIMEOUT, v
            ));
        }

        // HTTP/2 flow control validation
        if let Some(v) = self.pool_http2_initial_stream_window_size
            && !(MIN_HTTP2_WINDOW_SIZE..=MAX_HTTP2_WINDOW_SIZE).contains(&v)
        {
            errors.push(format!(
                "pool_http2_initial_stream_window_size must be between {} and {} (got {})",
                MIN_HTTP2_WINDOW_SIZE, MAX_HTTP2_WINDOW_SIZE, v
            ));
        }
        if let Some(v) = self.pool_http2_initial_connection_window_size
            && !(MIN_HTTP2_WINDOW_SIZE..=MAX_HTTP2_WINDOW_SIZE).contains(&v)
        {
            errors.push(format!(
                "pool_http2_initial_connection_window_size must be between {} and {} (got {})",
                MIN_HTTP2_WINDOW_SIZE, MAX_HTTP2_WINDOW_SIZE, v
            ));
        }
        if let Some(v) = self.pool_http2_max_frame_size
            && !(MIN_HTTP2_MAX_FRAME_SIZE..=MAX_HTTP2_MAX_FRAME_SIZE).contains(&v)
        {
            errors.push(format!(
                "pool_http2_max_frame_size must be between {} and {} (got {})",
                MIN_HTTP2_MAX_FRAME_SIZE, MAX_HTTP2_MAX_FRAME_SIZE, v
            ));
        }
        if let Some(v) = self.pool_http2_max_concurrent_streams
            && (v == 0 || u64::from(v) > MAX_POOL_SQL_INTEGER_VALUE)
        {
            errors.push(format!(
                "pool_http2_max_concurrent_streams must be between 1 and {} (got {})",
                MAX_POOL_SQL_INTEGER_VALUE, v
            ));
        }
        if let Some(v) = self.pool_max_requests_per_connection
            && v > MAX_POOL_SQL_INTEGER_VALUE
        {
            errors.push(format!(
                "pool_max_requests_per_connection must be between 0 and {} (got {})",
                MAX_POOL_SQL_INTEGER_VALUE, v
            ));
        }

        // HTTP/3 connections per backend
        if let Some(v) = self.pool_http3_connections_per_backend
            && (v == 0 || v > MAX_HTTP3_CONNECTIONS_PER_BACKEND)
        {
            errors.push(format!(
                "pool_http3_connections_per_backend must be between 1 and {} (got {})",
                MAX_HTTP3_CONNECTIONS_PER_BACKEND, v
            ));
        }

        // upstream_subset requires upstream_id
        if self.upstream_subset.is_some() && self.upstream_id.is_none() {
            errors.push(
                "upstream_subset requires upstream_id — subset routing only applies to upstream-backed proxies"
                    .to_string(),
            );
        }
        if self.upstream_subset.is_some() && effective_scheme.is_udp() {
            errors.push(
                "upstream_subset is not supported for udp/dtls proxies until UDP subset routing is implemented"
                    .to_string(),
            );
        }
        if let Some(ref subset) = self.upstream_subset
            && let Err(e) = validate_string_field("upstream_subset", subset, MAX_SUBSET_NAME_LENGTH)
        {
            errors.push(e);
        }

        // Reject backend TLS fields on non-TLS schemes — cert configs are
        // meaningless for plaintext backends and would waste disk I/O and
        // fragment the connection pool.
        //
        // Uses `effective_scheme()` rather than `dispatch_kind` because the
        // validation pipeline may run this check BEFORE `normalize_fields()`
        // populates `dispatch_kind` (file_loader runs field validation first,
        // then normalization). `effective_scheme()` applies the same
        // Https-default-for-HTTP-family rule at validation time.
        let effective = effective_scheme;
        if !effective.is_tls_backend() {
            let scheme = self.scheme_display();
            if self.backend_tls_client_cert_path.is_some() {
                errors.push(format!(
                    "backend_tls_client_cert_path cannot be set when backend_scheme is '{scheme}' — TLS client certs are only used with TLS-enabled schemes (https, tcps, dtls)"
                ));
            }
            if self.backend_tls_client_key_path.is_some() {
                errors.push(format!(
                    "backend_tls_client_key_path cannot be set when backend_scheme is '{scheme}' — TLS client keys are only used with TLS-enabled schemes (https, tcps, dtls)"
                ));
            }
            if self.backend_tls_server_ca_cert_path.is_some() {
                errors.push(format!(
                    "backend_tls_server_ca_cert_path cannot be set when backend_scheme is '{scheme}' — CA certs are only used with TLS-enabled schemes (https, tcps, dtls)"
                ));
            }
            if !self.backend_tls_verify_server_cert {
                errors.push(format!(
                    "backend_tls_verify_server_cert cannot be set to false when backend_scheme is '{scheme}' — there is no TLS to verify on plaintext schemes"
                ));
            }
        }

        // Stream proxies must declare an explicit scheme (no HTTP default).
        if self.listen_port.is_some() && self.backend_scheme.is_none() {
            errors.push(format!(
                "Stream proxy '{}' must set backend_scheme explicitly (tcp, tcps, udp, dtls) — no default is applied to stream proxies",
                self.id
            ));
        }

        // Reject backend TLS fields in passthrough mode — the proxy does not
        // originate its own TLS to the backend; the client's encrypted stream
        // passes through directly.
        if self.passthrough {
            if self.backend_tls_client_cert_path.is_some() {
                errors.push(
                    "backend_tls_client_cert_path cannot be set when passthrough is true — the proxy does not originate backend TLS in passthrough mode".to_string(),
                );
            }
            if self.backend_tls_client_key_path.is_some() {
                errors.push(
                    "backend_tls_client_key_path cannot be set when passthrough is true — the proxy does not originate backend TLS in passthrough mode".to_string(),
                );
            }
            if self.backend_tls_server_ca_cert_path.is_some() {
                errors.push(
                    "backend_tls_server_ca_cert_path cannot be set when passthrough is true — the proxy does not originate backend TLS in passthrough mode".to_string(),
                );
            }
        }

        // TLS material source lengths
        if let Some(ref path) = self.backend_tls_client_cert_path
            && let Err(e) = validate_tls_material_source_field(
                "backend_tls_client_cert_path",
                path,
                crate::tls::source::MaterialKind::Cert,
            )
        {
            errors.push(e);
        }
        if let Some(ref path) = self.backend_tls_client_key_path
            && let Err(e) = validate_tls_material_source_field(
                "backend_tls_client_key_path",
                path,
                crate::tls::source::MaterialKind::Key,
            )
        {
            errors.push(e);
        }
        if let Some(ref path) = self.backend_tls_server_ca_cert_path
            && let Err(e) = validate_tls_material_source_field(
                "backend_tls_server_ca_cert_path",
                path,
                crate::tls::source::MaterialKind::CaBundle,
            )
        {
            errors.push(e);
        }

        // TLS cert/key pairing: both must be set or neither
        match (
            &self.backend_tls_client_cert_path,
            &self.backend_tls_client_key_path,
        ) {
            (Some(_), None) => {
                errors.push(
                    "backend_tls_client_cert_path is set but backend_tls_client_key_path is missing — both must be configured together".to_string(),
                );
            }
            (None, Some(_)) => {
                errors.push(
                    "backend_tls_client_key_path is set but backend_tls_client_cert_path is missing — both must be configured together".to_string(),
                );
            }
            _ => {}
        }

        // TLS file content validation: open, read, and parse PEM files.
        // When a validated_tls_paths cache is provided (batch validation), paths
        // that were already validated by a prior proxy are skipped to avoid
        // redundant file I/O when many proxies share the same cert files.
        // Also checks certificate expiration: expired certs are rejected,
        // near-expiry certs emit a warning log.
        if let Some(ref path) = self.backend_tls_client_cert_path {
            let cache_key = tls_validation_cache_key(crate::tls::source::MaterialKind::Cert, path);
            let already_validated = validated_tls_paths
                .as_ref()
                .is_some_and(|s| s.contains(&cache_key));
            if !already_validated {
                if let Err(e) = validate_pem_cert_file("backend_tls_client_cert_path", path) {
                    errors.push(e);
                } else if let Err(e) = crate::tls::check_cert_expiry_for_validation(
                    path,
                    "backend_tls_client_cert_path",
                    cert_expiry_warning_days,
                ) {
                    errors.push(e);
                } else if let Some(ref mut cache) = validated_tls_paths {
                    cache.insert(cache_key);
                }
            }
        }
        if let Some(ref path) = self.backend_tls_client_key_path {
            let cache_key = tls_validation_cache_key(crate::tls::source::MaterialKind::Key, path);
            let already_validated = validated_tls_paths
                .as_ref()
                .is_some_and(|s| s.contains(&cache_key));
            if !already_validated {
                if let Err(e) = validate_pem_key_file("backend_tls_client_key_path", path) {
                    errors.push(e);
                } else if let Some(ref mut cache) = validated_tls_paths {
                    cache.insert(cache_key);
                }
            }
        }
        if let Some(ref path) = self.backend_tls_server_ca_cert_path {
            let cache_key =
                tls_validation_cache_key(crate::tls::source::MaterialKind::CaBundle, path);
            let already_validated = validated_tls_paths
                .as_ref()
                .is_some_and(|s| s.contains(&cache_key));
            if !already_validated {
                if let Err(e) = validate_pem_ca_file("backend_tls_server_ca_cert_path", path) {
                    errors.push(e);
                } else if let Err(e) = crate::tls::check_cert_expiry_for_validation(
                    path,
                    "backend_tls_server_ca_cert_path",
                    cert_expiry_warning_days,
                ) {
                    errors.push(e);
                } else if let Some(ref mut cache) = validated_tls_paths {
                    cache.insert(cache_key);
                }
            }
        }

        // Allowed methods validation
        if let Some(ref methods) = self.allowed_methods {
            if methods.is_empty() {
                errors.push(
                    "allowed_methods must be null (allow all) or a non-empty array".to_string(),
                );
            }
            for method in methods {
                let upper = method.trim().to_uppercase();
                if !VALID_HTTP_METHODS.contains(&upper.as_str()) {
                    errors.push(format!(
                        "allowed_methods contains invalid HTTP method: {}",
                        method
                    ));
                }
            }
        }

        // UDP amplification factor validation
        if let Some(factor) = self.udp_max_response_amplification_factor
            && factor <= 0.0
        {
            errors.push("udp_max_response_amplification_factor must be positive".to_string());
        }

        // Allowed WebSocket origins validation
        for (i, origin) in self.allowed_ws_origins.iter().enumerate() {
            if origin.trim().is_empty() {
                errors.push(format!("allowed_ws_origins[{}] must not be empty", i));
            }
        }

        // DNS override
        if let Some(ref dns) = self.dns_override
            && let Err(e) = validate_string_field("dns_override", dns, MAX_BACKEND_HOST_LENGTH)
        {
            errors.push(e);
        }

        // Circuit breaker config
        if let Some(ref cb) = self.circuit_breaker
            && let Err(cb_errors) = cb.validate_fields()
        {
            for e in cb_errors {
                errors.push(format!("circuit_breaker.{}", e));
            }
        }

        // Retry config
        if let Some(ref retry) = self.retry
            && let Err(retry_errors) = retry.validate_fields()
        {
            for e in retry_errors {
                errors.push(format!("retry.{}", e));
            }
        }

        if is_stream_proxy && self.response_body_mode != ResponseBodyMode::Stream {
            errors.push("Stream proxies (TCP/UDP) must use response_body_mode 'stream'".into());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl Consumer {
    /// Normalize a credential value to a list of object entries.
    pub(crate) fn credential_entries_from_value(
        credential_value: &serde_json::Value,
    ) -> Vec<&serde_json::Value> {
        match credential_value {
            serde_json::Value::Array(arr) => arr.iter().filter(|v| v.is_object()).collect(),
            _ => vec![],
        }
    }

    /// Returns all credential entries for a given type.
    /// - `{"keyauth": [{"key": "abc"}, {"key": "def"}]}` → `vec![&{"key": "abc"}, &{"key": "def"}]`
    ///
    /// Called on cold paths (index build) and semi-hot paths (after O(1) consumer
    /// lookup, iterating 1-2 entries). Non-object array elements are filtered out.
    pub fn credential_entries(&self, cred_type: &str) -> Vec<&serde_json::Value> {
        match self.credentials.get(cred_type) {
            Some(credential_value) => Self::credential_entries_from_value(credential_value),
            _ => vec![],
        }
    }

    /// Returns true if the consumer has any credentials of the given type.
    pub fn has_credential(&self, cred_type: &str) -> bool {
        match self.credentials.get(cred_type) {
            Some(serde_json::Value::Array(arr)) => arr.iter().any(|v| v.is_object()),
            _ => false,
        }
    }

    /// Normalize consumer fields to their canonical in-memory form.
    pub fn normalize_fields(&mut self) {
        if self
            .custom_id
            .as_ref()
            .is_some_and(|custom_id| custom_id.trim().is_empty())
        {
            self.custom_id = None;
        }
        if let Some(entries) = self
            .credentials
            .get_mut("mtls_auth")
            .and_then(serde_json::Value::as_array_mut)
        {
            for entry in entries {
                if let Some(object) = entry.as_object_mut()
                    && let Some(identity) = object
                        .get("identity")
                        .and_then(serde_json::Value::as_str)
                        .map(str::trim)
                        .map(str::to_owned)
                {
                    object.insert("identity".to_string(), serde_json::Value::String(identity));
                }
            }
        }
    }

    /// Validate all fields of a consumer for correctness and safe lengths.
    pub fn validate_fields(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Username
        if self.username.trim().is_empty() {
            errors.push("username must not be empty".to_string());
        }
        if let Err(e) = validate_string_field("username", &self.username, MAX_USERNAME_LENGTH) {
            errors.push(e);
        }

        // Custom ID
        if let Some(ref cid) = self.custom_id
            && let Err(e) = validate_string_field("custom_id", cid, MAX_CUSTOM_ID_LENGTH)
        {
            errors.push(e);
        }

        // ACL groups
        if self.acl_groups.len() > MAX_ACL_GROUPS_PER_CONSUMER {
            errors.push(format!(
                "acl_groups must not have more than {} entries (got {})",
                MAX_ACL_GROUPS_PER_CONSUMER,
                self.acl_groups.len()
            ));
        }
        for (i, group) in self.acl_groups.iter().enumerate() {
            if group.trim().is_empty() {
                errors.push(format!("acl_groups[{}] must not be empty", i));
            }
            if let Err(e) = validate_string_field("acl_groups entry", group, MAX_ACL_GROUP_LENGTH) {
                errors.push(e);
            }
        }

        // Credentials total size
        let cred_json = serde_json::to_string(&self.credentials).unwrap_or_default();
        if cred_json.len() > MAX_CREDENTIALS_SIZE {
            errors.push(format!(
                "credentials JSON must not exceed {} bytes (got {})",
                MAX_CREDENTIALS_SIZE,
                cred_json.len()
            ));
        }

        // Validate individual credential values.
        for (cred_type, cred_value) in &self.credentials {
            if let Err(e) = validate_credential_type_name(cred_type) {
                errors.push(e);
            }
            // Collect array entries to validate. Non-object elements are
            // rejected so operators cannot accidentally configure unusable
            // credentials.
            let objects: Vec<&serde_json::Map<String, serde_json::Value>> =
                if let Some(arr) = cred_value.as_array() {
                    let limit = max_credentials_per_type();
                    if arr.len() > limit {
                        errors.push(format!(
                            "credentials.{} array must not exceed {} entries (got {})",
                            cred_type,
                            limit,
                            arr.len()
                        ));
                    }
                    if arr.is_empty() {
                        errors.push(format!(
                            "credentials.{} array must not be empty — remove the key instead",
                            cred_type
                        ));
                    }
                    for (i, elem) in arr.iter().enumerate() {
                        if !elem.is_object() {
                            errors.push(format!(
                                "credentials.{}[{}] must be a JSON object, got {}",
                                cred_type,
                                i,
                                elem_type_name(elem)
                            ));
                        }
                    }
                    arr.iter().filter_map(|v| v.as_object()).collect()
                } else {
                    errors.push(format!(
                        "credentials.{} must be an array of JSON objects",
                        cred_type
                    ));
                    vec![]
                };
            for (idx, obj) in objects.iter().enumerate() {
                let prefix = format!("credentials.{}[{}]", cred_type, idx);
                if cred_type == "mtls_auth" {
                    if obj.len() != 1 || !obj.contains_key("identity") {
                        errors.push(format!(
                            "{} must contain exactly one field named 'identity'",
                            prefix
                        ));
                    }
                    match obj.get("identity") {
                        Some(serde_json::Value::String(identity))
                            if !identity.trim().is_empty() => {}
                        Some(serde_json::Value::String(_)) => {
                            errors.push(format!("{}.identity must not be empty", prefix));
                        }
                        Some(_) => errors.push(format!("{}.identity must be a string", prefix)),
                        None => {}
                    }
                }
                if cred_type == "hmac_auth" {
                    if obj.len() != 1 || !obj.contains_key("secret") {
                        errors.push(format!(
                            "{} must contain exactly one field named 'secret'",
                            prefix
                        ));
                    }
                    match obj.get("secret") {
                        Some(serde_json::Value::String(secret)) => {
                            let strength = hmac_secret_strength(secret);
                            if strength < MIN_HMAC_SECRET_LENGTH {
                                errors.push(format!(
                                    "{}.secret must be at least {} non-whitespace characters (got {})",
                                    prefix, MIN_HMAC_SECRET_LENGTH, strength
                                ));
                            }
                        }
                        Some(_) => errors.push(format!("{}.secret must be a string", prefix)),
                        None => {}
                    }
                }
                if cred_type == "basicauth"
                    && let Some(error) = basic_auth_credential_error(obj)
                {
                    errors.push(format!("{} {}", prefix, error));
                }
                if cred_type == "jwt" {
                    if obj.len() != 1 || !obj.contains_key("secret") {
                        errors.push(format!(
                            "{} must contain exactly one field named 'secret'",
                            prefix
                        ));
                    }
                    match obj.get("secret") {
                        Some(serde_json::Value::String(secret))
                            if secret.chars().count() >= MIN_JWT_SECRET_LENGTH => {}
                        Some(serde_json::Value::String(secret)) => {
                            errors.push(format!(
                                "{}.secret must be at least {} characters (got {})",
                                prefix,
                                MIN_JWT_SECRET_LENGTH,
                                secret.chars().count()
                            ));
                        }
                        Some(_) => errors.push(format!("{}.secret must be a string", prefix)),
                        None => {}
                    }
                }
                if cred_type == "keyauth" {
                    match obj.get("key") {
                        Some(serde_json::Value::String(key)) if !key.trim().is_empty() => {}
                        Some(serde_json::Value::String(_)) => {
                            errors.push(format!("{}.key must not be empty", prefix));
                        }
                        Some(_) => errors.push(format!("{}.key must be a string", prefix)),
                        None => errors.push(format!("{}.key is required", prefix)),
                    }
                }
                // `[REDACTED]` is reserved: whole-Consumer update treats it as
                // the round-trip sentinel for a secret the ordinary response
                // never disclosed, so it must never be storable as a live
                // credential value. Rejecting it here covers create, batch,
                // restore, the dedicated credential endpoints, and any update
                // placeholder left unmatched by a stored entry.
                for &(known_type, field) in REDACTED_CREDENTIAL_SECRET_FIELDS {
                    if known_type != cred_type.as_str() {
                        continue;
                    }
                    let value = obj.get(field).and_then(serde_json::Value::as_str);
                    if value == Some(CREDENTIAL_REDACTION_PLACEHOLDER) {
                        errors.push(format!(
                            "{}.{} must not be the reserved redaction placeholder",
                            prefix, field
                        ));
                    }
                }
                for (key, val) in *obj {
                    if let Some(s) = val.as_str() {
                        let value_length = s.chars().count();
                        if value_length > MAX_CREDENTIAL_VALUE_LENGTH {
                            errors.push(format!(
                                "{}.{} must not exceed {} characters (got {})",
                                prefix, key, MAX_CREDENTIAL_VALUE_LENGTH, value_length
                            ));
                        }
                        if contains_control_chars(s) {
                            errors.push(format!(
                                "{}.{} must not contain control characters",
                                prefix, key
                            ));
                        }
                    }
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

fn record_consumer_identity<'a>(
    seen: &mut HashMap<&'a str, (&'a str, &'static str)>,
    duplicates: &mut Vec<String>,
    consumer_id: &'a str,
    field: &'static str,
    value: &'a str,
) {
    let Some(&(existing_id, existing_field)) = seen.get(value) else {
        seen.insert(value, (consumer_id, field));
        return;
    };

    if existing_id == consumer_id {
        return;
    }

    let message = match (field, existing_field) {
        ("id", "id") => format!(
            "Duplicate consumer id '{}' in consumer '{}' (conflicts with '{}')",
            value, consumer_id, existing_id
        ),
        ("username", "username") => format!(
            "Duplicate consumer username '{}' in consumer '{}' (conflicts with '{}')",
            value, consumer_id, existing_id
        ),
        ("custom_id", "custom_id") => format!(
            "Duplicate consumer custom_id '{}' in consumer '{}' (conflicts with '{}')",
            value, consumer_id, existing_id
        ),
        _ => format!(
            "Consumer '{}' {} '{}' collides with {} of consumer '{}' \
             — this will cause incorrect JWKS/JWT authentication",
            consumer_id, field, value, existing_field, existing_id
        ),
    };

    duplicates.push(message);
}

pub fn redact_consumer_credentials(consumer: &Consumer) -> Consumer {
    let mut redacted = consumer.clone();

    fn entry_objects(
        credential_value: &serde_json::Value,
    ) -> Vec<&serde_json::Map<String, serde_json::Value>> {
        match credential_value {
            serde_json::Value::Array(entries) => entries
                .iter()
                .filter_map(serde_json::Value::as_object)
                .collect(),
            serde_json::Value::Object(object) => vec![object],
            _ => Vec::new(),
        }
    }

    fn secret_placeholders(
        credential_value: &serde_json::Value,
        field: &str,
    ) -> Option<serde_json::Value> {
        let entries: Vec<_> = entry_objects(credential_value)
            .into_iter()
            .map(|_| serde_json::json!({(field): CREDENTIAL_REDACTION_PLACEHOLDER}))
            .collect();
        (!entries.is_empty()).then(|| serde_json::Value::Array(entries))
    }

    fn visible_mtls_identities(credential_value: &serde_json::Value) -> Option<serde_json::Value> {
        let entries: Vec<_> = entry_objects(credential_value)
            .into_iter()
            .filter_map(|entry| entry.get("identity").and_then(serde_json::Value::as_str))
            .filter(|identity| {
                !identity.trim().is_empty()
                    && identity.chars().count() <= MAX_CREDENTIAL_VALUE_LENGTH
                    && !contains_control_chars(identity)
            })
            .map(|identity| serde_json::json!({"identity": identity}))
            .collect();
        (!entries.is_empty()).then(|| serde_json::Value::Array(entries))
    }

    // Ordinary responses are a deliberately closed projection. Rebuild the
    // credential map from known, explicitly safe fields so legacy extra fields
    // and unknown/custom credential values cannot cross the management
    // boundary. Input, persistence, backup, and restore retain the original
    // credential map; this projection affects ordinary responses and audit
    // events only.
    redacted.credentials.clear();
    for &(cred_type, field) in REDACTED_CREDENTIAL_SECRET_FIELDS {
        if let Some(entries) = consumer
            .credentials
            .get(cred_type)
            .and_then(|value| secret_placeholders(value, field))
        {
            redacted.credentials.insert(cred_type.to_string(), entries);
        }
    }
    if let Some(entries) = consumer
        .credentials
        .get("mtls_auth")
        .and_then(visible_mtls_identities)
    {
        redacted
            .credentials
            .insert("mtls_auth".to_string(), entries);
    }

    redacted
}

pub fn redact_consumer_credentials_for_audit(consumer: &Consumer) -> Consumer {
    let mut redacted = redact_consumer_credentials(consumer);
    if consumer.credentials.contains_key("basicauth") {
        // Audit events need to show that Basic credentials were present or
        // changed, but must not disclose values, entry fields, or even the
        // stored credential shape/cardinality. A single stable marker keeps
        // the mutation visible without creating a credential side channel.
        redacted.credentials.insert(
            "basicauth".to_string(),
            serde_json::json!(CREDENTIAL_REDACTION_PLACEHOLDER),
        );
    }
    redacted
}

/// Whether `entry` is exactly the redaction projection of one credential entry
/// of `cred_type`, i.e. a lone `field` set to
/// [`CREDENTIAL_REDACTION_PLACEHOLDER`].
fn is_redaction_placeholder_entry(entry: &serde_json::Value, field: &str) -> bool {
    entry.as_object().is_some_and(|object| {
        object.len() == 1
            && object.get(field).and_then(serde_json::Value::as_str)
                == Some(CREDENTIAL_REDACTION_PLACEHOLDER)
    })
}

/// Restores the credential state a whole-Consumer update cannot express.
///
/// Ordinary Consumer responses are a closed projection, so a read-modify-write
/// client that GETs a Consumer, edits a scalar field, and PUTs the body back
/// never sends the credential state it was not shown. Two rewrites are needed
/// so that flow stays non-destructive:
///
/// 1. A stored credential type the ordinary projection does not emit at all —
///    `basicauth`, every unknown/custom type, and an `mtls_auth` map whose
///    entries the projection all filtered out — is copied from `existing` when
///    the request omits it, because the client was never shown it. When an
///    `mtls_auth` projection contains only the visible subset of stored entries,
///    submitting that exact projection restores the original map too; an
///    actually edited value still replaces it. A type the projection does emit
///    is still deleted by omission, so that contract is unchanged. Explicit
///    removal of a hidden type uses
///    `DELETE /consumers/{id}/credentials/{cred_type}`, which is authoritative
///    for them.
/// 2. `keyauth`/`jwt`/`hmac_auth` entries submitted as the exact
///    [`CREDENTIAL_REDACTION_PLACEHOLDER`] projection are restored positionally
///    from the stored entry at the same index, so a round-tripped response
///    cannot overwrite a live API key or shared secret with the placeholder
///    string. Entries carrying real values are left untouched, so rotation
///    through this path still works.
///
/// Credential types the request does send are otherwise replaced wholesale, so
/// deleting a projected known type by omission keeps working.
pub fn preserve_response_hidden_consumer_credentials(updated: &mut Consumer, existing: &Consumer) {
    // Ask the projection itself which types a client could have seen, so this
    // stays correct by construction if the projection changes.
    let projected = redact_consumer_credentials(existing);
    for (cred_type, stored) in &existing.credentials {
        if !projected.credentials.contains_key(cred_type)
            && !updated.credentials.contains_key(cred_type)
        {
            updated
                .credentials
                .insert(cred_type.clone(), stored.clone());
        }
    }

    // mTLS identities are visible, but malformed legacy entries and every
    // non-identity field are filtered from the ordinary response. If the
    // submitted value is byte-for-byte the projection the server emitted,
    // restore the stored value so an unrelated Consumer edit cannot silently
    // delete that hidden state. Validation may then reject legacy-invalid data,
    // which is deliberately fail-closed; a caller that supplies any different
    // mTLS value is making an express replacement and keeps that value.
    let submitted_mtls_is_exact_projection = updated
        .credentials
        .get("mtls_auth")
        .zip(projected.credentials.get("mtls_auth"))
        .is_some_and(|(submitted, visible)| submitted == visible);
    if submitted_mtls_is_exact_projection
        && let Some(stored_mtls) = existing.credentials.get("mtls_auth")
    {
        updated
            .credentials
            .insert("mtls_auth".to_string(), stored_mtls.clone());
    }

    for &(cred_type, field) in REDACTED_CREDENTIAL_SECRET_FIELDS {
        // The projection emits one entry per stored entry, in order, for both
        // the array form and the legacy single-object form, so stored entries
        // are indexed the same way here.
        let stored_entries: Vec<&serde_json::Value> = match existing.credentials.get(cred_type) {
            Some(serde_json::Value::Array(entries)) => entries.iter().collect(),
            Some(entry @ serde_json::Value::Object(_)) => vec![entry],
            _ => continue,
        };
        let Some(submitted_entries) = updated
            .credentials
            .get_mut(cred_type)
            .and_then(serde_json::Value::as_array_mut)
        else {
            continue;
        };
        for (index, entry) in submitted_entries.iter_mut().enumerate() {
            if is_redaction_placeholder_entry(entry, field)
                && let Some(stored_entry) = stored_entries.get(index)
            {
                // Restoring an exactly-one-field type verbatim would reintroduce
                // legacy selectors such as a `jwt` `algorithm`, which the
                // current contract rejects, so an unrelated Consumer edit would
                // fail on data the client was never shown. Restore the canonical
                // field only — the same value the runtime uses and the same
                // shape `GET /backup` exports. Types without a single-field rule
                // (`keyauth`) keep every stored field.
                *entry = match single_credential_field(cred_type) {
                    Some(canonical_field) => {
                        canonical_single_field_entry(stored_entry, canonical_field)
                    }
                    None => (*stored_entry).clone(),
                };
            }
        }
    }
}

/// Canonicalizes a Consumer for `GET /backup` export.
///
/// Backups carry unredacted stored credentials so `POST /restore` can recreate
/// them faithfully. Exactly-one-field credential types — `jwt` and `hmac_auth`
/// (`secret`) and `mtls_auth` (`identity`) — can still hold rows written before
/// that contract was enforced, carrying ignored extra fields such as a `jwt`
/// `algorithm`, which restore now rejects. Reducing those entries to their
/// canonical field keeps a backup taken from a deployed database restorable,
/// which is also the shape `ConsumerBackup` already documents.
///
/// `POST /restore` also requires every credential value to be an array of
/// objects, so a value still stored in the legacy single-object form is wrapped
/// in a one-element array here rather than exported in a shape restore rejects.
///
/// The rewrite is deliberately narrow: it never mutates the stored Consumer,
/// keeps every rotation entry in order, leaves entries without a string value at
/// the canonical field untouched so genuinely unrepresentable data surfaces at
/// restore instead of being silently dropped, and copies every credential type
/// without a single-field rule — `basicauth`, `keyauth`, and unknown/custom
/// maps — through with its fields intact.
pub fn canonicalize_consumer_credentials_for_backup(consumer: &Consumer) -> Consumer {
    let mut canonical = consumer.clone();
    for (cred_type, value) in canonical.credentials.iter_mut() {
        if value.is_object() {
            let legacy_single_entry = value.clone();
            *value = serde_json::Value::Array(vec![legacy_single_entry]);
        }
        let Some(field) = single_credential_field(cred_type) else {
            continue;
        };
        if let serde_json::Value::Array(entries) = value {
            for entry in entries.iter_mut() {
                *entry = canonical_single_field_entry(entry, field);
            }
        }
    }
    canonical
}

pub(crate) fn hash_consumer_secrets(
    consumer: &mut Consumer,
) -> Result<(), BasicAuthCredentialPreparationError> {
    if let Some(credentials) = consumer.credentials.get_mut("basicauth") {
        hash_credential_passwords(credentials)?;
    }

    Ok(())
}

fn hash_basic_auth_password(password: &str) -> Result<String, BasicAuthCredentialPreparationError> {
    let secret = crate::config::conf_file::resolve_ferrum_var("FERRUM_BASIC_AUTH_HMAC_SECRET");
    hash_basic_auth_password_with_secret(password, secret.as_deref())
}

pub(crate) fn hash_basic_auth_password_with_secret(
    password: &str,
    secret: Option<&str>,
) -> Result<String, BasicAuthCredentialPreparationError> {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let secret = secret.ok_or_else(|| {
        BasicAuthCredentialPreparationError::ServerConfiguration(
            "FERRUM_BASIC_AUTH_HMAC_SECRET must be set to hash Basic-auth passwords".to_string(),
        )
    })?;
    validate_basic_auth_hmac_secret(secret)
        .map_err(BasicAuthCredentialPreparationError::ServerConfiguration)?;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|error| {
        BasicAuthCredentialPreparationError::ServerConfiguration(format!(
            "Failed to create HMAC instance: {error}"
        ))
    })?;
    mac.update(password.as_bytes());
    let hash = hex::encode(mac.finalize().into_bytes());
    Ok(format!("hmac_sha256:{}", hash))
}

pub(crate) fn hash_credential_passwords(
    cred: &mut serde_json::Value,
) -> Result<(), BasicAuthCredentialPreparationError> {
    fn prepare_entry(
        entry: &mut serde_json::Value,
    ) -> Result<(), BasicAuthCredentialPreparationError> {
        let object = entry.as_object().ok_or_else(|| {
            BasicAuthCredentialPreparationError::InvalidCredential(
                "Basic-auth credential entry must be a JSON object".to_string(),
            )
        })?;
        if let Some(error) = basic_auth_credential_error(object) {
            return Err(BasicAuthCredentialPreparationError::InvalidCredential(
                format!("Basic-auth credential entry {error}"),
            ));
        }
        let Some(password) = object.get("password").and_then(serde_json::Value::as_str) else {
            return Ok(());
        };
        let hash = hash_basic_auth_password(password)?;
        let object = entry.as_object_mut().ok_or_else(|| {
            BasicAuthCredentialPreparationError::InvalidCredential(
                "Basic-auth credential entry must be a JSON object".to_string(),
            )
        })?;
        object.remove("password");
        object.insert("password_hash".to_string(), serde_json::json!(hash));
        Ok(())
    }

    match cred {
        serde_json::Value::Array(entries) => {
            for entry in entries {
                prepare_entry(entry)?;
            }
        }
        serde_json::Value::Object(_) => prepare_entry(cred)?,
        _ => {
            return Err(BasicAuthCredentialPreparationError::InvalidCredential(
                "Basic-auth credentials must be an object or array".to_string(),
            ));
        }
    }

    Ok(())
}

impl Upstream {
    /// Screen this upstream's literal-IP target hosts against the backend
    /// egress policy. Hostname targets are screened at DNS-resolution time.
    /// Returns prefix-free messages so each caller can attribute them.
    ///
    /// Uses the canonical-literal-only [`stream_literal_ip`] rather than the
    /// URL-canonicalizing [`egress_literal_ip`]: an upstream can be referenced by
    /// stream (`tcp`/`udp`) proxies whose dial path resolves a numeric name like
    /// `111` through DNS, so URL-canonicalizing it here would wrongly reject a
    /// legitimate stream target at admission. URL-style IPv4 spellings on an
    /// HTTP-family target are still blocked at dispatch by the request-path
    /// `denied_literal_backend_ip` screen (which uses `egress_literal_ip` on the
    /// resolved target), so this admission scope does not weaken HTTP egress.
    pub fn validate_backend_egress_ips(
        &self,
        backend_allow_ips: &crate::config::BackendEgressPolicy,
    ) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        for (i, target) in self.targets.iter().enumerate() {
            if let Some(ip) = stream_literal_ip(&target.host)
                && let Some(reason) = backend_allow_ips.deny_reason(&ip)
            {
                errors.push(format!(
                    "targets[{i}].host IP {ip} denied by backend egress policy: {reason}"
                ));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Normalize upstream fields to their canonical in-memory form.
    pub fn normalize_fields(&mut self) {
        // RFC 1035: DNS names are case-insensitive. Normalize target hosts so
        // downstream consumers (DNS cache, health check keys, LB keys) never
        // create duplicate entries for mixed-case variants of the same hostname.
        for target in &mut self.targets {
            target.host = target.host.to_ascii_lowercase();
        }
        if let Some(sni) = &mut self.backend_tls_sni {
            *sni = sni.to_ascii_lowercase();
        }
        for san in &mut self.backend_tls_san_allow_list {
            normalize_backend_tls_san_allow_list_entry(san);
        }
        for override_config in self.port_overrides.values_mut() {
            if let Some(tls) = &mut override_config.tls {
                tls.normalize_fields();
            }
        }
    }

    /// Resolve the effective backend connect timeout for a request destined to
    /// `port`. Per-port `port_overrides[port].connect_timeout_ms` wins over
    /// `proxy_default_ms` (the Proxy's own `backend_connect_timeout_ms`).
    ///
    /// Used by the dispatch hot path so DestinationRule per-port settings
    /// translated by the Istio config source actually take effect at request
    /// time. `0` from either source means "disabled".
    #[inline]
    pub fn effective_connect_timeout_ms(&self, port: u16, proxy_default_ms: u64) -> u64 {
        self.port_overrides
            .get(&port)
            .and_then(|ovr| ovr.connect_timeout_ms)
            .unwrap_or(proxy_default_ms)
    }

    /// Validate all fields of an upstream for correctness and safe lengths.
    pub fn validate_fields(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.targets.is_empty() && self.service_discovery.is_none() {
            errors.push("must have at least one target or service_discovery".to_string());
        }

        // Name
        if let Some(ref name) = self.name
            && let Err(e) = validate_string_field("name", name, MAX_NAME_LENGTH)
        {
            errors.push(e);
        }

        // hash_on
        if let Some(ref hash_on) = self.hash_on
            && let Err(e) = validate_string_field("hash_on", hash_on, MAX_HASH_ON_LENGTH)
        {
            errors.push(e);
        }

        // Validate hash_on format: must be "ip", "header:<name>", or "cookie:<name>"
        if let Some(ref hash_on) = self.hash_on {
            let trimmed = hash_on.trim();
            if !trimmed.is_empty()
                && trimmed != "ip"
                && !trimmed.starts_with("header:")
                && !trimmed.starts_with("cookie:")
            {
                errors.push(format!(
                    "hash_on must be 'ip', 'header:<name>', or 'cookie:<name>' (got '{}')",
                    trimmed
                ));
            }
            // Validate that header/cookie name is non-empty
            if let Some(name) = trimmed.strip_prefix("header:")
                && name.trim().is_empty()
            {
                errors.push("hash_on 'header:' requires a non-empty header name".to_string());
            }
            if let Some(name) = trimmed.strip_prefix("cookie:")
                && name.trim().is_empty()
            {
                errors.push("hash_on 'cookie:' requires a non-empty cookie name".to_string());
            }
        }

        // hash_on_cookie_config
        if let Some(ref cc) = self.hash_on_cookie_config {
            if let Err(e) = validate_string_field(
                "hash_on_cookie_config.path",
                &cc.path,
                MAX_COOKIE_PATH_LENGTH,
            ) {
                errors.push(e);
            }
            if let Some(ref domain) = cc.domain
                && let Err(e) = validate_string_field(
                    "hash_on_cookie_config.domain",
                    domain,
                    MAX_COOKIE_DOMAIN_LENGTH,
                )
            {
                errors.push(e);
            }
            if let Some(ref same_site) = cc.same_site
                && !["Strict", "Lax", "None"].contains(&same_site.as_str())
            {
                errors.push(format!(
                    "hash_on_cookie_config.same_site must be 'Strict', 'Lax', or 'None' (got '{}')",
                    same_site
                ));
            }
            if cc.ttl_seconds > MAX_TIMEOUT_SECONDS {
                errors.push(format!(
                    "hash_on_cookie_config.ttl_seconds must not exceed {} (got {})",
                    MAX_TIMEOUT_SECONDS, cc.ttl_seconds
                ));
            }
        }

        // Target count limit
        if self.targets.len() > MAX_TARGETS_PER_UPSTREAM {
            errors.push(format!(
                "targets must not have more than {} entries (got {})",
                MAX_TARGETS_PER_UPSTREAM,
                self.targets.len()
            ));
        }

        // NOTE: rejection of mesh-PROJECTED fields that an operator must not set
        // directly (`port_overrides`, `source_locality`, `locality_lb_strict`,
        // `locality_lb_setting`, and the mesh-only fields nested under
        // `subsets[].traffic_policy`) lives in
        // [`Upstream::validate_operator_provided_fields`], NOT here. The rejection
        // belongs on every OPERATOR-PROVIDED load (admin write/admission AND the
        // file-mode loader, via [`GatewayConfig::validate_operator_provided_fields`])
        // but must NOT fire on the mesh slice-apply path, which legitimately
        // PROJECTS those fields. `validate_fields` runs on the mesh slice-prep path
        // too (it materializes upstreams carrying these fields), so putting the
        // rejection here would make every mesh reload / remote-endpoint update emit
        // a false "misconfigured" error. Operator entry points therefore call
        // `validate_operator_provided_fields` explicitly in addition to
        // `validate_fields`; the mesh slice-prep path never does.

        // Validate individual targets
        for (i, target) in self.targets.iter().enumerate() {
            if let Err(e) = validate_string_field(
                &format!("targets[{}].host", i),
                &target.host,
                MAX_BACKEND_HOST_LENGTH,
            ) {
                errors.push(e);
            }
            if target.host.is_empty() {
                errors.push(format!("targets[{}].host must not be empty", i));
            }
            if target.port == 0 {
                errors.push(format!("targets[{}].port must be greater than 0", i));
            }
            if target.weight == 0 || target.weight > MAX_TARGET_WEIGHT {
                errors.push(format!(
                    "targets[{}].weight must be between 1 and {} (got {})",
                    i, MAX_TARGET_WEIGHT, target.weight
                ));
            }
            // Tag limits
            if target.tags.len() > MAX_TAGS_PER_TARGET {
                errors.push(format!(
                    "targets[{}].tags must not have more than {} entries (got {})",
                    i,
                    MAX_TAGS_PER_TARGET,
                    target.tags.len()
                ));
            }
            for (key, val) in &target.tags {
                if key.len() > MAX_TAG_LENGTH {
                    errors.push(format!(
                        "targets[{}].tags key must not exceed {} characters",
                        i, MAX_TAG_LENGTH
                    ));
                }
                if val.len() > MAX_TAG_LENGTH {
                    errors.push(format!(
                        "targets[{}].tags value must not exceed {} characters",
                        i, MAX_TAG_LENGTH
                    ));
                }
            }
            // Target path
            if let Some(ref path) = target.path
                && let Err(e) = validate_string_field(
                    &format!("targets[{}].path", i),
                    path,
                    MAX_BACKEND_PATH_LENGTH,
                )
            {
                errors.push(e);
            }
            // Target locality — Istio-style `region/zone/subzone`. Validate the
            // length cap and parse it through `LocalityPreference::parse` so
            // operators get a clear 400 instead of a silent rank-3 fallback in
            // the load balancer.
            if let Some(ref locality) = target.locality {
                if let Err(e) = validate_string_field(
                    &format!("targets[{}].locality", i),
                    locality,
                    MAX_LOCALITY_LENGTH,
                ) {
                    errors.push(e);
                }
                if LocalityPreference::parse(locality).is_none() {
                    errors.push(format!(
                        "targets[{}].locality '{}' is not a valid \
                         region[/zone[/subzone]] string",
                        i, locality
                    ));
                }
            }
        }

        // Health check config
        if let Some(ref hc) = self.health_checks
            && let Err(hc_errors) = hc.validate_fields()
        {
            for e in hc_errors {
                errors.push(format!("health_checks.{}", e));
            }
        }

        // Service discovery config
        if let Some(ref sd) = self.service_discovery
            && let Err(sd_errors) = sd.validate_fields(&self.namespace)
        {
            for e in sd_errors {
                errors.push(format!("service_discovery.{}", e));
            }
        }

        // Subset definitions
        if let Some(ref subsets) = self.subsets {
            if subsets.is_empty() {
                errors.push(
                    "subsets must not be empty — omit the field when no subsets are defined"
                        .to_string(),
                );
            }
            if subsets.len() > MAX_SUBSETS_PER_UPSTREAM {
                errors.push(format!(
                    "subsets must not have more than {} entries (got {})",
                    MAX_SUBSETS_PER_UPSTREAM,
                    subsets.len()
                ));
            }
            let mut seen_names = HashSet::new();
            for (i, subset) in subsets.iter().enumerate() {
                if subset.name.trim().is_empty() {
                    errors.push(format!("subsets[{}].name must not be empty", i));
                }
                if let Err(e) =
                    validate_string_field("subsets.name", &subset.name, MAX_SUBSET_NAME_LENGTH)
                {
                    errors.push(format!("subsets[{}].{}", i, e));
                }
                if !seen_names.insert(&subset.name) {
                    errors.push(format!(
                        "subsets[{}].name '{}' is a duplicate — subset names must be unique within an upstream",
                        i, subset.name
                    ));
                }
                if subset.labels.is_empty() {
                    errors.push(format!(
                        "subsets[{}].labels must not be empty — a subset must select at least one label",
                        i
                    ));
                }
                for (key, val) in &subset.labels {
                    if key.len() > MAX_TAG_LENGTH {
                        errors.push(format!(
                            "subsets[{}].labels key must not exceed {} characters",
                            i, MAX_TAG_LENGTH
                        ));
                    }
                    if val.len() > MAX_TAG_LENGTH {
                        errors.push(format!(
                            "subsets[{}].labels value must not exceed {} characters",
                            i, MAX_TAG_LENGTH
                        ));
                    }
                }
                if let Some(hash_on) = subset
                    .traffic_policy
                    .as_ref()
                    .and_then(|policy| policy.hash_on.as_ref())
                {
                    // Bound the length the same way upstream-level `hash_on` is
                    // (MAX_HASH_ON_LENGTH): the value is persisted, cloned into
                    // the LB cache, and read per request, so an unbounded
                    // `header:`+megabytes string must be rejected at admission.
                    if let Err(e) = validate_string_field(
                        &format!("subsets[{i}].traffic_policy.hash_on"),
                        hash_on,
                        MAX_HASH_ON_LENGTH,
                    ) {
                        errors.push(e);
                    }
                    let trimmed = hash_on.trim();
                    if !trimmed.is_empty()
                        && trimmed != "ip"
                        && !trimmed.starts_with("header:")
                        && !trimmed.starts_with("cookie:")
                    {
                        errors.push(format!(
                            "subsets[{}].traffic_policy.hash_on must be 'ip', \
                             'header:<name>', or 'cookie:<name>' (got '{}')",
                            i, trimmed
                        ));
                    }
                    if let Some(name) = trimmed.strip_prefix("header:")
                        && name.trim().is_empty()
                    {
                        errors.push(format!(
                            "subsets[{}].traffic_policy.hash_on 'header:' requires a non-empty header name",
                            i
                        ));
                    }
                    if let Some(name) = trimmed.strip_prefix("cookie:")
                        && name.trim().is_empty()
                    {
                        errors.push(format!(
                            "subsets[{}].traffic_policy.hash_on 'cookie:' requires a non-empty cookie name",
                            i
                        ));
                    }
                }
            }
        }

        // Backend TLS material source lengths
        if let Some(ref path) = self.backend_tls_client_cert_path
            && let Err(e) = validate_tls_material_source_field(
                "backend_tls_client_cert_path",
                path,
                crate::tls::source::MaterialKind::Cert,
            )
        {
            errors.push(e);
        }
        if let Some(ref path) = self.backend_tls_client_key_path
            && let Err(e) = validate_tls_material_source_field(
                "backend_tls_client_key_path",
                path,
                crate::tls::source::MaterialKind::Key,
            )
        {
            errors.push(e);
        }
        if let Some(ref path) = self.backend_tls_server_ca_cert_path
            && let Err(e) = validate_tls_material_source_field(
                "backend_tls_server_ca_cert_path",
                path,
                crate::tls::source::MaterialKind::CaBundle,
            )
        {
            errors.push(e);
        }
        if let Some(ref sni) = self.backend_tls_sni
            && let Err(e) = validate_backend_tls_sni(sni)
        {
            errors.push(e);
        }
        if self.backend_tls_san_allow_list.len() > MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES {
            errors.push(format!(
                "backend_tls_san_allow_list must not have more than {} entries (got {})",
                MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES,
                self.backend_tls_san_allow_list.len()
            ));
        }
        for (i, san) in self.backend_tls_san_allow_list.iter().enumerate() {
            if let Err(e) = validate_backend_tls_san_allow_list_entry(san) {
                errors.push(format!("backend_tls_san_allow_list[{}].{}", i, e));
            }
        }

        // TLS cert/key pairing: both must be set or neither
        match (
            &self.backend_tls_client_cert_path,
            &self.backend_tls_client_key_path,
        ) {
            (Some(_), None) => {
                errors.push(
                    "backend_tls_client_cert_path is set but backend_tls_client_key_path is missing — both must be configured together".to_string(),
                );
            }
            (None, Some(_)) => {
                errors.push(
                    "backend_tls_client_key_path is set but backend_tls_client_cert_path is missing — both must be configured together".to_string(),
                );
            }
            _ => {}
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Reject mesh-PROJECTED fields that an OPERATOR must not set directly.
    ///
    /// `port_overrides`, `source_locality`, `locality_lb_strict`,
    /// `locality_lb_setting`, and the `tls`, `connect_timeout_ms`, and
    /// `passive_health_check` fields nested under `subsets[].traffic_policy` are
    /// all populated by the mesh slice-apply layer (from DestinationRules / the
    /// workload locality / `FERRUM_MESH_LOCALITY_LB_STRICT`), NOT by operators.
    /// The top-level projected fields are not persisted by the SQL / MongoDB
    /// schemas. The nested fields can round-trip inside the persisted `subsets`
    /// JSON, but their effective runtime state is materialized only while applying
    /// a mesh DestinationRule; accepting them from an admin/file config would
    /// therefore advertise policy that those entry points never apply. The
    /// canonical surface for each is named in its message.
    ///
    /// This applies to **every operator-PROVIDED config load** — the admin write /
    /// admission path AND the file-mode loader — and is deliberately SEPARATE from
    /// [`Upstream::validate_fields`]: `validate_fields` also runs on the mesh
    /// slice-apply path (which legitimately PROJECTS these fields), where rejecting
    /// them would emit a false "misconfigured" error on every mesh reload /
    /// remote-endpoint update. Operator entry points therefore call this in
    /// addition to `validate_fields`; the mesh slice-prep path never does.
    /// See [`GatewayConfig::validate_operator_provided_fields`] for the config-wide
    /// wrapper the file loader uses.
    pub fn validate_operator_provided_fields(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if !self.port_overrides.is_empty() {
            errors.push(
                "port_overrides is populated by mesh DestinationRule \
                 portLevelSettings and cannot be set directly via the admin \
                 API — express per-port traffic policy as a DestinationRule"
                    .to_string(),
            );
        }

        if self.source_locality.is_some() {
            errors.push(
                "source_locality is projected from the mesh workload's \
                 locality and cannot be set directly via the admin API — \
                 set it on the Workload / pod topology labels instead"
                    .to_string(),
            );
        }

        if self.locality_lb_strict {
            errors.push(
                "locality_lb_strict is projected from the \
                 FERRUM_MESH_LOCALITY_LB_STRICT environment flag and cannot be \
                 set directly via the admin API — set the env var instead"
                    .to_string(),
            );
        }

        if self.locality_lb_setting.is_some() {
            errors.push(
                "locality_lb_setting is projected from a mesh \
                 DestinationRule's trafficPolicy.localityLbSetting and \
                 cannot be set directly via the admin API — express \
                 weighted distribute and failover via a DestinationRule"
                    .to_string(),
            );
        }

        if let Some(subsets) = self.subsets.as_ref() {
            for (index, subset) in subsets.iter().enumerate() {
                let Some(policy) = subset.traffic_policy.as_ref() else {
                    continue;
                };
                let field_prefix =
                    format!("subsets[{index}].traffic_policy (subset '{}')", subset.name);

                if policy.tls.is_some() {
                    errors.push(format!(
                        "{field_prefix}.tls is projected from a mesh DestinationRule and cannot \
                         be set directly via the admin API — express subset TLS policy as a \
                         DestinationRule"
                    ));
                }
                if policy.connect_timeout_ms.is_some() {
                    errors.push(format!(
                        "{field_prefix}.connect_timeout_ms is projected from a mesh \
                         DestinationRule and cannot be set directly via the admin API — express \
                         subset connection-pool policy as a DestinationRule"
                    ));
                }
                if policy.passive_health_check.is_some() {
                    errors.push(format!(
                        "{field_prefix}.passive_health_check is projected from a mesh \
                         DestinationRule and cannot be set directly via the admin API — express \
                         subset outlier-detection policy as a DestinationRule"
                    ));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate fields with a shared TLS path cache and cert expiry checking.
    pub fn validate_fields_with_cache(
        &self,
        validated_tls_paths: &mut HashSet<String>,
        cert_expiry_warning_days: u64,
    ) -> Result<(), Vec<String>> {
        let mut errors = match self.validate_fields() {
            Ok(()) => Vec::new(),
            Err(errs) => errs,
        };

        // TLS file content validation with deduplication.
        if let Some(ref path) = self.backend_tls_client_cert_path {
            let cache_key = tls_validation_cache_key(crate::tls::source::MaterialKind::Cert, path);
            let already_validated = validated_tls_paths.contains(&cache_key);
            if !already_validated {
                if let Err(e) = validate_pem_cert_file("backend_tls_client_cert_path", path) {
                    errors.push(e);
                } else if let Err(e) = crate::tls::check_cert_expiry_for_validation(
                    path,
                    "backend_tls_client_cert_path",
                    cert_expiry_warning_days,
                ) {
                    errors.push(e);
                } else {
                    validated_tls_paths.insert(cache_key);
                }
            }
        }
        if let Some(ref path) = self.backend_tls_client_key_path {
            let cache_key = tls_validation_cache_key(crate::tls::source::MaterialKind::Key, path);
            let already_validated = validated_tls_paths.contains(&cache_key);
            if !already_validated {
                if let Err(e) = validate_pem_key_file("backend_tls_client_key_path", path) {
                    errors.push(e);
                } else {
                    validated_tls_paths.insert(cache_key);
                }
            }
        }
        if let Some(ref path) = self.backend_tls_server_ca_cert_path {
            let cache_key =
                tls_validation_cache_key(crate::tls::source::MaterialKind::CaBundle, path);
            let already_validated = validated_tls_paths.contains(&cache_key);
            if !already_validated {
                if let Err(e) = validate_pem_ca_file("backend_tls_server_ca_cert_path", path) {
                    errors.push(e);
                } else if let Err(e) = crate::tls::check_cert_expiry_for_validation(
                    path,
                    "backend_tls_server_ca_cert_path",
                    cert_expiry_warning_days,
                ) {
                    errors.push(e);
                } else {
                    validated_tls_paths.insert(cache_key);
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

pub(crate) fn validate_backend_tls_sni(sni: &str) -> Result<(), String> {
    validate_string_field("backend_tls_sni", sni, MAX_HOST_LENGTH)?;
    if sni.trim().is_empty() {
        return Err("backend_tls_sni must not be empty".to_string());
    }
    if sni.trim() != sni {
        return Err("backend_tls_sni must not have leading or trailing whitespace".to_string());
    }
    if sni.contains('*') {
        return Err("backend_tls_sni must be an exact hostname, not a wildcard".to_string());
    }
    // RFC 6066 §3: the SNI host_name MUST NOT be an IP literal. validate_host_entry
    // accepts dotted-digit strings as hostnames, so we reject IP addresses explicitly here.
    if sni.parse::<std::net::IpAddr>().is_ok() {
        return Err(
            "backend_tls_sni must be a DNS hostname, not an IP address (RFC 6066 §3)".to_string(),
        );
    }
    validate_host_entry(&sni.to_ascii_lowercase())
        .map_err(|e| format!("backend_tls_sni is invalid: {}", e))
}

pub(crate) fn validate_backend_tls_san_allow_list_entry(san: &str) -> Result<(), String> {
    validate_string_field("entry", san, MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRY_LENGTH)?;
    if san.trim().is_empty() {
        return Err("entry must not be empty".to_string());
    }
    if san.trim() != san {
        return Err("entry must not have leading or trailing whitespace".to_string());
    }
    if san.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    let spiffe_rest = san.get(..9).and_then(|prefix| {
        if prefix.eq_ignore_ascii_case("spiffe://") {
            Some(&san[9..])
        } else {
            None
        }
    });
    if let Some(rest) = spiffe_rest {
        let has_path = rest
            .find('/')
            .is_some_and(|slash| slash > 0 && slash + 1 < rest.len());
        if !has_path || rest.contains(char::is_whitespace) {
            return Err("entry is invalid: SPIFFE URI must include a non-empty path after the trust domain (e.g. spiffe://domain/ns/default/sa/name)".to_string());
        }
        return Ok(());
    }
    if san.contains("://") {
        return Err("entry is invalid: URI SAN allow-list entries must be SPIFFE URIs".to_string());
    }
    if san.contains('*') {
        return Err("entry must be an exact DNS name, SPIFFE URI, or IP address".to_string());
    }
    validate_host_entry(&san.to_ascii_lowercase()).map_err(|e| format!("entry is invalid: {}", e))
}

pub(crate) fn normalize_backend_tls_san_allow_list_entry(san: &mut String) {
    if san
        .get(..9)
        .is_some_and(|s| s.eq_ignore_ascii_case("spiffe://"))
        || san.parse::<std::net::IpAddr>().is_ok()
    {
        return;
    }
    *san = san.to_ascii_lowercase();
}

impl PluginConfig {
    /// Normalize plugin config fields to their canonical in-memory form.
    pub fn normalize_fields(&mut self) {
        if self
            .proxy_id
            .as_ref()
            .is_some_and(|proxy_id| proxy_id.trim().is_empty())
        {
            self.proxy_id = None;
        }
    }

    /// Validate all fields of a plugin config for correctness and safe lengths.
    pub fn validate_fields(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Plugin name length (should already be validated against known plugins,
        // but enforce a length limit as defense-in-depth)
        if self.plugin_name.trim().is_empty() {
            errors.push("plugin_name must not be empty".to_string());
        }
        if let Err(e) = validate_string_field("plugin_name", &self.plugin_name, MAX_NAME_LENGTH) {
            errors.push(e);
        }

        match self.scope {
            PluginScope::Proxy => match self.proxy_id.as_deref() {
                Some(proxy_id) => {
                    if let Err(e) = validate_resource_id(proxy_id) {
                        errors.push(format!("proxy_id {}", e));
                    }
                }
                None => errors.push("scope 'proxy' requires proxy_id".to_string()),
            },
            PluginScope::Global => {
                if self.proxy_id.is_some() {
                    errors.push("scope 'global' must not have proxy_id".to_string());
                }
            }
            PluginScope::ProxyGroup => {
                if self.proxy_id.is_some() {
                    errors.push("scope 'proxy_group' must not have proxy_id (associations are managed via proxy.plugins)".to_string());
                }
            }
        }

        // `transaction_log_schema` is process-global by design: it registers
        // named schemas into a single global registry, so a proxy / proxy_group
        // scope is meaningless. The runtime rejecting contract shared by database
        // full-loads and CP broadcasts (`GatewayConfig::validate_plugin_references`)
        // already rejects any non-global scope here; enforce the SAME invariant on
        // the admin write path so an operator write fails closed with a clear 4xx
        // at write time instead of admitting a document that every subsequent
        // full-config load then rejects (which flips the DB poll loop to
        // `db_available=false` and wedges the whole admin API read-only).
        if self.plugin_name == "transaction_log_schema" && self.scope != PluginScope::Global {
            errors.push(
                "transaction_log_schema must have scope 'global' (it registers process-global named schemas)"
                    .to_string(),
            );
        }
        if self.plugin_name == "prometheus_metrics" && self.scope != PluginScope::Global {
            errors.push(
                "prometheus_metrics must have scope 'global' (it owns one process-wide registry)"
                    .to_string(),
            );
        }

        // Config JSON size
        let config_json = serde_json::to_string(&self.config).unwrap_or_default();
        let max_config_size = if self.plugin_name == "openapi_validator" {
            MAX_OPENAPI_VALIDATOR_CONFIG_SIZE
        } else {
            MAX_PLUGIN_CONFIG_SIZE
        };
        if config_json.len() > max_config_size {
            errors.push(format!(
                "config JSON must not exceed {} bytes (got {})",
                max_config_size,
                config_json.len()
            ));
        }

        // Config JSON nesting depth
        let max_config_depth = if self.plugin_name == "openapi_validator" {
            MAX_OPENAPI_VALIDATOR_CONFIG_DEPTH
        } else {
            10
        };
        if json_depth(&self.config) > max_config_depth {
            errors.push(format!(
                "config JSON nesting depth must not exceed {}",
                max_config_depth
            ));
        }

        // Priority override range (0–10000 keeps plugins within sane ordering bands)
        if let Some(p) = self.priority_override
            && p > 10000
        {
            errors.push(format!(
                "priority_override must be between 0 and 10000 (got {})",
                p
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl CircuitBreakerConfig {
    /// Validate circuit breaker configuration fields.
    pub fn validate_fields(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if let Err(e) = validate_u32_range(
            "failure_threshold",
            self.failure_threshold,
            1,
            MAX_THRESHOLD,
        ) {
            errors.push(e);
        }
        if let Err(e) = validate_u32_range(
            "success_threshold",
            self.success_threshold,
            1,
            MAX_THRESHOLD,
        ) {
            errors.push(e);
        }
        if let Err(e) = validate_u64_range(
            "timeout_seconds",
            self.timeout_seconds,
            1,
            MAX_TIMEOUT_SECONDS,
        ) {
            errors.push(e);
        }
        if let Err(e) = validate_u32_range(
            "half_open_max_requests",
            self.half_open_max_requests,
            1,
            MAX_THRESHOLD,
        ) {
            errors.push(e);
        }
        if let Err(e) = validate_status_codes("failure_status_codes", &self.failure_status_codes) {
            errors.push(e);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl RetryConfig {
    /// Validate retry configuration fields.
    pub fn validate_fields(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if let Err(e) = validate_u32_range("max_retries", self.max_retries, 0, MAX_RETRIES) {
            errors.push(e);
        }
        if let Err(e) =
            validate_status_codes("retryable_status_codes", &self.retryable_status_codes)
        {
            errors.push(e);
        }
        if self.retryable_methods.len() > MAX_RETRYABLE_METHODS {
            errors.push(format!(
                "retryable_methods must not have more than {} entries (got {})",
                MAX_RETRYABLE_METHODS,
                self.retryable_methods.len()
            ));
        }
        for method in &self.retryable_methods {
            let upper = method.to_uppercase();
            if !VALID_HTTP_METHODS.contains(&upper.as_str()) {
                errors.push(format!(
                    "retryable_methods contains invalid HTTP method: {}",
                    method
                ));
            }
        }

        // Validate backoff
        match &self.backoff {
            BackoffStrategy::Fixed { delay_ms } => {
                if *delay_ms > MAX_BACKOFF_MS {
                    errors.push(format!(
                        "backoff.delay_ms must not exceed {} (got {})",
                        MAX_BACKOFF_MS, delay_ms
                    ));
                }
            }
            BackoffStrategy::Exponential { base_ms, max_ms } => {
                if *base_ms > MAX_BACKOFF_MS {
                    errors.push(format!(
                        "backoff.base_ms must not exceed {} (got {})",
                        MAX_BACKOFF_MS, base_ms
                    ));
                }
                if *max_ms > MAX_BACKOFF_MS {
                    errors.push(format!(
                        "backoff.max_ms must not exceed {} (got {})",
                        MAX_BACKOFF_MS, max_ms
                    ));
                }
                if *base_ms > *max_ms {
                    errors.push(format!(
                        "backoff.base_ms ({}) must not exceed backoff.max_ms ({})",
                        base_ms, max_ms
                    ));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl HealthCheckConfig {
    /// Validate health check configuration fields.
    pub fn validate_fields(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if let Some(ref active) = self.active {
            if let Err(e) = validate_string_field(
                "active.http_path",
                &active.http_path,
                MAX_BACKEND_PATH_LENGTH,
            ) {
                errors.push(e);
            }
            if let Err(e) = validate_u64_range(
                "active.interval_seconds",
                active.interval_seconds,
                1,
                MAX_HEALTH_CHECK_INTERVAL,
            ) {
                errors.push(e);
            }
            if let Err(e) =
                validate_u64_range("active.timeout_ms", active.timeout_ms, 1, MAX_TIMEOUT_MS)
            {
                errors.push(e);
            }
            if let Err(e) = validate_u32_range(
                "active.healthy_threshold",
                active.healthy_threshold,
                1,
                MAX_THRESHOLD,
            ) {
                errors.push(e);
            }
            if let Err(e) = validate_u32_range(
                "active.unhealthy_threshold",
                active.unhealthy_threshold,
                1,
                MAX_THRESHOLD,
            ) {
                errors.push(e);
            }
            if let Err(e) =
                validate_status_codes("active.healthy_status_codes", &active.healthy_status_codes)
            {
                errors.push(e);
            }
            if let Some(ref payload) = active.udp_probe_payload
                && let Err(e) = validate_string_field("active.udp_probe_payload", payload, 2048)
            {
                errors.push(e);
            }
        }

        if let Some(ref passive) = self.passive {
            if let Err(e) = validate_status_codes(
                "passive.unhealthy_status_codes",
                &passive.unhealthy_status_codes,
            ) {
                errors.push(e);
            }
            if let Err(e) = validate_u32_range(
                "passive.unhealthy_threshold",
                passive.unhealthy_threshold,
                1,
                MAX_RECENT_FAILURES_PER_TARGET as u32,
            ) {
                errors.push(e);
            }
            if let Err(e) = validate_u64_range(
                "passive.unhealthy_window_seconds",
                passive.unhealthy_window_seconds,
                1,
                MAX_TIMEOUT_SECONDS,
            ) {
                errors.push(e);
            }
            // healthy_after_seconds can be 0 (disabled), so min is 0
            if let Err(e) = validate_u64_range(
                "passive.healthy_after_seconds",
                passive.healthy_after_seconds,
                0,
                MAX_TIMEOUT_SECONDS,
            ) {
                errors.push(e);
            }
            // max_ejection_percent: 0-100
            if let Some(pct) = passive.max_ejection_percent
                && pct > 100
            {
                errors.push(format!(
                    "passive.max_ejection_percent must be between 0 and 100 (got {})",
                    pct
                ));
            }
            // gateway_error_codes: valid HTTP status codes
            if let Some(ref codes) = passive.gateway_error_codes
                && let Err(e) = validate_status_codes("passive.gateway_error_codes", codes)
            {
                errors.push(e);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl ServiceDiscoveryConfig {
    /// Validate service discovery configuration fields.
    ///
    /// `upstream_namespace` is the owning upstream's namespace; mesh SD
    /// namespace must match it to prevent cross-namespace workload reference.
    pub fn validate_fields(&self, upstream_namespace: &str) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.default_weight == 0 || self.default_weight > MAX_TARGET_WEIGHT {
            errors.push(format!(
                "default_weight must be between 1 and {} (got {})",
                MAX_TARGET_WEIGHT, self.default_weight
            ));
        }

        match self.provider {
            SdProvider::DnsSd => {
                if let Some(ref dns_sd) = self.dns_sd {
                    if let Err(e) = validate_string_field(
                        "dns_sd.service_name",
                        &dns_sd.service_name,
                        MAX_NAME_LENGTH,
                    ) {
                        errors.push(e);
                    }
                    if dns_sd.service_name.is_empty() {
                        errors.push("dns_sd.service_name must not be empty".to_string());
                    }
                    if let Err(e) = validate_u64_range(
                        "dns_sd.poll_interval_seconds",
                        dns_sd.poll_interval_seconds,
                        1,
                        MAX_SD_POLL_INTERVAL,
                    ) {
                        errors.push(e);
                    }
                } else {
                    errors.push("dns_sd config is required when provider is dns_sd".to_string());
                }
            }
            SdProvider::Kubernetes => {
                if let Some(ref k8s) = self.kubernetes {
                    if let Err(e) = validate_string_field(
                        "kubernetes.namespace",
                        &k8s.namespace,
                        MAX_NAME_LENGTH,
                    ) {
                        errors.push(e);
                    }
                    if let Err(e) = validate_string_field(
                        "kubernetes.service_name",
                        &k8s.service_name,
                        MAX_NAME_LENGTH,
                    ) {
                        errors.push(e);
                    }
                    if k8s.service_name.is_empty() {
                        errors.push("kubernetes.service_name must not be empty".to_string());
                    }
                    if let Some(ref port_name) = k8s.port_name
                        && let Err(e) = validate_string_field(
                            "kubernetes.port_name",
                            port_name,
                            MAX_SD_STRING_LENGTH,
                        )
                    {
                        errors.push(e);
                    }
                    if let Some(ref label_selector) = k8s.label_selector
                        && let Err(e) =
                            validate_string_field("kubernetes.label_selector", label_selector, 1024)
                    {
                        errors.push(e);
                    }
                    if let Err(e) = validate_u64_range(
                        "kubernetes.poll_interval_seconds",
                        k8s.poll_interval_seconds,
                        1,
                        MAX_SD_POLL_INTERVAL,
                    ) {
                        errors.push(e);
                    }
                } else {
                    errors.push(
                        "kubernetes config is required when provider is kubernetes".to_string(),
                    );
                }
            }
            SdProvider::Consul => {
                if let Some(ref consul) = self.consul {
                    if let Err(e) = validate_string_field(
                        "consul.address",
                        &consul.address,
                        MAX_BACKEND_PATH_LENGTH,
                    ) {
                        errors.push(e);
                    }
                    if consul.address.is_empty() {
                        errors.push("consul.address must not be empty".to_string());
                    }
                    if let Err(e) = validate_string_field(
                        "consul.service_name",
                        &consul.service_name,
                        MAX_NAME_LENGTH,
                    ) {
                        errors.push(e);
                    }
                    if consul.service_name.is_empty() {
                        errors.push("consul.service_name must not be empty".to_string());
                    }
                    if let Some(ref dc) = consul.datacenter
                        && let Err(e) =
                            validate_string_field("consul.datacenter", dc, MAX_SD_STRING_LENGTH)
                    {
                        errors.push(e);
                    }
                    if let Some(ref tag) = consul.tag
                        && let Err(e) =
                            validate_string_field("consul.tag", tag, MAX_SD_STRING_LENGTH)
                    {
                        errors.push(e);
                    }
                    if let Some(ref token) = consul.token
                        && let Err(e) = validate_string_field(
                            "consul.token",
                            token,
                            MAX_CREDENTIAL_VALUE_LENGTH,
                        )
                    {
                        errors.push(e);
                    }
                    if let Err(e) = validate_u64_range(
                        "consul.poll_interval_seconds",
                        consul.poll_interval_seconds,
                        1,
                        MAX_SD_POLL_INTERVAL,
                    ) {
                        errors.push(e);
                    }
                } else {
                    errors.push("consul config is required when provider is consul".to_string());
                }
            }
            SdProvider::Mesh => {
                if let Some(ref mesh) = self.mesh {
                    if let Err(e) = validate_string_field(
                        "mesh.service_name",
                        &mesh.service_name,
                        MAX_NAME_LENGTH,
                    ) {
                        errors.push(e);
                    }
                    if mesh.service_name.is_empty() {
                        errors.push("mesh.service_name must not be empty".to_string());
                    }
                    if let Some(ref namespace) = mesh.namespace {
                        if let Err(e) =
                            validate_string_field("mesh.namespace", namespace, MAX_NAMESPACE_LENGTH)
                        {
                            errors.push(e);
                        }
                        if namespace.is_empty() {
                            errors.push("mesh.namespace must not be empty".to_string());
                        } else if namespace != upstream_namespace {
                            errors.push(format!(
                                "mesh.namespace '{}' must match the upstream's namespace '{}' \
                                 to prevent cross-namespace workload reference",
                                namespace, upstream_namespace
                            ));
                        }
                    }
                    if let Some(port) = mesh.port
                        && port == 0
                    {
                        errors.push("mesh.port must be between 1 and 65535".to_string());
                    }
                    if let Err(e) = validate_u64_range(
                        "mesh.poll_interval_seconds",
                        mesh.poll_interval_seconds,
                        1,
                        MAX_SD_POLL_INTERVAL,
                    ) {
                        errors.push(e);
                    }
                } else {
                    errors.push("mesh config is required when provider is mesh".to_string());
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl GatewayConfig {
    /// Validate all field-level constraints across every resource in the config.
    ///
    /// This validates individual field values (lengths, ranges, formats) — not
    /// cross-resource constraints like uniqueness or FK references, which are
    /// handled by the existing `validate_*` methods.
    ///
    /// `cert_expiry_warning_days` controls the near-expiry warning threshold
    /// for TLS certificate files. Expired certificates are always rejected.
    pub fn validate_all_fields(&self, cert_expiry_warning_days: u64) -> Result<(), Vec<String>> {
        self.validate_all_fields_with_ip_policy(
            cert_expiry_warning_days,
            &crate::config::BackendEgressPolicy::unrestricted(),
        )
    }

    /// Validate all fields with backend IP policy enforcement.
    pub fn validate_all_fields_with_ip_policy(
        &self,
        cert_expiry_warning_days: u64,
        backend_allow_ips: &crate::config::BackendEgressPolicy,
    ) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Shared cache: when multiple proxies reference the same TLS file path,
        // each file is opened and parsed only once during batch validation.
        let mut validated_tls_paths = std::collections::HashSet::new();
        for proxy in &self.proxies {
            if let Err(errs) =
                proxy.validate_fields_with_cache(&mut validated_tls_paths, cert_expiry_warning_days)
            {
                for e in errs {
                    errors.push(format!("Proxy '{}': {}", proxy.id, e));
                }
            }
        }
        for consumer in &self.consumers {
            if let Err(errs) = consumer.validate_fields() {
                for e in errs {
                    errors.push(format!("Consumer '{}': {}", consumer.id, e));
                }
            }
        }
        for upstream in &self.upstreams {
            if let Err(errs) = upstream
                .validate_fields_with_cache(&mut validated_tls_paths, cert_expiry_warning_days)
            {
                for e in errs {
                    errors.push(format!("Upstream '{}': {}", upstream.id, e));
                }
            }
        }
        for pc in &self.plugin_configs {
            if let Err(errs) = pc.validate_fields() {
                for e in errs {
                    errors.push(format!("PluginConfig '{}': {}", pc.id, e));
                }
            }
        }

        // SSRF: validate literal IP backend_host / upstream target host values.
        // Skipped only when the policy can never deny anything (fully open).
        if !backend_allow_ips.is_fully_open() {
            for proxy in &self.proxies {
                if let Err(errs) = proxy.validate_backend_egress_ips(backend_allow_ips) {
                    for e in errs {
                        errors.push(format!("Proxy '{}': {}", proxy.id, e));
                    }
                }
                // A hostname `dns_override` cannot be classified at config time;
                // it is screened at DNS-resolution time instead.
                if let Some(ref dns_override) = proxy.dns_override
                    && dns_override.parse::<std::net::IpAddr>().is_err()
                {
                    tracing::warn!(
                        "Proxy '{}': dns_override '{}' is not an IP address, so startup cannot classify it under the backend egress policy ({})",
                        proxy.id,
                        dns_override,
                        backend_allow_ips
                    );
                }
            }
            for upstream in &self.upstreams {
                if let Err(errs) = upstream.validate_backend_egress_ips(backend_allow_ips) {
                    for e in errs {
                        errors.push(format!("Upstream '{}': {}", upstream.id, e));
                    }
                }
            }
            for plugin in &self.plugin_configs {
                if !plugin.enabled || plugin.plugin_name != "mesh_route_dispatch" {
                    continue;
                }
                if let Err(errs) = crate::plugins::screen_mesh_route_dispatch_egress(
                    &plugin.config,
                    backend_allow_ips,
                ) {
                    for e in errs {
                        errors.push(format!("PluginConfig '{}' {}", plugin.id, e));
                    }
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Reject mesh-PROJECTED upstream fields on operator-PROVIDED config loads.
    ///
    /// `Upstream.{port_overrides, source_locality, locality_lb_strict,
    /// locality_lb_setting}` and mesh-only fields under
    /// `Upstream.subsets[].traffic_policy` are owned by the mesh slice-apply layer
    /// (Destination rules / workload locality /
    /// `FERRUM_MESH_LOCALITY_LB_STRICT`); an operator must never set them directly.
    /// This is the config-wide wrapper over
    /// [`Upstream::validate_operator_provided_fields`] that the **file-mode loader**
    /// runs so an operator-authored YAML/JSON upstream cannot smuggle in strict
    /// locality / DR-derived policy (none of these fields are persisted, so they
    /// would silently vanish on reload, or worse, briefly take effect).
    ///
    /// It is deliberately SEPARATE from [`Self::validate_all_fields_with_ip_policy`]
    /// (and is NOT part of the shared validation pipeline): the mesh slice-apply
    /// path legitimately PROJECTS these fields and must keep applying clean, so
    /// only operator entry points call this — file mode here, the admin API per
    /// resource on POST/PUT/import/restore.
    pub fn validate_operator_provided_fields(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        for upstream in &self.upstreams {
            if let Err(errs) = upstream.validate_operator_provided_fields() {
                for e in errs {
                    errors.push(format!("Upstream '{}': {}", upstream.id, e));
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate the mesh portion of the config (Layer 2 — Phase A).
    ///
    /// Returns a flat `Vec<String>` of error messages so each mode can
    /// dispatch the result per its own policy:
    /// - **File mode**: fatal (bail)
    /// - **DB mode**: warn (data already in DB)
    /// - **DP mode**: reject the update, keep the cached config
    ///
    /// This is separate from `validate_all_fields_with_ip_policy()` so the
    /// mesh fields can fail independently — operators may want to
    /// experiment with mesh resources in dev without bricking their
    /// existing proxy config.
    #[allow(dead_code)] // Phase A scaffolding — wired into modes in Phase B/C.
    pub fn validate_mesh_fields(&self) -> Vec<String> {
        match &self.mesh {
            Some(m) => m.validate(),
            None => Vec::new(),
        }
    }

    /// Normalise hostname-bearing mesh fields (lower-case ASCII). Idempotent.
    #[allow(dead_code)] // Phase A scaffolding — wired into loaders in Phase B/C.
    pub fn normalize_mesh_fields(&mut self) {
        if let Some(m) = &mut self.mesh {
            m.normalize();
        }
    }

    /// Validate file dependencies for plugins that reference external files
    /// (e.g., geo_restriction `.mmdb` databases, `body_validator` and
    /// `ai_response_guard` protobuf descriptors, and `udp_logging` DTLS
    /// sources).
    ///
    /// This is separate from `validate_all_fields_with_ip_policy()` so that
    /// each mode can handle missing files independently:
    /// - **File mode**: fatal (bail)
    /// - **DB mode**: warn (data already in DB)
    /// - **DP mode**: validate full snapshots and affected incremental rebuilds
    ///   off the runtime worker. Readable-invalid descriptor dependencies
    ///   reject construction and retain the live generation; absent/unreadable
    ///   descriptors keep enrollment and fail closed at request time for
    ///   enforcing actions rather than rejecting the DP update solely for
    ///   absence.
    ///
    /// Deduplicates paths so each file is read at most once. Enabled
    /// `udp_logging` DTLS validation caches by the full validation-input tuple
    /// (host / no_verify / source paths) so identical rows share one
    /// materialization while still attaching errors per PluginConfig id.
    /// `body_validator` and `ai_response_guard` share one descriptor-pool cache
    /// keyed by path so a descriptor used by both families is decoded once;
    /// diagnostics remain plugin-prefixed and never include path or body bytes.
    pub fn validate_plugin_file_dependencies(&self) -> Vec<String> {
        self.validate_plugin_file_dependencies_inner(None)
    }

    pub(crate) fn country_mmdb_file_dependency_paths(&self) -> HashSet<PathBuf> {
        self.plugin_configs
            .iter()
            .filter(|plugin| plugin.enabled && plugin.plugin_name == "geo_restriction")
            .filter_map(|plugin| {
                plugin
                    .config
                    .get("db_path")
                    .and_then(serde_json::Value::as_str)
            })
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .collect()
    }

    pub(crate) fn validate_plugin_file_dependencies_for_generation(
        &self,
        generation: &CountryMmdbValidationGeneration,
    ) -> Vec<String> {
        self.validate_plugin_file_dependencies_inner(Some(generation))
    }

    fn validate_plugin_file_dependencies_inner(
        &self,
        generation: Option<&CountryMmdbValidationGeneration>,
    ) -> Vec<String> {
        let mut errors = Vec::new();
        let mut validated_paths = std::collections::HashSet::new();
        // Shared across body_validator and ai_response_guard so a path used by
        // both families is read and decoded at most once per pass.
        let mut protobuf_descriptor_cache = std::collections::HashMap::<
            String,
            Result<prost_reflect::DescriptorPool, SharedProtobufDescriptorLoadError>,
        >::new();
        let mut reported_body_validator_path_errors = std::collections::HashSet::new();
        let mut reported_guard_path_errors = std::collections::HashSet::new();
        // Identical enabled UDP DTLS validation inputs share one materialization
        // (provider/file read) per pass; cached errors are still attached to
        // each affected PluginConfig id.
        let mut udp_dtls_cache = std::collections::HashMap::new();
        for pc in &self.plugin_configs {
            if !pc.enabled {
                continue;
            }
            if pc.plugin_name == "geo_restriction"
                && let Some(db_path) = pc.config.get("db_path").and_then(|v| v.as_str())
                && let db_path = db_path.trim()
                && !db_path.is_empty()
                && validated_paths.insert(db_path.to_string())
                && let Err(e) = match generation {
                    Some(generation) => validate_mmdb_file_for_generation(
                        "geo_restriction.db_path",
                        db_path,
                        generation,
                    ),
                    None => validate_mmdb_file("geo_restriction.db_path", db_path),
                }
            {
                errors.push(format!("PluginConfig '{}': {}", pc.id, e));
            }
            if pc.plugin_name == "body_validator" {
                match crate::plugins::body_validator::protobuf_descriptor_path(&pc.config) {
                    Ok(Some(path)) => {
                        let cached = protobuf_descriptor_cache
                            .entry(path.to_string())
                            .or_insert_with(|| load_shared_protobuf_descriptor_pool(path));
                        match cached {
                            Ok(pool) => {
                                if let Err(error) =
                                    crate::plugins::body_validator::validate_protobuf_descriptor_config(
                                        &pc.config,
                                        pool,
                                    )
                                {
                                    errors.push(format!("PluginConfig '{}': {}", pc.id, error));
                                }
                            }
                            Err(error)
                                if reported_body_validator_path_errors.insert(path.to_string()) =>
                            {
                                errors.push(format!(
                                    "PluginConfig '{}': {}",
                                    pc.id,
                                    error.body_validator_message()
                                ));
                            }
                            Err(_) => {}
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        errors.push(format!("PluginConfig '{}': {}", pc.id, error));
                    }
                }
            }
            if pc.plugin_name == "ai_response_guard" {
                use crate::plugins::ai_response_guard as guard;
                match guard::grpc_descriptor_path(&pc.config) {
                    Ok(Some(path)) => {
                        let cached = protobuf_descriptor_cache
                            .entry(path.clone())
                            .or_insert_with(|| load_shared_protobuf_descriptor_pool(&path));
                        match cached {
                            Ok(pool) => {
                                if let Err(error) =
                                    guard::validate_grpc_descriptor_config(&pc.config, pool)
                                {
                                    errors.push(format!("PluginConfig '{}': {}", pc.id, error));
                                }
                            }
                            Err(error) if reported_guard_path_errors.insert(path.clone()) => {
                                errors.push(format!(
                                    "PluginConfig '{}': {}",
                                    pc.id,
                                    error.ai_response_guard_message()
                                ));
                            }
                            Err(_) => {}
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        errors.push(format!("PluginConfig '{}': {}", pc.id, error));
                    }
                }
            }
            if pc.plugin_name == "mesh_route_dispatch"
                && let Some(rules) = pc.config.get("rules").and_then(serde_json::Value::as_array)
            {
                for (rule_idx, rule) in rules.iter().enumerate() {
                    let Some(backend_tls) = rule
                        .get("destination")
                        .and_then(|destination| destination.get("backend_tls"))
                        .and_then(serde_json::Value::as_object)
                    else {
                        continue;
                    };
                    let client_cert = backend_tls
                        .get("client_cert_path")
                        .and_then(serde_json::Value::as_str);
                    let client_key = backend_tls
                        .get("client_key_path")
                        .and_then(serde_json::Value::as_str);
                    let server_ca = backend_tls
                        .get("server_ca_cert_path")
                        .and_then(serde_json::Value::as_str);
                    for (field, path) in [
                        ("client_cert_path", client_cert),
                        ("client_key_path", client_key),
                        ("server_ca_cert_path", server_ca),
                    ] {
                        if path.is_some_and(str::is_empty) {
                            errors.push(format!(
                                "PluginConfig '{}': mesh_route_dispatch.rules[{}].destination.backend_tls.{} must not be empty",
                                pc.id, rule_idx, field
                            ));
                        }
                    }
                    let client_cert = client_cert.filter(|path| !path.is_empty());
                    let client_key = client_key.filter(|path| !path.is_empty());
                    match (client_cert, client_key) {
                        (Some(_), None) => errors.push(format!(
                            "PluginConfig '{}': mesh_route_dispatch.rules[{}].destination.backend_tls.client_cert_path is set but client_key_path is missing",
                            pc.id, rule_idx
                        )),
                        (None, Some(_)) => errors.push(format!(
                            "PluginConfig '{}': mesh_route_dispatch.rules[{}].destination.backend_tls.client_key_path is set but client_cert_path is missing",
                            pc.id, rule_idx
                        )),
                        _ => {}
                    }
                    if let Some(path) = client_cert {
                        let cache_key =
                            tls_validation_cache_key(crate::tls::source::MaterialKind::Cert, path);
                        if validated_paths.insert(cache_key)
                            && let Err(e) = validate_pem_cert_file(
                                "mesh_route_dispatch.backend_tls.client_cert_path",
                                path,
                            )
                        {
                            errors.push(format!("PluginConfig '{}': {}", pc.id, e));
                        }
                    }
                    if let Some(path) = client_key {
                        let cache_key =
                            tls_validation_cache_key(crate::tls::source::MaterialKind::Key, path);
                        if validated_paths.insert(cache_key)
                            && let Err(e) = validate_pem_key_file(
                                "mesh_route_dispatch.backend_tls.client_key_path",
                                path,
                            )
                        {
                            errors.push(format!("PluginConfig '{}': {}", pc.id, e));
                        }
                    }
                    if let Some(path) = server_ca.filter(|path| !path.is_empty()) {
                        let cache_key = tls_validation_cache_key(
                            crate::tls::source::MaterialKind::CaBundle,
                            path,
                        );
                        if validated_paths.insert(cache_key)
                            && let Err(e) = validate_pem_ca_file(
                                "mesh_route_dispatch.backend_tls.server_ca_cert_path",
                                path,
                            )
                        {
                            errors.push(format!("PluginConfig '{}': {}", pc.id, e));
                        }
                    }
                }
            }
            if pc.plugin_name == "udp_logging"
                && let Some(config) = pc.config.as_object()
                && let Err(e) = crate::plugins::udp_logging::validate_dtls_file_dependencies_cached(
                    config,
                    &mut udp_dtls_cache,
                )
            {
                // Attach the (possibly cached) error to each PluginConfig row.
                let message = format!("PluginConfig '{}': {}", pc.id, e);
                if !errors.iter().any(|existing| existing == &message) {
                    errors.push(message);
                }
            }
        }
        errors
    }
}

/// Compute the maximum nesting depth of a JSON value.
pub(crate) fn json_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Array(arr) => 1 + arr.iter().map(json_depth).max().unwrap_or(0),
        serde_json::Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

/// Check if a wildcard pattern matches a hostname.
/// `*.example.com` matches any DNS name below `example.com`, including
/// `foo.example.com` and `a.b.example.com`, but not `example.com` itself.
pub fn wildcard_matches(pattern: &str, hostname: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Don't match the base domain itself
        if hostname == suffix {
            return false;
        }
        hostname
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
    } else {
        pattern == hostname
    }
}

#[cfg(all(test, not(feature = "pkcs11")))]
mod pkcs11_key_validation_tests {
    use super::*;

    #[test]
    fn backend_pkcs11_key_validation_requires_feature() {
        let error = validate_pem_key_file(
            "backend_tls_client_key_path",
            "pkcs11://edge-rsa?module=/usr/lib/pkcs11.so",
        )
        .expect_err("pkcs11 key sources require the feature");

        assert!(error.contains("'pkcs11' Cargo feature"));
    }
}
