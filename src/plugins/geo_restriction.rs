//! GeoIP Restriction Plugin
//!
//! Allows or denies requests based on the geographic location of the client IP
//! address. Uses MaxMind GeoIP2/GeoLite2 `.mmdb` database files for IP-to-country
//! lookups.
//!
//! Supports:
//! - Country allow/deny lists (ISO 3166-1 alpha-2 codes)
//! - Optional geographic header injection (`X-Geo-Country`)
//! - Configurable default action when IP lookup fails (defaults to `allow`,
//!   i.e. fail-open — see `on_lookup_failure`)
//!
//! The `.mmdb` file is loaded into an owned immutable byte buffer at plugin
//! construction. This keeps live readers safe from external in-place database
//! rewrites or truncation while retaining zero-copy decoding from the in-memory
//! buffer. The complete database and its country record shape are verified
//! before publication, and each validation/load session bounds the aggregate
//! declared size of its distinct MMDB paths. If the file is unavailable at
//! construction time on a runtime node, the plugin degrades gracefully and
//! lookups use `on_lookup_failure`; a readable but invalid database is rejected.
//!
//! Every decision stamps two fixed-grammar metadata values for transaction
//! logs — [`GEO_DECISION_METADATA_KEY`] (one of seven reasons) and, when a
//! country was resolved, [`GEO_COUNTRY_METADATA_KEY`] (an ISO 3166-1 alpha-2
//! code) — on both the HTTP and the stream hook. Both names are on the
//! built-in log allowlist
//! (`crate::plugins::utils::metadata_redaction::BUILTIN_SAFE_METADATA_KEYS`).
//! Construction logs the loaded database's build date and age so a stale
//! `.mmdb` is visible at every load and reload.

use crate::plugins::utils::log_sampling::warn_sampled;

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, warn};

use super::{Plugin, PluginResult, RequestContext};
use crate::config::types::{
    CountryMmdbLoadError, CountryMmdbLoadSession, CountryMmdbSnapshot, SUPPORTED_GEO_COUNTRY_CODES,
    load_validated_country_mmdb,
};

const GEO_COUNTRY_HEADER: &str = "x-geo-country";

/// Metadata key carrying the decision reason for this request or stream
/// session: `allowed`, `country_not_allowed`, `country_denied`,
/// `lookup_failed_allowed`, `lookup_failed_denied`, `db_not_loaded_allowed`, or
/// `db_not_loaded_denied`. Fixed cardinality, so it is log-allowlisted.
pub const GEO_DECISION_METADATA_KEY: &str = "geo.decision";

/// Metadata key carrying the resolved ISO 3166-1 alpha-2 country code, on
/// admitted and rejected requests alike. Absent when no country was resolved.
pub const GEO_COUNTRY_METADATA_KEY: &str = "geo.country";

/// A `.mmdb` older than this is reported at `warn` when it is loaded. MaxMind
/// republishes its country databases weekly.
const STALE_DATABASE_AGE_DAYS: u64 = 30;

/// Why `check_ip` decided the way it did. The `as_str` set is the closed value
/// grammar of [`GEO_DECISION_METADATA_KEY`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GeoDecision {
    Allowed,
    CountryNotAllowed,
    CountryDenied,
    LookupFailedAllowed,
    LookupFailedDenied,
    DbNotLoadedAllowed,
    DbNotLoadedDenied,
}

impl GeoDecision {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::CountryNotAllowed => "country_not_allowed",
            Self::CountryDenied => "country_denied",
            Self::LookupFailedAllowed => "lookup_failed_allowed",
            Self::LookupFailedDenied => "lookup_failed_denied",
            Self::DbNotLoadedAllowed => "db_not_loaded_allowed",
            Self::DbNotLoadedDenied => "db_not_loaded_denied",
        }
    }
}

/// One `check_ip` verdict: the plugin result, the resolved country (when
/// any), and the decision reason for metadata.
struct GeoVerdict {
    result: PluginResult,
    country: Option<CountryCode>,
    decision: GeoDecision,
}
const CONFIG_KEYS: &[&str] = &[
    "db_path",
    "allow_countries",
    "deny_countries",
    "inject_headers",
    "on_lookup_failure",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CountryCode(u16);

impl CountryCode {
    fn parse(value: &str) -> Option<Self> {
        let bytes = value.as_bytes();
        if bytes.len() != 2 || !bytes.iter().all(u8::is_ascii_alphabetic) {
            return None;
        }
        Some(Self(
            ((bytes[0].to_ascii_uppercase() as u16) << 8) | bytes[1].to_ascii_uppercase() as u16,
        ))
    }

    fn bytes(self) -> [u8; 2] {
        [(self.0 >> 8) as u8, self.0 as u8]
    }

    fn is_supported(self) -> bool {
        let code = self.bytes();
        SUPPORTED_GEO_COUNTRY_CODES
            .as_chunks::<2>()
            .0
            .contains(&code)
    }

    fn bit_index(self) -> usize {
        let [first, second] = self.bytes();
        usize::from(first - b'A') * 26 + usize::from(second - b'A')
    }

    fn into_string(self) -> String {
        let [first, second] = self.bytes();
        let mut value = String::with_capacity(2);
        value.push(first as char);
        value.push(second as char);
        value
    }
}

impl std::fmt::Display for CountryCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let [first, second] = self.bytes();
        write!(formatter, "{}{}", first as char, second as char)
    }
}

#[derive(Default)]
struct CountrySet {
    bits: [u64; 11],
    len: usize,
}

impl CountrySet {
    fn insert(&mut self, country: CountryCode) {
        let bit_index = country.bit_index();
        let word = bit_index / u64::BITS as usize;
        let mask = 1_u64 << (bit_index % u64::BITS as usize);
        if self.bits[word] & mask == 0 {
            self.bits[word] |= mask;
            self.len += 1;
        }
    }

    fn contains(&self, country: CountryCode) -> bool {
        let bit_index = country.bit_index();
        let word = bit_index / u64::BITS as usize;
        let mask = 1_u64 << (bit_index % u64::BITS as usize);
        self.bits[word] & mask != 0
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Action when GeoIP lookup fails (IP not in database).
#[derive(Debug, Clone, PartialEq, Eq)]
enum LookupFailureAction {
    Allow,
    Deny,
}

pub struct GeoRestriction {
    reader: Option<Arc<CountryMmdbSnapshot>>,
    db_path: String,
    /// Packed ISO country-code bitsets keep membership checks allocation-free.
    allow_countries: CountrySet,
    deny_countries: CountrySet,
    inject_headers: bool,
    on_lookup_failure: LookupFailureAction,
    /// Set once the first request-time fail-open (lookup failed but policy is
    /// Allow) has been logged at warn level, so subsequent occurrences drop to
    /// debug and do not flood logs on the hot path.
    fail_open_warned: AtomicBool,
}

struct GeoRestrictionConfig {
    db_path: String,
    allow_countries: CountrySet,
    deny_countries: CountrySet,
    inject_headers: bool,
    on_lookup_failure: LookupFailureAction,
    on_lookup_failure_explicit: bool,
}

impl GeoRestriction {
    pub fn new(config: &Value) -> Result<Self, String> {
        Self::new_with_loader(config, load_validated_country_mmdb)
    }

    pub(crate) fn new_with_load_session(
        config: &Value,
        load_session: &CountryMmdbLoadSession,
    ) -> Result<Self, String> {
        Self::new_with_loader(config, |path| load_session.load(path))
    }

    /// Validate only the JSON policy shape. Node-local MMDB I/O belongs to the
    /// mode-aware plugin-file dependency stage, which deduplicates paths and
    /// hands validated snapshots to the real cache build.
    pub(crate) fn validate_config(config: &Value) -> Result<(), String> {
        parse_config(config).map(|_| ())
    }

    fn new_with_loader(
        config: &Value,
        loader: impl FnOnce(&str) -> Result<Arc<CountryMmdbSnapshot>, CountryMmdbLoadError>,
    ) -> Result<Self, String> {
        let GeoRestrictionConfig {
            db_path,
            allow_countries,
            deny_countries,
            inject_headers,
            on_lookup_failure,
            on_lookup_failure_explicit,
        } = parse_config(config)?;

        // Nudge operators toward an explicit failure policy. When
        // `on_lookup_failure` is omitted it defaults to `allow` (fail-open):
        // any IP that cannot be resolved — not in the DB, unparseable, or a
        // missing/stale .mmdb — is permitted. For an access-control plugin
        // that silently disables the geo gate, so surface the default once at
        // construction so it is a conscious choice.
        if !on_lookup_failure_explicit && on_lookup_failure == LookupFailureAction::Allow {
            warn!(
                plugin = "geo_restriction",
                "`on_lookup_failure` is not set; defaulting to `allow` (fail-open) — \
                 unresolved IPs and a missing/stale .mmdb will be permitted. Set \
                 `on_lookup_failure` explicitly (`allow` or `deny`) to silence this warning"
            );
        }

        // A missing or unreadable node-local dependency remains a supported
        // fallback condition. Once bytes are readable, however, corruption,
        // product mismatch, and incompatible records reject the generation.
        let reader = match loader(&db_path) {
            Ok(reader) => {
                log_database_freshness(&reader);
                Some(reader)
            }
            Err(CountryMmdbLoadError::Unavailable(error)) => {
                // The loader Debug-quotes the path around native filesystem
                // errors, so cause sanitization retains the I/O stage/reason.
                warn!(
                    db_path = %crate::startup::sanitize_startup_scalar(&db_path),
                    error = %crate::startup::sanitize_startup_cause(&error, &[]),
                    plugin = "geo_restriction",
                    "MaxMind database file not available — plugin will use on_lookup_failure policy until file is present"
                );
                None
            }
            Err(CountryMmdbLoadError::Invalid(error)) => {
                return Err(format!("geo_restriction: invalid `db_path`: {error}"));
            }
        };

        Ok(Self {
            reader,
            db_path,
            allow_countries,
            deny_countries,
            inject_headers,
            on_lookup_failure,
            fail_open_warned: AtomicBool::new(false),
        })
    }

    /// Log a request-time fail-open (lookup failed, policy is Allow). The first
    /// occurrence is logged at warn so operators get a visible signal that the
    /// geo gate is permitting unresolved traffic; subsequent occurrences drop
    /// to debug to avoid flooding the hot path.
    fn log_fail_open(&self, client_ip: &str, reason: &'static str) {
        if !self.fail_open_warned.swap(true, Ordering::Relaxed) {
            warn!(
                client_ip = %client_ip,
                plugin = "geo_restriction",
                reason = reason,
                "GeoIP lookup failed; allowing request by on_lookup_failure policy (fail-open). \
                 Further occurrences logged at debug"
            );
        } else {
            debug!(
                client_ip = %client_ip,
                plugin = "geo_restriction",
                reason = reason,
                "GeoIP lookup failed; allowing request by on_lookup_failure policy (fail-open)"
            );
        }
    }

    /// Look up the country ISO code for an already-canonical client address.
    ///
    /// The caller supplies the request/connection-scoped canonical typed IP
    /// (`RequestContext::canonical_client_ip` / the stream equivalent), so an
    /// IPv4-mapped IPv6 client reaches MaxMind as native IPv4 and its lookup
    /// descends the database's IPv4 tree. Passing the mapped form instead makes
    /// an IPv4-only database reject the query outright and a combined database
    /// search the mapped IPv6 range rather than the IPv4 country record —
    /// either way the request falls through to `on_lookup_failure`, whose
    /// default is `allow` (GHSA-vjwj-657f-5w9g).
    ///
    /// `None` is the single "no country could be determined" outcome — no
    /// loaded database, a lookup or decode error, an address absent from the
    /// database, or a record without a usable code — which the only caller
    /// routes to `on_lookup_failure`. Errors are never formatted: the request
    /// path allocates nothing on failure. `registered_country` is decoded only
    /// when the record has no direct `country` (direct precedence is the
    /// pinned behavior), so the common record costs one path decode.
    fn lookup_country(&self, ip: std::net::IpAddr) -> Option<CountryCode> {
        let reader = self.reader.as_ref()?;
        let result = reader.lookup(ip).ok()?;
        let direct: Option<&str> = result
            .decode_path(&maxminddb::path!["country", "iso_code"])
            .ok()?;
        let raw_code = match direct {
            Some(code) => code,
            None => result
                .decode_path::<&str>(&maxminddb::path!["registered_country", "iso_code"])
                .ok()??,
        };
        // CountryMmdbSnapshot is published only after every record has passed
        // the shared supported-code invariant. Keep the request path to packed
        // parsing plus the constant-time policy bitset lookup.
        CountryCode::parse(raw_code)
    }

    /// Check whether the client IP's country is allowed.
    ///
    /// `canonical_ip` is the shared per-request/per-connection typed identity
    /// and `client_ip` is only its display form for logs. A `None` typed
    /// identity means the authoritative client IP is not an address literal, so
    /// no country can be determined and the configured `on_lookup_failure`
    /// policy decides — the same branch an unresolvable address takes.
    fn check_ip(&self, canonical_ip: Option<std::net::IpAddr>, client_ip: &str) -> GeoVerdict {
        if self.reader.is_none() {
            // Database file not loaded — apply the configured failure policy.
            return match self.on_lookup_failure {
                LookupFailureAction::Allow => {
                    // Fail-open: surface that the geo gate is disabled because
                    // the .mmdb is absent (first occurrence at warn).
                    self.log_fail_open(client_ip, "db_not_loaded");
                    GeoVerdict {
                        result: PluginResult::Continue,
                        country: None,
                        decision: GeoDecision::DbNotLoadedAllowed,
                    }
                }
                LookupFailureAction::Deny => {
                    warn_sampled!(
                        client_ip = %client_ip,
                        db_path = %crate::startup::sanitize_startup_scalar(&self.db_path),
                        plugin = "geo_restriction",
                        reason = "db_not_loaded",
                        "MaxMind database not loaded, denying by on_lookup_failure policy"
                    );
                    GeoVerdict {
                        result: PluginResult::Reject {
                            status_code: 403,
                            body: r#"{"error":"Access denied: GeoIP database not available"}"#
                                .to_string(),
                            headers: HashMap::new(),
                        },
                        country: None,
                        decision: GeoDecision::DbNotLoadedDenied,
                    }
                }
            };
        }

        // No typed identity, a lookup error, and an address absent from the
        // database are one outcome: no country could be determined.
        let country = match canonical_ip.and_then(|ip| self.lookup_country(ip)) {
            Some(code) => code,
            None => {
                // Lookup failed or IP not in database
                match self.on_lookup_failure {
                    LookupFailureAction::Allow => {
                        // Fail-open: the IP could not be resolved but policy
                        // permits it. Previously silent — surface it so an
                        // operator can detect unresolved traffic slipping past
                        // the geo gate.
                        self.log_fail_open(client_ip, "lookup_failed");
                        return GeoVerdict {
                            result: PluginResult::Continue,
                            country: None,
                            decision: GeoDecision::LookupFailedAllowed,
                        };
                    }
                    LookupFailureAction::Deny => {
                        warn_sampled!(
                            client_ip = %client_ip,
                            plugin = "geo_restriction",
                            reason = "lookup_failed",
                            "GeoIP lookup failed, denying by policy"
                        );
                        return GeoVerdict {
                            result: PluginResult::Reject {
                                status_code: 403,
                                body: r#"{"error":"Access denied: unable to determine geographic location"}"#
                                    .to_string(),
                                headers: HashMap::new(),
                            },
                            country: None,
                            decision: GeoDecision::LookupFailedDenied,
                        };
                    }
                }
            }
        };

        // Allow-list mode: only listed countries pass
        if !self.allow_countries.is_empty() && !self.allow_countries.contains(country) {
            warn_sampled!(
                client_ip = %client_ip,
                country = %country,
                plugin = "geo_restriction",
                reason = "country_not_allowed",
                "Country not in allow list"
            );
            return GeoVerdict {
                result: PluginResult::Reject {
                    status_code: 403,
                    body: r#"{"error":"Access denied from your geographic location"}"#.to_string(),
                    headers: HashMap::new(),
                },
                country: Some(country),
                decision: GeoDecision::CountryNotAllowed,
            };
        }

        // Deny-list mode: listed countries are blocked
        if self.deny_countries.contains(country) {
            warn_sampled!(
                client_ip = %client_ip,
                country = %country,
                plugin = "geo_restriction",
                reason = "country_denied",
                "Country in deny list"
            );
            return GeoVerdict {
                result: PluginResult::Reject {
                    status_code: 403,
                    body: r#"{"error":"Access denied from your geographic location"}"#.to_string(),
                    headers: HashMap::new(),
                },
                country: Some(country),
                decision: GeoDecision::CountryDenied,
            };
        }

        GeoVerdict {
            result: PluginResult::Continue,
            country: Some(country),
            decision: GeoDecision::Allowed,
        }
    }
}

/// Report the loaded database's build date and age. A database older than
/// [`STALE_DATABASE_AGE_DAYS`] is a `warn` — country assignments drift as
/// address space is reallocated — and a fresh one is `debug`. The source path
/// is deliberately not logged, matching the plugin's other load diagnostics;
/// `database_type` is safe to emit because a published snapshot has already
/// passed the closed supported-product check.
fn log_database_freshness(snapshot: &CountryMmdbSnapshot) {
    let metadata = snapshot.metadata();
    let build_epoch = metadata.build_epoch;
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let age_days = now_epoch.saturating_sub(build_epoch) / 86_400;
    if age_days > STALE_DATABASE_AGE_DAYS {
        warn!(
            plugin = "geo_restriction",
            database_type = %metadata.database_type,
            build_epoch,
            age_days,
            stale_after_days = STALE_DATABASE_AGE_DAYS,
            "MaxMind database is stale; country assignments may be outdated — refresh the .mmdb"
        );
    } else {
        debug!(
            plugin = "geo_restriction",
            database_type = %metadata.database_type,
            build_epoch,
            age_days,
            "MaxMind database loaded"
        );
    }
}

fn parse_config(config: &Value) -> Result<GeoRestrictionConfig, String> {
    let object = config.as_object().ok_or_else(|| {
        format!(
            "geo_restriction: config must be an object, got: {config:?}",
            config = config.to_string()
        )
    })?;
    if let Some(unknown) = object
        .keys()
        .find(|key| !CONFIG_KEYS.contains(&key.as_str()))
    {
        return Err(format!(
            "geo_restriction: unknown configuration field {unknown:?}"
        ));
    }

    let db_path = string_config(config, "db_path")?;
    let allow_countries = parse_country_set(config, "allow_countries")?;
    let deny_countries = parse_country_set(config, "deny_countries")?;

    if allow_countries.is_empty() && deny_countries.is_empty() {
        return Err(
            "geo_restriction: at least one `allow_countries` or `deny_countries` entry is required"
                .to_string(),
        );
    }

    if !allow_countries.is_empty() && !deny_countries.is_empty() {
        return Err(
            "geo_restriction: `allow_countries` and `deny_countries` are mutually exclusive"
                .to_string(),
        );
    }

    let inject_headers = bool_config(config, "inject_headers", false)?;
    let on_lookup_failure = lookup_failure_action(config)?;
    // Explicit null is rejected by `lookup_failure_action`, so successful
    // parsing only needs to distinguish presence from omission here.
    let on_lookup_failure_explicit = config.get("on_lookup_failure").is_some();

    Ok(GeoRestrictionConfig {
        db_path,
        allow_countries,
        deny_countries,
        inject_headers,
        on_lookup_failure,
        on_lookup_failure_explicit,
    })
}

fn string_config(config: &Value, key: &str) -> Result<String, String> {
    match config.get(key) {
        Some(Value::String(value)) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Err(format!(
                    "geo_restriction: `{key}` must be a non-empty string"
                ))
            } else {
                Ok(trimmed.to_string())
            }
        }
        None | Some(Value::Null) => Err(format!(
            "geo_restriction: `{key}` is required (path to .mmdb file)"
        )),
        Some(other) => Err(format!(
            "geo_restriction: `{key}` must be a string, got: {other:?}",
            other = other.to_string()
        )),
    }
}

fn parse_country_set(config: &Value, key: &str) -> Result<CountrySet, String> {
    let Some(value) = config.get(key) else {
        return Ok(CountrySet::default());
    };
    if value.is_null() {
        return Err(format!(
            "geo_restriction: `{key}` must be an array of ISO country codes"
        ));
    }
    let Value::Array(arr) = value else {
        return Err(format!(
            "geo_restriction: `{key}` must be an array of ISO country codes"
        ));
    };

    let mut countries = CountrySet::default();
    for value in arr {
        let country = value.as_str().ok_or_else(|| {
            format!(
                "geo_restriction: `{key}` entries must be strings, got: {value:?}",
                value = value.to_string()
            )
        })?;
        let Some(country_code) = CountryCode::parse(country) else {
            return Err(format!(
                "geo_restriction: `{key}` contains invalid ISO 3166-1 alpha-2 country code: {country:?}"
            ));
        };
        if !country_code.is_supported() {
            return Err(format!(
                "geo_restriction: `{key}` contains unassigned ISO 3166-1 alpha-2 country code: {country:?}"
            ));
        }
        countries.insert(country_code);
    }
    Ok(countries)
}

fn bool_config(config: &Value, key: &str, default: bool) -> Result<bool, String> {
    match config.get(key) {
        None => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        Some(other) => Err(format!(
            "geo_restriction: `{key}` must be a boolean, got: {other:?}",
            other = other.to_string()
        )),
    }
}

fn lookup_failure_action(config: &Value) -> Result<LookupFailureAction, String> {
    match config.get("on_lookup_failure") {
        None => Ok(LookupFailureAction::Allow),
        Some(Value::String(action)) if action == "allow" => Ok(LookupFailureAction::Allow),
        Some(Value::String(action)) if action == "deny" => Ok(LookupFailureAction::Deny),
        Some(other) => Err(format!(
            "geo_restriction: `on_lookup_failure` must be `allow` or `deny`, got: {other:?}",
            other = other.to_string()
        )),
    }
}

#[async_trait]
impl Plugin for GeoRestriction {
    fn name(&self) -> &str {
        "geo_restriction"
    }

    fn country_mmdb_snapshot(&self) -> Option<&CountryMmdbSnapshot> {
        self.reader.as_deref()
    }

    fn country_mmdb_retained_load(&self) -> Option<(&str, Arc<CountryMmdbSnapshot>)> {
        self.reader
            .as_ref()
            .map(|reader| (self.db_path.as_str(), Arc::clone(reader)))
    }

    fn priority(&self) -> u16 {
        super::priority::GEO_RESTRICTION
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    async fn on_stream_connect(
        &self,
        ctx: &mut super::StreamConnectionContext,
    ) -> super::PluginResult {
        let GeoVerdict {
            result,
            country,
            decision,
        } = self.check_ip(ctx.canonical_client_ip(), &ctx.client_ip);
        ctx.insert_metadata(
            GEO_DECISION_METADATA_KEY.to_string(),
            decision.as_str().to_string(),
        );
        // The pair always describes THIS evaluation: an unresolved lookup
        // removes a country an earlier instance recorded.
        match country {
            Some(code) => {
                ctx.insert_metadata(GEO_COUNTRY_METADATA_KEY.to_string(), code.into_string())
            }
            None => {
                if let Some(metadata) = ctx.metadata.as_mut() {
                    metadata.remove(GEO_COUNTRY_METADATA_KEY);
                }
            }
        }
        result
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        let GeoVerdict {
            result,
            country,
            decision,
        } = self.check_ip(ctx.canonical_client_ip(), &ctx.client_ip);
        ctx.metadata.insert(
            GEO_DECISION_METADATA_KEY.to_string(),
            decision.as_str().to_string(),
        );
        // The pair always describes THIS evaluation: an unresolved lookup
        // removes a country an earlier instance recorded. The private country
        // assertion and its header are deliberately left alone below.
        match country {
            Some(code) => {
                ctx.metadata
                    .insert(GEO_COUNTRY_METADATA_KEY.to_string(), code.into_string());
            }
            None => {
                ctx.metadata.remove(GEO_COUNTRY_METADATA_KEY);
            }
        }

        // Header materialization centrally strips every client-supplied value
        // before the plugin chain. Writing the authoritative value here avoids
        // metadata collisions and lets later non-injecting or fail-open geo
        // instances preserve an assertion produced by an earlier instance.
        if self.inject_headers
            && matches!(&result, PluginResult::Continue)
            && let Some(code) = country
        {
            ctx.set_backend_geo_country(code.bytes());
            ctx.headers
                .insert(GEO_COUNTRY_HEADER.to_string(), code.into_string());
        }

        result
    }
}
