//! GeoIP Restriction Plugin
//!
//! Allows or denies requests based on the geographic location of the client IP
//! address. Uses MaxMind GeoIP2/GeoLite2 `.mmdb` database files for IP-to-country
//! lookups.
//!
//! Supports:
//! - Country allow/deny lists (ISO 3166-1 alpha-2 codes)
//! - Optional geographic header injection (`X-Geo-Country`, `X-Geo-Region`)
//! - Configurable default action when IP lookup fails
//!
//! The `.mmdb` file is memory-mapped via `mmap(2)` at plugin construction time
//! (`Reader::open_mmap`) for zero-copy lookups on the hot path without loading
//! the entire database into heap memory. If the file is unavailable at construction
//! time (e.g., on a control plane that doesn't proxy traffic), the plugin degrades
//! gracefully — lookups fall back to the `on_lookup_failure` policy. File existence
//! is validated separately by `GatewayConfig::validate_plugin_file_dependencies()`,
//! which each mode calls independently: fatal in file mode, warn in db mode,
//! skipped in dp mode (plugin degrades gracefully with `reader: None`).

use async_trait::async_trait;
use maxminddb::{Mmap, Reader};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::warn;

use super::{Plugin, PluginResult, RequestContext};

/// Deserialization target for MaxMind country-level GeoIP records.
#[derive(Deserialize, Debug)]
struct GeoCountryRecord {
    country: Option<CountryInfo>,
    registered_country: Option<CountryInfo>,
}

#[derive(Deserialize, Debug)]
struct CountryInfo {
    iso_code: Option<String>,
}

/// Action when GeoIP lookup fails (IP not in database).
#[derive(Debug, Clone, PartialEq, Eq)]
enum LookupFailureAction {
    Allow,
    Deny,
}

pub struct GeoRestriction {
    reader: Option<Arc<Reader<Mmap>>>,
    db_path: String,
    /// Allow-list of ISO 3166-1 alpha-2 country codes (uppercase). Empty disables allow-list mode.
    /// `HashSet` for O(1) membership tests on the hot path.
    allow_countries: HashSet<String>,
    /// Deny-list of ISO 3166-1 alpha-2 country codes (uppercase). Empty disables deny-list mode.
    /// `HashSet` for O(1) membership tests on the hot path.
    deny_countries: HashSet<String>,
    inject_headers: bool,
    on_lookup_failure: LookupFailureAction,
}

impl GeoRestriction {
    pub fn new(config: &Value) -> Result<Self, String> {
        let db_path = config["db_path"].as_str().ok_or_else(|| {
            "geo_restriction: 'db_path' is required (path to .mmdb file)".to_string()
        })?;

        // Open the MaxMind database file. If the file is missing or unreadable,
        // log a warning but allow the plugin to be created — the file may exist
        // on data plane nodes but not on the control plane, or may be deployed
        // after config is pushed. At request time, a missing reader falls back
        // to the on_lookup_failure policy.
        // SAFETY: The mmdb file is read-only after construction. The gateway only
        // opens it once at plugin init and does not modify or truncate it.
        let reader = match unsafe { Reader::open_mmap(db_path) } {
            Ok(r) => Some(Arc::new(r)),
            Err(e) => {
                warn!(
                    db_path = %db_path,
                    error = %e,
                    plugin = "geo_restriction",
                    "MaxMind database file not available — plugin will use on_lookup_failure policy until file is present"
                );
                None
            }
        };

        let allow_countries: HashSet<String> = config["allow_countries"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_ascii_uppercase()))
                    .collect()
            })
            .unwrap_or_default();

        let deny_countries: HashSet<String> = config["deny_countries"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_ascii_uppercase()))
                    .collect()
            })
            .unwrap_or_default();

        if allow_countries.is_empty() && deny_countries.is_empty() {
            return Err(
                "geo_restriction: at least one 'allow_countries' or 'deny_countries' entry is required"
                    .to_string(),
            );
        }

        if !allow_countries.is_empty() && !deny_countries.is_empty() {
            return Err(
                "geo_restriction: 'allow_countries' and 'deny_countries' are mutually exclusive"
                    .to_string(),
            );
        }

        let inject_headers = config["inject_headers"].as_bool().unwrap_or(false);

        let on_lookup_failure = match config["on_lookup_failure"].as_str().unwrap_or("allow") {
            "deny" => LookupFailureAction::Deny,
            _ => LookupFailureAction::Allow,
        };

        Ok(Self {
            reader,
            db_path: db_path.to_string(),
            allow_countries,
            deny_countries,
            inject_headers,
            on_lookup_failure,
        })
    }

    /// Look up the country ISO code for a given IP address string.
    fn lookup_country(&self, ip_str: &str) -> Result<Option<String>, String> {
        let reader = self
            .reader
            .as_ref()
            .ok_or_else(|| "MaxMind database not loaded".to_string())?;

        let ip: std::net::IpAddr = ip_str.parse().map_err(|e| format!("invalid IP: {}", e))?;

        let result = reader.lookup(ip).map_err(|e| e.to_string())?;
        let record: Option<GeoCountryRecord> = result.decode().map_err(|e| e.to_string())?;

        let iso_code = record.and_then(|r| {
            // Prefer the direct country, fall back to registered_country
            r.country
                .and_then(|c| c.iso_code)
                .or_else(|| r.registered_country.and_then(|c| c.iso_code))
        });

        Ok(iso_code.map(|s: String| s.to_ascii_uppercase()))
    }

    /// Check whether the client IP's country is allowed.
    fn check_ip(&self, client_ip: &str) -> (PluginResult, Option<String>) {
        if self.reader.is_none() {
            // Database file not loaded — apply the configured failure policy.
            warn!(
                client_ip = %client_ip,
                db_path = %self.db_path,
                plugin = "geo_restriction",
                reason = "db_not_loaded",
                "MaxMind database not loaded, applying on_lookup_failure policy"
            );
            return match self.on_lookup_failure {
                LookupFailureAction::Allow => (PluginResult::Continue, None),
                LookupFailureAction::Deny => (
                    PluginResult::Reject {
                        status_code: 403,
                        body: r#"{"error":"Access denied: GeoIP database not available"}"#
                            .to_string(),
                        headers: HashMap::new(),
                    },
                    None,
                ),
            };
        }

        let country = match self.lookup_country(client_ip) {
            Ok(Some(code)) => code,
            Ok(None) | Err(_) => {
                // Lookup failed or IP not in database
                match self.on_lookup_failure {
                    LookupFailureAction::Allow => return (PluginResult::Continue, None),
                    LookupFailureAction::Deny => {
                        warn!(
                            client_ip = %client_ip,
                            plugin = "geo_restriction",
                            reason = "lookup_failed",
                            "GeoIP lookup failed, denying by policy"
                        );
                        return (
                            PluginResult::Reject {
                                status_code: 403,
                                body: r#"{"error":"Access denied: unable to determine geographic location"}"#
                                    .to_string(),
                                headers: HashMap::new(),
                            },
                            None,
                        );
                    }
                }
            }
        };

        // Allow-list mode: only listed countries pass
        if !self.allow_countries.is_empty() && !self.allow_countries.contains(&country) {
            warn!(
                client_ip = %client_ip,
                country = %country,
                plugin = "geo_restriction",
                reason = "country_not_allowed",
                "Country not in allow list"
            );
            return (
                PluginResult::Reject {
                    status_code: 403,
                    body: r#"{"error":"Access denied from your geographic location"}"#.to_string(),
                    headers: HashMap::new(),
                },
                Some(country),
            );
        }

        // Deny-list mode: listed countries are blocked
        if self.deny_countries.contains(&country) {
            warn!(
                client_ip = %client_ip,
                country = %country,
                plugin = "geo_restriction",
                reason = "country_denied",
                "Country in deny list"
            );
            return (
                PluginResult::Reject {
                    status_code: 403,
                    body: r#"{"error":"Access denied from your geographic location"}"#.to_string(),
                    headers: HashMap::new(),
                },
                Some(country),
            );
        }

        (PluginResult::Continue, Some(country))
    }
}

#[async_trait]
impl Plugin for GeoRestriction {
    fn name(&self) -> &str {
        "geo_restriction"
    }

    fn priority(&self) -> u16 {
        super::priority::GEO_RESTRICTION
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    /// Declares that `before_proxy` may insert `x-geo-country` into outbound headers.
    /// The proxy uses this hint to take the explicit-clone code path instead of
    /// the zero-clone optimization, ensuring deterministic header propagation.
    fn modifies_request_headers(&self) -> bool {
        self.inject_headers
    }

    async fn on_stream_connect(
        &self,
        ctx: &mut super::StreamConnectionContext,
    ) -> super::PluginResult {
        let (result, _country) = self.check_ip(&ctx.client_ip);
        result
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        let (result, country) = self.check_ip(&ctx.client_ip);

        // Inject geo headers if configured and lookup succeeded
        if self.inject_headers
            && let Some(ref code) = country
        {
            ctx.metadata.insert("geo_country".to_string(), code.clone());
        }

        result
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Inject geo headers into the upstream request if configured
        if self.inject_headers
            && let Some(country) = ctx.metadata.get("geo_country")
        {
            headers.insert("x-geo-country".to_string(), country.clone());
        }
        PluginResult::Continue
    }
}
