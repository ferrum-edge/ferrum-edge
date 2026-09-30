//! Read-only configuration export: `GET /config/export` (issue #5904).
//!
//! `GET /backup` releases the raw configuration and is therefore `admin`-only.
//! Drift detection, dashboards, and audit tooling need the same resource graph
//! but must not hold write authority, so this endpoint serves a `viewer`-grade
//! snapshot of one namespace:
//!
//! - the same namespace-scoped resource collections `/backup` carries for
//!   `proxies`, `consumers`, `plugin_configs`, and `upstreams`, from the same
//!   authoritative load (`FullConfigLoadPurpose::BackupExport`) with the same
//!   labeled cached fallback (`X-Data-Source: database` or `cached`);
//! - every value the ordinary non-admin projection withholds — Consumer
//!   credential secrets (the audit-diff projection, so Basic credentials are a
//!   single opaque marker), plugin `config` secrets, credential-bearing URLs,
//!   and upstream Consul tokens — replaced by a keyed fingerprint instead of
//!   the `[REDACTED]` marker.
//!
//! The export never decides sensitivity itself. It runs the one projection each
//! resource already has ([`crate::config::types::redact_consumer_credentials_for_audit_with`],
//! [`crate::admin::plugin_config_projection::project_plugin_config_with`], and the
//! upstream audit projection) with [`FingerprintRendering`] in place of the
//! placeholder renderer, so a field the viewer projection redacts is
//! fingerprinted here, and a field it shows is shown here — the two cannot
//! drift apart.
//!
//! # Fingerprints
//!
//! `hmac-sha256:<64 lowercase hex>` = HMAC-SHA-256 under a subkey derived from
//! the primary admin JWT secret:
//!
//! ```text
//! subkey      = HMAC-SHA-256(FERRUM_ADMIN_JWT_SECRET,
//!                            "ferrum-edge/admin-config-export-fingerprint/v1")
//! fingerprint = HMAC-SHA-256(subkey, len64(kind) || kind || len64(namespace) || namespace
//!                                    || len64(id) || id || canonical_json(stored_value))
//! ```
//!
//! - **Keyed**, never a plain digest: many credentials (API keys, passwords)
//!   are guessable, and an unkeyed digest would be an offline oracle for them.
//! - **Not derivable by the reader**: the subkey comes from the primary secret,
//!   never from `FERRUM_ADMIN_JWT_VIEWER_SECRET`, so the viewer-tier credential
//!   the export exists for cannot compute or dictionary-test a fingerprint.
//! - **Stable**: the canonical JSON sorts object keys, so an unchanged stored
//!   value fingerprints identically across calls and across replicas that
//!   share `FERRUM_ADMIN_JWT_SECRET`. Rotating that secret changes every
//!   fingerprint; `redaction.fingerprint_key_id` (a keyed label, not the key)
//!   tells a consumer that two exports are not comparable.
//! - **Bound to its resource**: the resource kind, namespace, and id are MAC
//!   inputs, so equal secrets on two different resources do not produce equal
//!   fingerprints, and a fingerprint cannot be replayed onto another resource.

use bytes::Bytes;
use chrono::Utc;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use serde_json::{Value, json};

use crate::admin::AdminState;
use crate::config::db_backend::FullConfigLoadPurpose;
use crate::config::types::{
    GatewayConfig, RedactionRendering, redact_consumer_credentials_for_audit_with,
};
use crate::fips::approved::{HmacSha256, HmacSha256Key};

/// Domain-separation label for the fingerprint subkey. Bump the version to
/// invalidate every published fingerprint when the canonical input changes.
const FINGERPRINT_SUBKEY_LABEL: &[u8] = b"ferrum-edge/admin-config-export-fingerprint/v1";

/// Label MACed under the fingerprint subkey to produce the published key id.
const FINGERPRINT_KEY_ID_LABEL: &[u8] = b"ferrum-edge/admin-config-export-fingerprint/key-id/v1";

/// Bytes of the key-id MAC that are published (64 bits): enough to tell keys
/// apart, and a label only — it cannot be used to compute a fingerprint.
const FINGERPRINT_KEY_ID_BYTES: usize = 8;

/// Prefix of every fingerprint string in an export.
pub const FINGERPRINT_PREFIX: &str = "hmac-sha256:";

/// Resource-kind labels bound into each fingerprint.
const CONSUMER_KIND: &str = "consumer";
const PLUGIN_CONFIG_KIND: &str = "plugin_config";
const UPSTREAM_KIND: &str = "upstream";

/// Derive the fingerprint subkey from the primary admin JWT secret. `None`
/// when no secret is configured.
pub fn fingerprint_key(jwt_secret: &str) -> Option<HmacSha256Key> {
    if jwt_secret.is_empty() {
        return None;
    }
    let mut derive = HmacSha256::new_from_slice(jwt_secret.as_bytes()).ok()?;
    derive.update(FINGERPRINT_SUBKEY_LABEL);
    HmacSha256Key::new_from_slice(derive.finalize().as_ref()).ok()
}

/// Published identifier of a fingerprint subkey (16 lowercase hex).
pub fn fingerprint_key_id(key: &HmacSha256Key) -> String {
    let mut mac = key.begin();
    mac.update(FINGERPRINT_KEY_ID_LABEL);
    hex::encode(&mac.finalize().as_ref()[..FINGERPRINT_KEY_ID_BYTES])
}

/// Renders every withheld value as a keyed fingerprint bound to one resource.
pub struct FingerprintRendering<'a> {
    key: &'a HmacSha256Key,
    resource_kind: &'a str,
    namespace: &'a str,
    id: &'a str,
}

impl<'a> FingerprintRendering<'a> {
    pub fn new(
        key: &'a HmacSha256Key,
        resource_kind: &'a str,
        namespace: &'a str,
        id: &'a str,
    ) -> Self {
        Self {
            key,
            resource_kind,
            namespace,
            id,
        }
    }

    /// The fingerprint of one stored value.
    pub fn fingerprint(&self, stored: &Value) -> String {
        let mut canonical = String::new();
        crate::admin::preconditions::write_canonical_json(stored, &mut canonical);
        let mut mac = self.key.begin();
        for part in [self.resource_kind, self.namespace, self.id] {
            mac.update((part.len() as u64).to_be_bytes());
            mac.update(part.as_bytes());
        }
        mac.update(canonical.as_bytes());
        let digest = hex::encode(mac.finalize().as_ref());
        format!("{FINGERPRINT_PREFIX}{digest}")
    }
}

impl RedactionRendering for FingerprintRendering<'_> {
    fn render(&self, stored: &Value, redacted: Value) -> Value {
        // The projection hands every candidate site to the renderer, including
        // ones where its redacted form is the stored value (a credential-free
        // URL). Those disclose nothing to a viewer, so they stay verbatim.
        if redacted == *stored {
            return redacted;
        }
        Value::String(self.fingerprint(stored))
    }
}

/// Build the export document for an already namespace-scoped config.
///
/// API-spec ownership tags are stripped: a cached snapshot has already lost
/// them, so keeping them only on database-sourced exports would make the
/// source switch itself look like drift. Collections are sorted by `id` so two
/// exports of unchanged configuration compare equal resource by resource.
pub fn build_config_export(
    mut config: GatewayConfig,
    source: &str,
    namespace: &str,
    key: &HmacSha256Key,
) -> Value {
    crate::config::db_loader::strip_api_spec_id_from_runtime_config(&mut config);
    config.proxies.sort_by(|a, b| a.id.cmp(&b.id));
    config.consumers.sort_by(|a, b| a.id.cmp(&b.id));
    config.plugin_configs.sort_by(|a, b| a.id.cmp(&b.id));
    config.upstreams.sort_by(|a, b| a.id.cmp(&b.id));

    let proxies: Vec<Value> = config.proxies.iter().map(|proxy| json!(proxy)).collect();
    let consumers: Vec<Value> = config
        .consumers
        .iter()
        .map(|consumer| {
            let rendering =
                FingerprintRendering::new(key, CONSUMER_KIND, &consumer.namespace, &consumer.id);
            let projected = redact_consumer_credentials_for_audit_with(consumer, &rendering);
            json!(projected)
        })
        .collect();
    let plugin_configs: Vec<Value> = config
        .plugin_configs
        .iter()
        .map(|plugin_config| {
            let rendering = FingerprintRendering::new(
                key,
                PLUGIN_CONFIG_KIND,
                &plugin_config.namespace,
                &plugin_config.id,
            );
            crate::admin::crud::plugin_config_audit_body_with(plugin_config, &rendering)
        })
        .collect();
    let upstreams: Vec<Value> = config
        .upstreams
        .iter()
        .map(|upstream| {
            let rendering =
                FingerprintRendering::new(key, UPSTREAM_KIND, &upstream.namespace, &upstream.id);
            crate::admin::crud::upstream_audit_body_with(upstream, &rendering)
        })
        .collect();

    json!({
        "version": config.version,
        "ferrum_version": crate::FERRUM_VERSION,
        "exported_at": Utc::now().to_rfc3339(),
        "source": source,
        "namespace": namespace,
        "redaction": {
            "fingerprint_algorithm": "hmac-sha256",
            "fingerprint_prefix": FINGERPRINT_PREFIX,
            "fingerprint_key_id": fingerprint_key_id(key),
        },
        "counts": {
            "proxies": proxies.len(),
            "consumers": consumers.len(),
            "plugin_configs": plugin_configs.len(),
            "upstreams": upstreams.len(),
        },
        "proxies": proxies,
        "consumers": consumers,
        "plugin_configs": plugin_configs,
        "upstreams": upstreams,
    })
}

fn config_export_unavailable_response(message: &str) -> Response<Full<Bytes>> {
    super::json_response(StatusCode::SERVICE_UNAVAILABLE, &json!({"error": message}))
}

/// `GET /config/export`. Authorization (any authenticated role, `ns` claim)
/// is enforced by the dispatcher before this runs.
pub(crate) async fn handle_config_export(
    state: &AdminState,
    namespace: &str,
) -> Response<Full<Bytes>> {
    let Some(key) = state.jwt_manager.config_export_fingerprint_key() else {
        return config_export_unavailable_response(
            "Configuration export unavailable: no admin JWT secret is configured",
        );
    };

    let cached = || {
        state
            .cached_gateway_config()
            .map(|config| crate::admin::backup::filter_config_by_namespace(&config, namespace))
    };
    let (config, source) = match state.db.as_ref() {
        Some(db) => match db
            .load_full_config_for_purpose(namespace, FullConfigLoadPurpose::BackupExport)
            .await
        {
            Ok(config) => (config, "database"),
            Err(_error) => {
                super::warn_persistence_failure_redacted("config_export_database_load");
                match cached() {
                    Some(config) => (config, "cached"),
                    None => {
                        return config_export_unavailable_response(
                            "Database unavailable and no cached config",
                        );
                    }
                }
            }
        },
        None => match cached() {
            Some(config) => (config, "cached"),
            None => {
                return config_export_unavailable_response(
                    "No database configured and no cached config available",
                );
            }
        },
    };

    let export = build_config_export(config, source, namespace, &key);
    let body = serde_json::to_vec(&export).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header("X-Data-Source", source)
        .header("X-Content-Type-Options", "nosniff")
        .header("Cache-Control", "no-store")
        .header("X-Frame-Options", "DENY")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| {
            Response::new(Full::new(Bytes::from(
                "{\"error\":\"Internal Server Error\"}",
            )))
        })
}
