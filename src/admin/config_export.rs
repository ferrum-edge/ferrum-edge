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
//!   credential secrets, plugin `config` secrets, credential-bearing URLs,
//!   URL userinfo anywhere in a Proxy or Upstream, and upstream Consul tokens —
//!   replaced by a keyed fingerprint instead of the `[REDACTED]` marker;
//! - per Consumer, one [`HIDDEN_CREDENTIALS_FIELD`] fingerprint of the
//!   credential types ordinary viewer reads omit entirely (`basicauth`,
//!   unknown/custom types). It is emitted for every consumer, so it shows that
//!   hidden credentials changed without revealing whether any exist.
//!
//! The export never decides sensitivity itself. It runs the one projection each
//! resource already has for viewer reads
//! ([`crate::config::types::redact_consumer_credentials_with`],
//! [`crate::admin::plugin_config_projection::project_plugin_config_with`], and
//! the Proxy/Upstream projections) with [`FingerprintRendering`] in place of
//! the placeholder renderer, so a field the viewer projection redacts is
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
//!                                    || len64(id) || id || len64(pointer) || pointer
//!                                    || canonical_json(stored_value))
//! ```
//!
//! `pointer` is the RFC 6901 JSON pointer of the field inside the resource
//! body (`/credentials/keyauth/0/key`, `/config/headers/x-api-key`,
//! `/service_discovery/consul/token`).
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
//!   tells a consumer that two exports are not comparable. Without a
//!   configured secret (`file`/`mesh`/`node_agent` fallback) the key is random
//!   per process, and a CP and a DP whose secrets differ never agree.
//! - **Bound to its field**: the resource kind, namespace, id, and field
//!   pointer are MAC inputs, so equal secrets in two fields — or on two
//!   resources — do not produce equal fingerprints, and a fingerprint cannot be
//!   replayed onto another field.
//! - **One fingerprint per JSON pointer**: once a layer has fingerprinted a
//!   pointer, a later layer matching it (a schema rule and then the name
//!   heuristic) leaves it alone. A fingerprint of an ancestor may still cover
//!   fingerprints of its children. A legacy single-object credential uses
//!   index `0`, the position it is emitted at.
//!
//! Residual oracle: a principal that can *write* a field (an operator for
//! plugin configs and upstreams, an admin for consumers) can confirm a guess
//! of that field's current value by writing the guess to the same field and
//! comparing the new fingerprint with the old one. That requires write access
//! to the exact field, which already lets them replace the secret outright, and
//! the guess destroys the stored value.

use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{HeaderValue, RETRY_AFTER};
use hyper::{Response, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Semaphore;
use tracing::info;

use crate::admin::AdminState;
use crate::admin::audit::AuditActor;
use crate::config::db_backend::FullConfigLoadPurpose;
use crate::config::types::{GatewayConfig, RedactionRendering, redact_consumer_credentials_with};
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
const PROXY_KIND: &str = "proxy";
const UPSTREAM_KIND: &str = "upstream";

/// Field added to each exported Consumer: one fingerprint of every stored
/// credential type the ordinary viewer projection omits (`basicauth` and
/// unknown/custom types). It is always present — over an empty map when there
/// are none — so it reveals that hidden credentials *changed*, never whether
/// any exist.
pub const HIDDEN_CREDENTIALS_FIELD: &str = "hidden_credentials_fingerprint";

/// JSON pointer the hidden-credentials fingerprint is bound to.
const HIDDEN_CREDENTIALS_POINTER: &str = "/hidden_credentials";

/// At most this many exports load from the database at once per process. An
/// export that finds every permit taken does not wait: it serves the labelled
/// cached snapshot (`X-Data-Source: cached`), the same as on a database error.
pub const MAX_CONCURRENT_DATABASE_EXPORT_LOADS: usize = 1;

/// At most this many exports (database or cached) are in flight at once per
/// process. The document is built and serialized on the blocking pool, never
/// on an async admin worker.
pub const MAX_CONCURRENT_EXPORT_BUILDS: usize = 4;

/// How long an export waits for a build permit before answering `503` with
/// `Retry-After: 1`.
pub const EXPORT_PERMIT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

static DATABASE_EXPORT_LOADS: std::sync::OnceLock<Semaphore> = std::sync::OnceLock::new();
static EXPORT_BUILDS: std::sync::OnceLock<Semaphore> = std::sync::OnceLock::new();

fn database_export_loads() -> &'static Semaphore {
    DATABASE_EXPORT_LOADS.get_or_init(|| Semaphore::new(MAX_CONCURRENT_DATABASE_EXPORT_LOADS))
}

fn export_builds() -> &'static Semaphore {
    EXPORT_BUILDS.get_or_init(|| Semaphore::new(MAX_CONCURRENT_EXPORT_BUILDS))
}

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

    /// The fingerprint of the value stored at `pointer` (an RFC 6901 JSON
    /// pointer into the resource body).
    pub fn fingerprint(&self, pointer: &str, stored: &Value) -> String {
        let mut canonical = String::new();
        crate::admin::preconditions::write_canonical_json(stored, &mut canonical);
        let mut mac = self.key.begin();
        for part in [self.resource_kind, self.namespace, self.id, pointer] {
            mac.update((part.len() as u64).to_be_bytes());
            mac.update(part.as_bytes());
        }
        mac.update(canonical.as_bytes());
        let digest = hex::encode(mac.finalize().as_ref());
        format!("{FINGERPRINT_PREFIX}{digest}")
    }
}

impl RedactionRendering for FingerprintRendering<'_> {
    fn render(&self, pointer: &str, stored: &Value, redacted: Value) -> Value {
        // The projection hands every candidate site to the renderer, including
        // ones where its redacted form is the stored value (a credential-free
        // URL). Those disclose nothing to a viewer, so they stay verbatim.
        if redacted == *stored {
            return redacted;
        }
        Value::String(self.fingerprint(pointer, stored))
    }

    fn renders_opaque(&self) -> bool {
        true
    }
}

/// One exported Consumer: the ordinary viewer projection with fingerprints in
/// place of `[REDACTED]`, plus [`HIDDEN_CREDENTIALS_FIELD`].
pub fn export_consumer(consumer: &crate::config::types::Consumer, key: &HmacSha256Key) -> Value {
    let rendering =
        FingerprintRendering::new(key, CONSUMER_KIND, &consumer.namespace, &consumer.id);
    let projected = redact_consumer_credentials_with(consumer, &rendering);
    let hidden: serde_json::Map<String, Value> = consumer
        .credentials
        .iter()
        .filter(|(cred_type, _)| !projected.credentials.contains_key(*cred_type))
        .map(|(cred_type, stored)| (cred_type.clone(), stored.clone()))
        .collect();
    let hidden = rendering.fingerprint(HIDDEN_CREDENTIALS_POINTER, &Value::Object(hidden));
    let mut body = json!(projected);
    if let Some(object) = body.as_object_mut() {
        object.insert(HIDDEN_CREDENTIALS_FIELD.to_string(), Value::String(hidden));
    }
    body
}

/// Build the export document for an already namespace-scoped config.
///
/// API-spec ownership tags are stripped: a cached snapshot has already lost
/// them, so keeping them only on database-sourced exports would make the
/// source switch itself look like drift. Collections are sorted by `id`, and
/// proxy plugin associations by config id (SQL reads them unordered), and the
/// document carries no timestamp of its own, so two exports of unchanged
/// configuration under one key are byte-identical.
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
    for proxy in &mut config.proxies {
        proxy
            .plugins
            .sort_by(|a, b| a.plugin_config_id.cmp(&b.plugin_config_id));
    }

    let proxies: Vec<Value> = config
        .proxies
        .iter()
        .map(|proxy| {
            let rendering = FingerprintRendering::new(key, PROXY_KIND, &proxy.namespace, &proxy.id);
            crate::admin::crud::proxy_audit_body_with(proxy, &rendering)
        })
        .collect();
    let consumers: Vec<Value> = config
        .consumers
        .iter()
        .map(|consumer| export_consumer(consumer, key))
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

    sorted_keys(json!({
        "version": config.version,
        "ferrum_version": crate::FERRUM_VERSION,
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
    }))
}

/// Rebuild every object with its keys in sorted order, whatever map
/// implementation `serde_json` was built with, so map-valued fields (Consumer
/// credentials are a `HashMap`) serialize identically on every export.
fn sorted_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            let mut sorted = serde_json::Map::new();
            for (key, child) in entries {
                sorted.insert(key, sorted_keys(child));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sorted_keys).collect()),
        scalar => scalar,
    }
}

fn config_export_unavailable_response(message: &str) -> Response<Full<Bytes>> {
    super::json_response(StatusCode::SERVICE_UNAVAILABLE, &json!({"error": message}))
}

fn config_export_busy_response() -> Response<Full<Bytes>> {
    let mut response = config_export_unavailable_response(
        "Configuration export busy: too many exports in progress; retry shortly",
    );
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

/// Outcome of a database-backed export load.
enum DatabaseLoad {
    Loaded(Box<GatewayConfig>),
    /// Another export holds the load permit. Retrying shortly will succeed.
    Busy,
    /// No database is configured, or the load failed.
    Unavailable,
}

/// Load the namespace from the database under the process-wide load cap.
/// On `Busy` or `Unavailable` the caller falls back to the labelled cached
/// configuration.
async fn load_from_database(
    db: &dyn crate::config::db_backend::DatabaseBackend,
    namespace: &str,
) -> DatabaseLoad {
    let Ok(_permit) = database_export_loads().try_acquire() else {
        info!(
            namespace = %namespace,
            "Configuration export database load cap reached; serving the cached snapshot"
        );
        return DatabaseLoad::Busy;
    };
    match db
        .load_full_config_for_purpose(namespace, FullConfigLoadPurpose::BackupExport)
        .await
    {
        Ok(config) => DatabaseLoad::Loaded(Box::new(config)),
        Err(_error) => {
            super::warn_persistence_failure_redacted("config_export_database_load");
            DatabaseLoad::Unavailable
        }
    }
}

/// Where an export's configuration came from.
enum ExportInput {
    Database(Box<GatewayConfig>),
    /// The whole cached snapshot; namespace filtering runs off the async worker.
    Cached(std::sync::Arc<GatewayConfig>),
}

/// `GET /config/export`. Authorization (any authenticated role, `ns` claim,
/// and the viewer-key namespace ceiling) is enforced by the dispatcher before
/// this runs.
pub(crate) async fn handle_config_export(
    state: &AdminState,
    actor: &AuditActor,
    namespace: &str,
) -> Response<Full<Bytes>> {
    let Some(key) = state.jwt_manager.config_export_fingerprint_key() else {
        return config_export_unavailable_response(
            "Configuration export unavailable: no admin JWT secret is configured",
        );
    };
    let permit = match tokio::time::timeout(EXPORT_PERMIT_WAIT, export_builds().acquire()).await {
        Ok(Ok(permit)) => permit,
        _ => return config_export_busy_response(),
    };

    let from_database = match state.db.as_ref() {
        Some(db) => load_from_database(db.as_ref(), namespace).await,
        None => DatabaseLoad::Unavailable,
    };
    let (input, source) = match from_database {
        DatabaseLoad::Loaded(config) => (ExportInput::Database(config), "database"),
        fallback => match state.cached_gateway_config() {
            Some(cached) => (ExportInput::Cached(cached), "cached"),
            // Busy with nothing cached (for example just after startup): the
            // database is fine, so say so and ask for a retry.
            None if matches!(fallback, DatabaseLoad::Busy) => {
                return config_export_busy_response();
            }
            None => {
                return config_export_unavailable_response(
                    "No database available and no cached config",
                );
            }
        },
    };

    let owned_namespace = namespace.to_string();
    let built = tokio::task::spawn_blocking(move || {
        // Held until the document is serialized.
        let _permit = permit;
        let config = match input {
            ExportInput::Database(config) => *config,
            ExportInput::Cached(snapshot) => {
                crate::admin::backup::filter_config_by_namespace(&snapshot, &owned_namespace)
            }
        };
        let export = build_config_export(config, source, &owned_namespace, &key);
        serde_json::to_vec(&export).unwrap_or_else(|_| b"{}".to_vec())
    })
    .await;
    let Ok(body) = built else {
        return super::json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": "Configuration export failed"}),
        );
    };
    info!(
        actor = %actor.sub,
        key_tier = actor.key_tier.as_str(),
        namespace = %namespace,
        namespace_ceiling = actor.namespace_ceiling_decision(namespace).as_str(),
        source,
        bytes = body.len(),
        "Configuration export served"
    );
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
