//! First-class namespace registry (issue #3955).
//!
//! Historically `GET /namespaces` was a DISTINCT union over resource tables.
//! This module is the durable registry so an empty tenant can exist before any
//! proxy, consumer, plugin, upstream, or trust bundle is written, and so
//! rename/delete have a single object to operate on.
//!
//! `GET /namespaces` remains a paginated list of **name strings**
//! (`data: string[]`) for Foundry and other existing clients. Detail and write
//! operations use [`NamespaceRecord`].
//!
//! Every registry mutation is serialized cross-process by the global
//! [`NAMESPACE_REGISTRY_ADMISSION_KEY`] lease plus one lease per affected
//! namespace, taken in canonical order — the global key first, then the
//! affected names in ascending order. Create and delete therefore take global
//! plus one name; rename takes global plus source and target. Each backend
//! requires that exact canonical key sequence before mutating anything; an
//! empty, incomplete, duplicated, reordered, or substituted set is a lost
//! lease ([`BatchAdmissionLeaseLost`]) with nothing applied. The committing
//! transaction then re-verifies each held lease's owner and generation against
//! the datastore's own clock.
//!
//! The last-remaining-namespace invariant is **registry-row** based: every
//! registry-row removal takes that global lease, so two deletes cannot empty
//! the table. Ordinary resource CRUD does **not** take the global lease and
//! does **not** insert registry rows, so a derived-only name cannot be the
//! durable authority for "a namespace still exists". `GET /namespaces` stays
//! the backward-compatible union of registry names and derived resource names.
//!
//! Connect/migrate runs a **one-time** compatibility backfill of pre-existing
//! derived names plus canonical `ferrum`, then durably records completion in
//! [`SCHEMA_COMPAT_TABLE`]. That pass takes the SAME global
//! [`NAMESPACE_REGISTRY_ADMISSION_KEY`] lease every live create/rename/delete
//! takes AND commits as one atomic unit (an explicit transaction on
//! PostgreSQL/MySQL; a SAVEPOINT on SQLite's already-open `BEGIN IMMEDIATE`
//! migration transaction), so a confirmed DELETE can never commit
//! next to a backfill that already read the derived names and then resurrect the
//! removed row. Holding a lease is not enough on its own, because a lease can
//! lapse mid-pass: SQL verifies and row-locks the lease before the derived-name
//! scan and holds that lock through the commit, and MongoDB performs the
//! discovery, the upserts, the identity validation, the marker, and the
//! owner/generation lease proof in one transaction. A standalone `mongod` has
//! no transactions and already refuses every registry mutation, so the pass is
//! deferred there rather than writing rows it cannot fence. A failed
//! attempt leaves that marker absent so a later startup retries. Once complete,
//! later compatibility passes do not reseed deleted names or materialize newer
//! derived-only names. The marker is not a registry row and never appears in
//! `GET /namespaces`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};

use crate::config::batch_atomicity::{BatchAdmissionLeaseLost, NamespaceAdmissionLeaseHold};
use crate::config::types::validate_namespace;

/// Maximum length for an optional namespace description, in Unicode scalar
/// values (characters), matching the OpenAPI `maxLength` on the field. There is
/// deliberately no separate byte bound: 1024 characters is at most 4 KiB of
/// UTF-8, which every backend column accepts.
pub const MAX_NAMESPACE_DESCRIPTION_CHARS: usize = 1024;

/// Cross-process serialization key for namespace **registry** mutations.
///
/// Every create / rename / delete acquires this admission lease FIRST, then the
/// affected source (and target) namespace leases in ascending name order. That
/// makes the lock order total, so a source/target rename cannot deadlock
/// against a concurrent create or delete, and two gateway instances can never
/// each observe "two namespaces exist" and concurrently delete a different one.
///
/// The leading `!` can never appear in a namespace name — [`validate_namespace`]
/// requires an alphanumeric first character — so this key is collision-proof
/// against any tenant's own admission row.
pub const NAMESPACE_REGISTRY_ADMISSION_KEY: &str = "!namespace-registry";

/// Internal one-time compatibility-state table (SQL) and collection (MongoDB).
///
/// This is not a tenant namespace, not a registry row, and is never unioned
/// into `GET /namespaces`. The leading `_` is illegal as a namespace name
/// ([`validate_namespace`] requires an alphanumeric first character), so it
/// cannot collide with tenant data.
pub const SCHEMA_COMPAT_TABLE: &str = "_ferrum_schema_compat";

/// Completion marker for the one-time namespace-registry compatibility
/// backfill. Stored as [`SCHEMA_COMPAT_TABLE`].`name` (SQL) / `_id` (MongoDB).
pub const NAMESPACES_REGISTRY_BACKFILL_ID: &str = "namespaces_registry_backfill";

/// Normalize the namespaces this process refuses to remove.
///
/// Callers pass the already-resolved startup configuration — `FERRUM_NAMESPACE`
/// in database mode, and additionally every explicitly configured
/// `FERRUM_CP_NAMESPACES` entry in CP mode. Entries are trimmed, empties are
/// dropped, and the result is sorted and de-duplicated so a lookup is a
/// deterministic binary search over a tiny cold-path vector. An input that
/// carries nothing usable falls back to the canonical default namespace rather
/// than leaving the process with no protection at all.
///
/// A cluster-wide CP (`FERRUM_CP_NAMESPACES=*`) deliberately does NOT freeze
/// every discovered name here: its scope is dynamic, so only `FERRUM_NAMESPACE`
/// is protected and any other tenant stays removable.
pub fn normalize_protected_namespaces(names: &[String]) -> Vec<String> {
    let mut normalized: Vec<String> = names
        .iter()
        .map(|name| name.trim())
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect();
    normalized.sort_unstable();
    normalized.dedup();
    if normalized.is_empty() {
        normalized.push(crate::config::types::DEFAULT_NAMESPACE.to_string());
    }
    normalized
}

/// Fail-closed default for a backend whose protected set was never configured.
///
/// Both production stores apply the resolved startup set, but a backend that
/// skipped that step must still refuse to delete the canonical namespace rather
/// than protect nothing at all.
pub fn default_protected_namespaces() -> &'static [String] {
    static DEFAULT_PROTECTED: OnceLock<Vec<String>> = OnceLock::new();
    DEFAULT_PROTECTED.get_or_init(|| vec![crate::config::types::DEFAULT_NAMESPACE.to_string()])
}

/// Membership test for a [`normalize_protected_namespaces`] result.
///
/// The slice is sorted, so this is a binary search; it is only ever reached
/// from admin namespace CRUD and the registry mutation transactions, never
/// from a proxy request path.
pub fn protected_namespaces_contains(protected: &[String], name: &str) -> bool {
    protected
        .binary_search_by(|candidate| candidate.as_str().cmp(name))
        .is_ok()
}

/// Durable registry row for one tenant namespace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NamespaceRecord {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl NamespaceRecord {
    pub fn new(name: String, description: Option<String>, now: DateTime<Utc>) -> Self {
        Self {
            name,
            description,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn audit_body(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
    }
}

/// POST /namespaces body.
///
/// `description` is typed as `Option<String>`, so a non-string, non-null JSON
/// value fails deserialization and the handler answers `400` before touching
/// persistence.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateNamespaceRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// Serde maps a present JSON `null` to `None` for `Option<T>`. Capture the
/// field as `Some(Value::Null)` instead so [`UpdateNamespaceBody::resolve`]
/// can reject `name: null` and clear on `description: null`. Absent fields
/// still become `None` via `#[serde(default)]`.
fn deserialize_present_json_value<'de, D>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error>
where
    D: Deserializer<'de>,
{
    serde_json::Value::deserialize(deserializer).map(Some)
}

/// PUT /namespaces/:name body.
///
/// Both fields are captured as raw JSON so the handler can distinguish
/// *omitted* from *explicitly null* and reject every other JSON type instead of
/// silently coercing it. Resolve with [`UpdateNamespaceBody::resolve`]; nothing
/// else may interpret these values.
#[derive(Debug, Clone)]
pub struct UpdateNamespaceBody {
    pub name: Option<serde_json::Value>,
    pub description: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct UpdateNamespaceObject {
    #[serde(default, deserialize_with = "deserialize_present_json_value")]
    name: Option<serde_json::Value>,
    #[serde(default, deserialize_with = "deserialize_present_json_value")]
    description: Option<serde_json::Value>,
}

impl<'de> Deserialize<'de> for UpdateNamespaceBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        if !value.is_object() {
            return Err(serde::de::Error::custom(
                "namespace update body must be a JSON object",
            ));
        }
        let object = UpdateNamespaceObject::deserialize(value).map_err(serde::de::Error::custom)?;
        Ok(Self {
            name: object.name,
            description: object.description,
        })
    }
}

/// The validated meaning of one `PUT /namespaces/:name` body.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResolvedNamespaceUpdate {
    /// `Some` only when the body carried a `name`, already validated against
    /// the namespace grammar. `None` leaves the current name unchanged.
    pub name: Option<String>,
    /// `None` = field omitted, leave the stored description unchanged.
    /// `Some(None)` = explicit clear (JSON `null`, or an empty/whitespace
    /// string). `Some(Some(_))` = the normalized replacement.
    pub description: Option<Option<String>>,
}

impl UpdateNamespaceBody {
    /// Fail-closed interpretation of the request body.
    ///
    /// The OpenAPI schema permits `name` only as a string when present and
    /// `description` only as a string or `null`. Every other shape — object,
    /// array, number, boolean, and `name: null` — is an error here rather than
    /// a silent clear or a silent no-op, so a malformed request can never
    /// mutate the registry.
    pub fn resolve(&self) -> Result<ResolvedNamespaceUpdate, String> {
        let name = match &self.name {
            None => None,
            Some(serde_json::Value::String(raw)) => {
                validate_namespace_name(raw)?;
                Some(raw.clone())
            }
            Some(serde_json::Value::Null) => {
                return Err(
                    "name must be a string when present; omit the field to keep the current name"
                        .to_string(),
                );
            }
            Some(_) => return Err("name must be a string".to_string()),
        };
        let description = match &self.description {
            None => None,
            Some(serde_json::Value::Null) => Some(None),
            // One canonical trim/length rule shared with POST /namespaces.
            Some(serde_json::Value::String(raw)) => Some(normalize_description(Some(raw.clone()))?),
            Some(_) => {
                return Err("description must be a string or null (null clears it)".to_string());
            }
        };
        Ok(ResolvedNamespaceUpdate { name, description })
    }
}

/// Resource tables whose `namespace` column participates in derived listing
/// and rename/delete occupancy. Keep in sync with SQL unions and Mongo
/// `distinct_namespaces` scans.
pub const DERIVED_NAMESPACE_RESOURCE_TABLES: &[&str] = &[
    "proxies",
    "consumers",
    "plugin_configs",
    "upstreams",
    "gateway_trust_bundles",
];

/// Occupancy tables that block an unconfirmed DELETE. Broader than the
/// derived-list union: API specs are admin-only metadata that still live
/// under the tenant.
pub const NAMESPACE_OCCUPANCY_TABLES: &[&str] = &[
    "proxies",
    "consumers",
    "plugin_configs",
    "upstreams",
    "gateway_trust_bundles",
    "api_specs",
];

/// Tables whose `namespace` column is rewritten in place on rename (SQL).
///
/// Tables keyed by `namespace` (or by a namespace-derived primary key) are NOT
/// here — they are copied and removed explicitly so the primary key moves with
/// the row (see [`NAMESPACE_RENAME_COPY_TABLES`]).
/// `config_admission_locks` is never touched at all: those rows are
/// the leases proving the mutation, and removing one before commit would
/// destroy the very fence the transaction verifies against.
///
/// `config_changes` and `config_change_retention` are deliberately absent: a
/// rename writes `delete` tombstones under the OLD name so pollers of the old
/// namespace converge, and those tombstones need the old name's history and
/// retention floor to stay where they are.
///
/// `audit_events` is the only remaining in-place rewrite. Its `namespace`
/// column is authorization-scoping and must follow the renamed tenant:
/// leaving those rows under the old name would disclose the previous tenant's
/// history to a later occupant of that name (rename removes the source
/// `namespaces` row and frees the name). The immutable `namespace_at_event`
/// column is not part of this rewrite: it preserves the namespace identity
/// recorded when the event occurred. `audit_events` has no foreign keys and is
/// keyed on `id` alone, so an in-place update is still safe there.
pub const NAMESPACE_RENAME_SIMPLE_TABLES: &[&str] = &["audit_events"];

/// Resource tables a rename must COPY under the new name and then delete under
/// the old one, parent-first, in exactly this order.
///
/// Since issue #4627 `proxies`, `upstreams`, `plugin_configs`, and `api_specs`
/// key on `(namespace, id)` and `proxy_plugins` keys on
/// `(namespace, proxy_id, plugin_config_id)`, and every relationship between
/// them is namespace-qualified. That makes an in-place
/// `UPDATE <table> SET namespace = ?` impossible: moving a parent orphans its
/// children, and moving a child points it at a parent that has not moved, so no
/// ordering of such updates keeps every constraint satisfied at statement
/// boundaries. `consumers` and `gateway_trust_bundles` already used the
/// copy-then-delete shape for the same reason.
///
/// The order below is the INSERT order; deletes run in reverse. Each entry is
/// the complete column list of the table in `V001SqlBuilder`; the `namespace`
/// entry becomes the bound new name in the `SELECT` projection.
/// `sql_namespace_rename_copy_plan_matches_baseline_schema` in
/// `tests/unit/config/db_loader_tests.rs` fails if a column is added to one of
/// these tables without being added here.
pub const NAMESPACE_RENAME_COPY_TABLES: &[(&str, &[&str])] = &[
    (
        "upstreams",
        &[
            "labels",
            "id",
            "namespace",
            "name",
            "targets",
            "algorithm",
            "hash_on",
            "hash_on_cookie_config",
            "health_checks",
            "service_discovery",
            "subsets",
            "backend_tls_client_cert_path",
            "backend_tls_client_key_path",
            "backend_tls_verify_server_cert",
            "backend_tls_server_ca_cert_path",
            "backend_tls_sni",
            "backend_tls_san_allow_list",
            "api_spec_id",
            "created_at",
            "updated_at",
        ],
    ),
    (
        "proxies",
        &[
            "labels",
            "id",
            "namespace",
            "name",
            "hosts",
            "listen_path",
            "backend_scheme",
            "backend_host",
            "backend_port",
            "backend_path",
            "strip_listen_path",
            "preserve_host_header",
            "backend_connect_timeout_ms",
            "backend_read_timeout_ms",
            "backend_write_timeout_ms",
            "backend_tls_client_cert_path",
            "backend_tls_client_key_path",
            "backend_tls_verify_server_cert",
            "backend_tls_server_ca_cert_path",
            "dns_override",
            "dns_cache_ttl_seconds",
            "auth_mode",
            "upstream_id",
            "upstream_subset",
            "circuit_breaker",
            "retry",
            "response_body_mode",
            "pool_idle_timeout_seconds",
            "pool_enable_http_keep_alive",
            "pool_enable_http2",
            "pool_tcp_keepalive_seconds",
            "pool_http2_keep_alive_interval_seconds",
            "pool_http2_keep_alive_timeout_seconds",
            "pool_http2_initial_stream_window_size",
            "pool_http2_initial_connection_window_size",
            "pool_http2_adaptive_window",
            "pool_http2_max_frame_size",
            "pool_http2_max_concurrent_streams",
            "pool_http3_connections_per_backend",
            "pool_max_requests_per_connection",
            "listen_port",
            "frontend_tls",
            "passthrough",
            "udp_idle_timeout_seconds",
            "tcp_idle_timeout_seconds",
            "websocket_idle_timeout_seconds",
            "allowed_methods",
            "allowed_ws_origins",
            "udp_max_response_amplification_factor",
            "stream_proxy_protocol",
            "backend_proxy_protocol",
            "stream_match",
            "api_spec_id",
            "created_at",
            "updated_at",
        ],
    ),
    (
        "plugin_configs",
        &[
            "labels",
            "id",
            "namespace",
            "plugin_name",
            "config",
            "scope",
            "proxy_id",
            "enabled",
            "priority_override",
            "trigger_json",
            "api_spec_id",
            "created_at",
            "updated_at",
        ],
    ),
    (
        "proxy_plugins",
        &["namespace", "proxy_id", "plugin_config_id"],
    ),
    (
        "api_specs",
        &[
            "id",
            "namespace",
            "proxy_id",
            "spec_version",
            "spec_format",
            "spec_content",
            "content_encoding",
            "uncompressed_size",
            "content_hash",
            "title",
            "info_version",
            "description",
            "contact_name",
            "contact_email",
            "license_name",
            "license_identifier",
            "tags",
            "server_urls",
            "operation_count",
            "resource_hash",
            "external_ref_snapshot",
            "external_ref_digest",
            "created_at",
            "updated_at",
        ],
    ),
];

/// One canonical trim/length rule for `description`, shared by create and
/// update. Trims surrounding whitespace, maps empty to absent, and rejects
/// anything longer than [`MAX_NAMESPACE_DESCRIPTION_CHARS`] **characters**
/// (Unicode scalar values), matching the OpenAPI `maxLength` semantics.
pub fn normalize_description(description: Option<String>) -> Result<Option<String>, String> {
    let Some(raw) = description else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let characters = trimmed.chars().count();
    if characters > MAX_NAMESPACE_DESCRIPTION_CHARS {
        return Err(format!(
            "description must be at most {MAX_NAMESPACE_DESCRIPTION_CHARS} characters, got {characters}"
        ));
    }
    Ok(Some(trimmed.to_string()))
}

pub fn validate_namespace_name(name: &str) -> Result<(), String> {
    validate_namespace(name)
}

/// Typed persist errors so admin handlers can map to a documented status
/// without inspecting driver text.
#[derive(Debug)]
pub enum NamespaceRegistryError {
    NameInUse { name: String },
    NotFound { name: String },
    NotEmpty { name: String },
    Protected { name: String, reason: &'static str },
}

impl NamespaceRegistryError {
    /// Reason text for a namespace this process is configured to serve.
    ///
    /// A rename is semantically a removal of the old name, so both DELETE and
    /// rename-away use this. The text is a fixed constant: it names the two
    /// configuration keys an operator can change and never echoes the rest of
    /// the configured set, so a 409 cannot be used to enumerate which other
    /// tenants this gateway serves.
    pub const PROTECTED_CONFIGURED_NAMESPACE: &str = "it is one of the namespaces this gateway is configured to serve \
         (FERRUM_NAMESPACE / FERRUM_CP_NAMESPACES)";
    /// Last **registry row**, not last derived resource name. Resource writers
    /// do not take the global registry lease, so they cannot be the authority.
    pub const PROTECTED_LAST_REMAINING: &str = "it is the last remaining namespace";

    pub fn not_found(name: &str) -> anyhow::Error {
        anyhow::Error::new(Self::NotFound {
            name: name.to_string(),
        })
    }

    pub fn name_in_use(name: &str) -> anyhow::Error {
        anyhow::Error::new(Self::NameInUse {
            name: name.to_string(),
        })
    }

    pub fn not_empty(name: &str) -> anyhow::Error {
        anyhow::Error::new(Self::NotEmpty {
            name: name.to_string(),
        })
    }

    pub fn protected(name: &str, reason: &'static str) -> anyhow::Error {
        anyhow::Error::new(Self::Protected {
            name: name.to_string(),
            reason,
        })
    }
}

impl std::fmt::Display for NamespaceRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NameInUse { name } => {
                write!(f, "namespace '{name}' already exists")
            }
            Self::NotFound { name } => write!(f, "namespace '{name}' not found"),
            Self::NotEmpty { name } => write!(
                f,
                "namespace '{name}' still has resources; pass ?confirm=true to cascade-delete them"
            ),
            Self::Protected { name, reason } => {
                write!(f, "namespace '{name}' cannot be removed: {reason}")
            }
        }
    }
}

impl std::error::Error for NamespaceRegistryError {}

/// Durable registry row that cannot be interpreted as a [`NamespaceRecord`].
///
/// The payload is a schema field name only. It never carries the stored name,
/// timestamp, description, or driver text — those can be hostile or
/// PII-bearing and must not appear in client or log output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceRegistryCorrupt {
    field: &'static str,
}

impl NamespaceRegistryCorrupt {
    pub const MESSAGE: &'static str =
        "durable namespace registry record is corrupt and cannot be served";

    pub fn field(field: &'static str) -> Self {
        Self { field }
    }

    pub fn into_error(self) -> anyhow::Error {
        anyhow::Error::new(self)
    }
}

impl std::fmt::Display for NamespaceRegistryCorrupt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", Self::MESSAGE, self.field)
    }
}

impl std::error::Error for NamespaceRegistryCorrupt {}

pub fn is_namespace_registry_error(error: &anyhow::Error) -> Option<&NamespaceRegistryError> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<NamespaceRegistryError>())
}

/// Stable admin-facing message for a registry mutation the database aborted as
/// a concurrency conflict.
///
/// Fixed and redacted on purpose: the driver's own text names the relation, the
/// conflicting transaction, and sometimes the row, none of which may reach a
/// client or a log line.
pub const NAMESPACE_REGISTRY_RETRYABLE_CONFLICT_MESSAGE: &str = "The namespace registry mutation conflicted with a concurrent database transaction and was \
     rolled back; nothing was applied. Retry the request.";

/// The committing transaction was aborted by the database itself as a
/// serialization failure or deadlock victim.
///
/// This is a *fail-closed* outcome, not a partial one: the abort happens before
/// commit, so no registry row, resource row, or change-log tombstone is
/// durable. It is distinct from a lost admission lease (the lease was still
/// held; the datastore simply refused to serialize the two transactions) and
/// from a name conflict (which is a real, non-retryable 409).
///
/// Concretely, PostgreSQL under `REPEATABLE READ` can raise `40001`
/// (`serialization_failure`) or `40P01` (`deadlock_detected`) when the
/// independent admission renewer updates `config_admission_locks` between this
/// transaction's snapshot and its final `SELECT ... FOR UPDATE` on the same
/// rows. MySQL reports a deadlock victim with the same `40001` SQLSTATE.
#[derive(Debug)]
pub struct NamespaceRegistryRetryableConflict;

impl std::fmt::Display for NamespaceRegistryRetryableConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(NAMESPACE_REGISTRY_RETRYABLE_CONFLICT_MESSAGE)
    }
}

impl std::error::Error for NamespaceRegistryRetryableConflict {}

pub fn is_namespace_registry_retryable_conflict(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.is::<NamespaceRegistryRetryableConflict>())
}

/// Stable admin-facing message for a registry mutation the configured database
/// deployment cannot perform with the documented guarantee.
pub const NAMESPACE_REGISTRY_ATOMICITY_UNSUPPORTED_MESSAGE: &str =
    "Namespace registry mutations are not supported by the configured database deployment";

/// The configured backend cannot commit a namespace registry mutation
/// all-or-nothing with a commit-boundary admission check.
///
/// This is a deployment property, not a property of the request: standalone
/// MongoDB has no multi-document transactions, so a rename or cascade delete
/// could strand a half-moved tenant and even a single-document write could not
/// be fenced against a stolen admission lease. The only way to keep the
/// documented guarantee is to refuse before mutating anything.
#[derive(Debug, Clone)]
pub struct NamespaceRegistryAtomicityUnsupported {
    detail: String,
}

impl NamespaceRegistryAtomicityUnsupported {
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }

    /// Operator-actionable remediation. Safe to return to an authenticated
    /// admin caller: it names configuration, never schema or driver internals.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl std::fmt::Display for NamespaceRegistryAtomicityUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{NAMESPACE_REGISTRY_ATOMICITY_UNSUPPORTED_MESSAGE}: {}",
            self.detail
        )
    }
}

impl std::error::Error for NamespaceRegistryAtomicityUnsupported {}

pub fn is_namespace_registry_corrupt(error: &anyhow::Error) -> Option<&NamespaceRegistryCorrupt> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<NamespaceRegistryCorrupt>())
}

/// Canonical admission-key sequence for a namespace-registry mutation.
///
/// The global [`NAMESPACE_REGISTRY_ADMISSION_KEY`] is always first, followed
/// by the affected tenant names sorted and de-duplicated — the same sequence
/// the registry admission helper acquires.
/// Create and delete pass one tenant name; a description-only update
/// de-duplicates source and target; a rename passes both names.
pub fn namespace_registry_admission_keys(names: &[&str]) -> Vec<String> {
    let mut keys = vec![NAMESPACE_REGISTRY_ADMISSION_KEY.to_string()];
    let mut sorted: Vec<&str> = names.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    keys.extend(sorted.into_iter().map(str::to_string));
    keys
}

/// Fail closed unless `supplied_keys` is exactly
/// [`namespace_registry_admission_keys`] for `names`.
///
/// Empty, missing, extra, duplicated, reordered, or wrong-key slices cannot
/// fence a registry mutation. The error is the static
/// [`BatchAdmissionLeaseLost`] message and never echoes supplied keys,
/// owners, or generations.
pub fn require_namespace_registry_admission_keys(
    names: &[&str],
    supplied_keys: &[&str],
) -> Result<(), BatchAdmissionLeaseLost> {
    let expected = namespace_registry_admission_keys(names);
    if supplied_keys.len() != expected.len()
        || supplied_keys
            .iter()
            .zip(expected.iter())
            .any(|(got, want)| *got != want.as_str())
    {
        return Err(BatchAdmissionLeaseLost);
    }
    Ok(())
}

/// Fail closed unless `leases` carries exactly the canonical key sequence for
/// `names`. Owner and generation validity is re-checked inside the committing
/// transaction against datastore time; this gate only proves the *set* is the
/// one the admission helper produced.
pub fn require_namespace_registry_admission_leases(
    names: &[&str],
    leases: &[NamespaceAdmissionLeaseHold<'_>],
) -> Result<(), BatchAdmissionLeaseLost> {
    let supplied: Vec<&str> = leases.iter().map(|hold| hold.key).collect();
    require_namespace_registry_admission_keys(names, &supplied)
}

/// Sorted, de-duplicated namespace names whose mTLS DNS admission fences a
/// registry update must hold.
///
/// A rename writes resources into `new_name`, so both the source and the
/// target fences are required (a retained guarded-restore owner on the target
/// would otherwise be bypassed once the target config lease is free). A
/// description-only update needs only the current name. Callers acquire in
/// this order so SQL row locks and Mongo multi-lease acquisition cannot
/// deadlock.
pub fn mtls_dns_admission_namespaces<'a>(current_name: &'a str, new_name: &'a str) -> Vec<&'a str> {
    let mut names = vec![current_name];
    if new_name != current_name {
        names.push(new_name);
    }
    names.sort_unstable();
    names.dedup();
    names
}

/// Strict RFC 3339 timestamp. Never invents `Utc::now()` for a missing or
/// malformed durable value, and never echoes `raw` in the error.
pub fn parse_namespace_rfc3339(
    raw: &str,
    field: &'static str,
) -> Result<DateTime<Utc>, NamespaceRegistryCorrupt> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| NamespaceRegistryCorrupt::field(field))
}

/// Require a non-empty string `_id`/`name` pair that agrees with itself and,
/// when the caller requested a specific key, with that key. The agreed name
/// must also pass [`validate_namespace`]: a durable row whose identity pair
/// is consistent but illegal as a namespace is still corrupt. Failures map
/// to [`NamespaceRegistryCorrupt`] without the stored value or validator text.
pub fn require_namespace_identity(
    id: &str,
    name: &str,
    expected: Option<&str>,
) -> Result<String, NamespaceRegistryCorrupt> {
    if id.is_empty() || name.is_empty() || id != name {
        return Err(NamespaceRegistryCorrupt::field("name"));
    }
    if let Some(expected) = expected
        && id != expected
    {
        return Err(NamespaceRegistryCorrupt::field("name"));
    }
    if validate_namespace(name).is_err() {
        return Err(NamespaceRegistryCorrupt::field("name"));
    }
    Ok(name.to_string())
}

/// Strict parser for a durable registry description.
///
/// Writes store only SQL/BSON null (absence) or a trimmed nonempty string of
/// at most [`MAX_NAMESPACE_DESCRIPTION_CHARS`] Unicode scalar values. Empty,
/// whitespace-only, untrimmed, and over-limit strings are corruption — they
/// are not normalized or served. The error names the schema field only.
pub fn require_canonical_stored_description(
    description: Option<&str>,
) -> Result<Option<String>, NamespaceRegistryCorrupt> {
    let Some(raw) = description else {
        return Ok(None);
    };
    if raw.is_empty() || raw.trim() != raw || raw.chars().count() > MAX_NAMESPACE_DESCRIPTION_CHARS
    {
        return Err(NamespaceRegistryCorrupt::field("description"));
    }
    Ok(Some(raw.to_string()))
}

/// Document field that must equal the `{namespace}:` suffix for a composite-id
/// collection rewritten during namespace rename.
pub fn namespace_prefixed_id_suffix_field(
    collection_name: &str,
) -> Result<&'static str, NamespaceRegistryCorrupt> {
    match collection_name {
        // Every namespaced resource collection keys on the composite
        // `"{namespace}:{id}"` — consumers since issue #2121, the other four
        // since issue #4627 — and carries the bare value in `id`.
        "consumers" | "proxies" | "upstreams" | "plugin_configs" | "api_specs" => Ok("id"),
        "consumer_identity_index" => Ok("identity_value"),
        _ => Err(NamespaceRegistryCorrupt::field("identity")),
    }
}

/// Fail closed unless a composite Mongo `_id` is exactly
/// `{current_name}:{suffix}` with a nonempty suffix that equals the
/// collection's identity field, and the embedded `namespace` string equals
/// `current_name`. Missing, empty, or mismatched fields are corruption.
/// The error names the schema field only and never echoes stored values.
pub fn require_namespace_prefixed_identity<'a>(
    current_name: &str,
    old_id: &'a str,
    embedded_namespace: Option<&str>,
    suffix_field: &'static str,
    suffix_value: Option<&str>,
) -> Result<&'a str, NamespaceRegistryCorrupt> {
    let expected_prefix = format!("{current_name}:");
    let Some(suffix) = old_id.strip_prefix(&expected_prefix) else {
        return Err(NamespaceRegistryCorrupt::field("identity"));
    };
    if suffix.is_empty() {
        return Err(NamespaceRegistryCorrupt::field("identity"));
    }
    match embedded_namespace {
        Some(value) if !value.is_empty() && value == current_name => {}
        _ => return Err(NamespaceRegistryCorrupt::field("namespace")),
    }
    match suffix_value {
        Some(value) if !value.is_empty() && value == suffix => {}
        _ => return Err(NamespaceRegistryCorrupt::field(suffix_field)),
    }
    Ok(suffix)
}

/// Fail closed unless a namespace-keyed document's embedded `namespace`
/// exists as a nonempty string and exactly equals the current key. A
/// mismatch aborts rather than rewriting the field onto a corrupt document.
pub fn require_namespace_keyed_embedded_namespace(
    current_key: &str,
    embedded_namespace: Option<&str>,
) -> Result<(), NamespaceRegistryCorrupt> {
    match embedded_namespace {
        Some(value) if !value.is_empty() && value == current_key => Ok(()),
        _ => Err(NamespaceRegistryCorrupt::field("namespace")),
    }
}

/// Fail closed unless a namespace-keyed document's durable `_id`, embedded
/// `namespace`, and resource `id` all agree with `current_name`.
///
/// `_id` and the embedded namespace must equal `current_name`. The resource
/// identity must be a nonempty string (it defaults to the namespace but may
/// be an operator-chosen address). Missing, empty, or mismatched fields are
/// corruption. The error names the schema field only and never echoes stored
/// values.
pub fn require_namespace_keyed_identity(
    current_name: &str,
    old_id: &str,
    embedded_namespace: Option<&str>,
    resource_id: Option<&str>,
) -> Result<String, NamespaceRegistryCorrupt> {
    if old_id.is_empty() || old_id != current_name {
        return Err(NamespaceRegistryCorrupt::field("identity"));
    }
    require_namespace_keyed_embedded_namespace(current_name, embedded_namespace)?;
    match resource_id {
        Some(id) if !id.is_empty() => Ok(id.to_string()),
        _ => Err(NamespaceRegistryCorrupt::field("id")),
    }
}

pub fn namespace_registry_atomicity_unsupported(
    error: &anyhow::Error,
) -> Option<&NamespaceRegistryAtomicityUnsupported> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<NamespaceRegistryAtomicityUnsupported>())
}

/// Deterministic, test-installed abort points inside a registry mutation
/// transaction.
///
/// Happy-path tests cannot prove the all-or-nothing claim: a duplicate key can
/// only fail where the duplicate is. These phases reach the *late* steps of a
/// cascade delete and a rename, so a rollback can be observed after resource
/// rows, ancillary rows, and the registry row have already been written inside
/// the transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceRegistryPhase {
    /// Before any statement in the mutation transaction.
    Start,
    /// After resource rows were removed or rewritten.
    Resources,
    /// After ancillary lock / retention / index rows.
    Ancillary,
    /// After the registry row itself.
    RegistryRow,
    /// After the last-remaining-namespace invariant re-check.
    LastNamespaceCheck,
    /// At the commit-boundary lease verification, reported as a lost lease so
    /// the retryable fail-closed 503 mapping is exercised end to end.
    LeaseLost,
    /// At the commit-boundary lease verification, reported as the database
    /// aborting the transaction as a serialization failure / deadlock victim.
    ///
    /// A real `40001` / `40P01` needs two racing PostgreSQL transactions and
    /// the 30-second admission renewer, which no deterministic test can stage.
    /// This phase injects the already-classified typed conflict at exactly the
    /// point the real abort surfaces, so the documented `503` +
    /// `Retry-After: 1` + `rollback: not_needed` response is exercised end to
    /// end. The SQLSTATE classification itself is covered separately.
    TransactionConflict,
    /// Immediately before the single commit.
    Commit,
}

impl NamespaceRegistryPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Resources => "resources",
            Self::Ancillary => "ancillary",
            Self::RegistryRow => "registry_row",
            Self::LastNamespaceCheck => "last_namespace_check",
            Self::LeaseLost => "lease_lost",
            Self::TransactionConflict => "transaction_conflict",
            Self::Commit => "commit",
        }
    }

    pub fn error(self) -> anyhow::Error {
        if self == Self::LeaseLost {
            return anyhow::Error::new(BatchAdmissionLeaseLost).context(
                "injected namespace registry fault: the admission lease was reported lost at the \
                 commit boundary",
            );
        }
        if self == Self::TransactionConflict {
            return anyhow::Error::new(NamespaceRegistryRetryableConflict).context(
                "injected namespace registry fault: the database aborted the transaction at the \
                 commit boundary",
            );
        }
        anyhow::anyhow!(
            "injected namespace registry fault at phase '{}'",
            self.as_str()
        )
    }
}

/// Per-namespace test overrides. Empty in production, gated behind one relaxed
/// atomic load so registry writes never touch the map or its lock.
static ANY_REGISTRY_FAULT: AtomicBool = AtomicBool::new(false);
static REGISTRY_FAULTS: OnceLock<Mutex<HashMap<String, NamespaceRegistryPhase>>> = OnceLock::new();

fn registry_faults() -> MutexGuard<'static, HashMap<String, NamespaceRegistryPhase>> {
    REGISTRY_FAULTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Install (or clear, with `None`) a deterministic abort for `namespace`.
///
/// Keyed per namespace so tests sharing one process cannot perturb each other.
pub(crate) fn set_namespace_registry_fault(namespace: &str, phase: Option<NamespaceRegistryPhase>) {
    let mut faults = registry_faults();
    match phase {
        Some(phase) => {
            faults.insert(namespace.to_string(), phase);
        }
        None => {
            faults.remove(namespace);
        }
    }
    let any = !faults.is_empty();
    ANY_REGISTRY_FAULT.store(any, Ordering::Release);
}

/// Resolve the fault for one mutation. Called once per registry write, never
/// per statement: production takes a single acquire load and returns.
pub fn namespace_registry_fault(namespace: &str) -> Option<NamespaceRegistryPhase> {
    if !ANY_REGISTRY_FAULT.load(Ordering::Acquire) {
        return None;
    }
    registry_faults().get(namespace).copied()
}

pub(crate) fn check_namespace_registry_fault(
    fault: Option<NamespaceRegistryPhase>,
    phase: NamespaceRegistryPhase,
) -> Result<(), anyhow::Error> {
    match fault {
        Some(installed) if installed == phase => Err(installed.error()),
        _ => Ok(()),
    }
}
