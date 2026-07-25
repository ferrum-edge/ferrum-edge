//! Canonical MongoDB index / collection plan for migrate `up`, dry-run, and status.
//!
//! `MongoStore::run_migrations`, migrate dry-run output, and migrate status all
//! consume [`required_mongo_indexes`] / [`required_guard_collections`] so the
//! operator-facing plan cannot drift from the indexes `up` actually ensures.

use mongodb::IndexModel;
use mongodb::bson::{Document, doc};
use mongodb::options::IndexOptions;

/// Projection field stamped onto consumer documents for the HMAC secret-hash
/// uniqueness index. Must stay identical to the field written by
/// `MongoStore` consumer encode paths.
pub const HMAC_SECRET_HASHES_FIELD: &str = "_ferrum_hmac_secret_hashes";

/// Empty shell collections that must exist before transactional writes (MongoDB
/// < 4.4 cannot implicitly create collections inside a transaction).
pub const REQUIRED_GUARD_COLLECTIONS: &[&str] = &[
    "proxy_route_locks",
    "upstream_ref_guards",
    "mtls_dns_admission_locks",
];

/// One required index in the baseline MongoDB migration plan.
#[derive(Clone, Debug)]
pub struct RequiredMongoIndex {
    pub collection: &'static str,
    pub model: IndexModel,
    /// When `createIndex` raises IndexOptionsConflict / IndexKeySpecsConflict,
    /// drop the default-named legacy index and recreate. Used for the
    /// api_specs `(namespace, proxy_id)` unique+partial upgrade path.
    pub recreate_on_options_conflict: bool,
}

/// Classification of a required index against a live `listIndexes` snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexPresence {
    Present,
    Missing,
    Mismatched { detail: String },
}

/// One row in a status report.
#[derive(Clone, Debug)]
pub struct IndexStatusEntry {
    pub collection: &'static str,
    pub summary: String,
    pub presence: IndexPresence,
}

/// One required empty-shell collection in a status report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardCollectionStatusEntry {
    pub collection: &'static str,
    pub present: bool,
}

/// Complete non-mutating comparison of the live database against the
/// canonical MongoDB migration plan.
#[derive(Clone, Debug)]
pub struct MongoMigrationStatus {
    pub indexes: Vec<IndexStatusEntry>,
    pub guard_collections: Vec<GuardCollectionStatusEntry>,
}

/// Build the baseline index plan. This is the single source of truth for
/// `up`, dry-run, and status.
pub fn required_mongo_indexes() -> Vec<RequiredMongoIndex> {
    let mut plan = Vec::with_capacity(48);

    // proxies — uniqueness scoped to namespace.
    // Intentionally NO unique index on (namespace, listen_path): path uniqueness
    // is host-scoped and enforced at the application layer.
    // No standalone {namespace} index: covered by {namespace, updated_at}.
    plan.push(unique_partial(
        "proxies",
        doc! { "namespace": 1, "name": 1 },
        doc! { "name": { "$type": "string" } },
    ));
    plan.push(keys_only("proxies", doc! { "updated_at": 1 }));
    plan.push(keys_only("proxies", doc! { "upstream_id": 1 }));
    plan.push(keys_only("proxies", doc! { "plugins.plugin_config_id": 1 }));
    plan.push(unique_partial(
        "proxies",
        doc! { "namespace": 1, "listen_port": 1 },
        doc! { "listen_port": { "$type": "number" } },
    ));
    plan.push(keys_only(
        "proxies",
        doc! { "namespace": 1, "updated_at": 1 },
    ));
    plan.push(keys_only("proxies", doc! { "namespace": 1, "_id": 1 }));

    // consumers — `_id` is already `{namespace}:{id}`; username/custom_id/
    // credential uniqueness are secondary guards.
    plan.push(unique_keys(
        "consumers",
        doc! { "namespace": 1, "username": 1 },
    ));
    plan.push(unique_partial(
        "consumers",
        doc! { "namespace": 1, "custom_id": 1 },
        doc! { "custom_id": { "$type": "string" } },
    ));
    plan.push(unique_partial(
        "consumers",
        doc! { "namespace": 1, "credentials.keyauth.key": 1 },
        doc! { "credentials.keyauth.key": { "$type": "string" } },
    ));
    plan.push(unique_partial(
        "consumers",
        doc! { "namespace": 1, "credentials.mtls_auth.identity": 1 },
        doc! { "credentials.mtls_auth.identity": { "$type": "string" } },
    ));
    plan.push(unique_partial(
        "consumers",
        doc! { "namespace": 1, HMAC_SECRET_HASHES_FIELD: 1 },
        doc! { HMAC_SECRET_HASHES_FIELD: { "$type": "string" } },
    ));
    plan.push(keys_only("consumers", doc! { "updated_at": 1 }));
    plan.push(keys_only(
        "consumers",
        doc! { "namespace": 1, "updated_at": 1 },
    ));
    plan.push(keys_only("consumers", doc! { "namespace": 1, "_id": 1 }));

    // consumer_identity_index — `_id` uniqueness is the atomic guard; the
    // non-unique {namespace} index supports namespace wipes / cleanup filters.
    plan.push(keys_only(
        "consumer_identity_index",
        doc! { "namespace": 1 },
    ));

    // plugin_configs
    plan.push(keys_only("plugin_configs", doc! { "proxy_id": 1 }));
    plan.push(keys_only("plugin_configs", doc! { "updated_at": 1 }));
    plan.push(keys_only(
        "plugin_configs",
        doc! { "namespace": 1, "updated_at": 1 },
    ));
    plan.push(keys_only(
        "plugin_configs",
        doc! { "namespace": 1, "_id": 1 },
    ));
    plan.push(keys_only(
        "plugin_configs",
        doc! { "namespace": 1, "scope": 1 },
    ));
    plan.push(keys_only("plugin_configs", doc! { "scope": 1, "_id": 1 }));
    plan.push(keys_only(
        "plugin_configs",
        doc! { "namespace": 1, "plugin_name": 1 },
    ));
    plan.push(RequiredMongoIndex {
        collection: "plugin_configs",
        model: IndexModel::builder()
            .keys(doc! { "plugin_name": 1, "enabled": 1 })
            .options(
                IndexOptions::builder()
                    .partial_filter_expression(doc! { "enabled": true })
                    .build(),
            )
            .build(),
        recreate_on_options_conflict: false,
    });
    plan.push(sparse_keys("plugin_configs", doc! { "api_spec_id": 1 }));

    // upstreams
    plan.push(unique_partial(
        "upstreams",
        doc! { "namespace": 1, "name": 1 },
        doc! { "name": { "$type": "string" } },
    ));
    plan.push(keys_only("upstreams", doc! { "updated_at": 1 }));
    plan.push(sparse_keys("upstreams", doc! { "api_spec_id": 1 }));
    plan.push(keys_only(
        "upstreams",
        doc! { "namespace": 1, "updated_at": 1 },
    ));
    plan.push(keys_only("upstreams", doc! { "namespace": 1, "_id": 1 }));

    // api_specs — unique (namespace, proxy_id) with partial filter; recreates
    // over the legacy unique-only same-keyed index on IndexOptionsConflict.
    plan.push(RequiredMongoIndex {
        collection: "api_specs",
        model: IndexModel::builder()
            .keys(doc! { "namespace": 1, "proxy_id": 1 })
            .options(
                IndexOptions::builder()
                    .unique(true)
                    .partial_filter_expression(doc! {
                        "proxy_id": { "$type": "string" }
                    })
                    .build(),
            )
            .build(),
        recreate_on_options_conflict: true,
    });
    plan.push(keys_only("api_specs", doc! { "proxy_id": 1 }));
    plan.push(keys_only(
        "api_specs",
        doc! { "namespace": 1, "updated_at": 1 },
    ));
    plan.push(keys_only(
        "api_specs",
        doc! { "namespace": 1, "spec_version": 1 },
    ));
    plan.push(keys_only(
        "api_specs",
        doc! { "namespace": 1, "operation_count": 1 },
    ));
    plan.push(keys_only(
        "api_specs",
        doc! { "namespace": 1, "created_at": -1 },
    ));
    plan.push(keys_only("api_specs", doc! { "namespace": 1, "tags": 1 }));

    // audit_events
    plan.push(keys_only("audit_events", doc! { "namespace": 1, "ts": -1 }));
    plan.push(keys_only("audit_events", doc! { "actor": 1 }));
    plan.push(keys_only(
        "audit_events",
        doc! { "namespace": 1, "action": 1 },
    ));
    plan.push(keys_only("audit_events", doc! { "resource_type": 1 }));
    plan.push(keys_only(
        "audit_events",
        doc! { "namespace": 1, "resource_id": 1 },
    ));

    // config_changes
    plan.push(keys_only(
        "config_changes",
        doc! { "namespace": 1, "sequence": 1 },
    ));
    plan.push(keys_only("config_changes", doc! { "sequence": 1 }));

    plan
}

/// Human-readable dry-run lines generated from the canonical plan (no I/O).
pub fn dry_run_lines() -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(
        "MongoDB dry run: indexes that would be created/verified (canonical plan):".to_string(),
    );

    let plan = required_mongo_indexes();
    let mut current_collection = "";
    for entry in &plan {
        if entry.collection != current_collection {
            current_collection = entry.collection;
            lines.push(format!("  {current_collection}:"));
        }
        let mut summary = summarize_index(&entry.model);
        if entry.recreate_on_options_conflict {
            summary.push_str(" (recreate on options conflict)");
        }
        lines.push(format!("    - {summary}"));
    }

    lines.push("  collections ensured (empty shell):".to_string());
    for name in REQUIRED_GUARD_COLLECTIONS {
        lines.push(format!("    - {name}"));
    }
    lines
}

/// Classify every required index against a map of collection → live indexes.
///
/// `live_by_collection` should omit collections that do not exist yet (treated
/// as empty / all-missing). Extra live indexes not in the plan are ignored.
pub fn classify_plan_against_live(
    live_by_collection: &std::collections::HashMap<String, Vec<IndexModel>>,
) -> Vec<IndexStatusEntry> {
    required_mongo_indexes()
        .into_iter()
        .map(|entry| {
            let live = live_by_collection
                .get(entry.collection)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let presence = classify_required_index(&entry.model, live);
            IndexStatusEntry {
                collection: entry.collection,
                summary: summarize_index(&entry.model),
                presence,
            }
        })
        .collect()
}

/// Classify every required guard collection against live collection names.
pub fn classify_guard_collections(
    live_collection_names: &std::collections::HashSet<String>,
) -> Vec<GuardCollectionStatusEntry> {
    REQUIRED_GUARD_COLLECTIONS
        .iter()
        .map(|collection| GuardCollectionStatusEntry {
            collection,
            present: live_collection_names.contains(*collection),
        })
        .collect()
}

/// Compare one required index model to a live `listIndexes` snapshot.
pub fn classify_required_index(required: &IndexModel, live: &[IndexModel]) -> IndexPresence {
    let candidates = live
        .iter()
        .filter(|idx| idx.keys == required.keys)
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return IndexPresence::Missing;
    }

    let mut mismatches = Vec::new();
    for candidate in candidates {
        match compare_index_options(required.options.as_ref(), candidate.options.as_ref()) {
            Ok(()) => return IndexPresence::Present,
            Err(detail) => mismatches.push(detail),
        }
    }
    IndexPresence::Mismatched {
        detail: mismatches.join("; "),
    }
}

/// Default MongoDB index name derived from keys (matches driver `update_name`).
pub fn default_index_name(keys: &Document) -> String {
    keys.iter()
        .map(|(field, value)| match value {
            mongodb::bson::Bson::String(s) => format!("{field}_{s}"),
            other => format!("{field}_{other}"),
        })
        .collect::<Vec<_>>()
        .join("_")
}

/// Compact single-line description of keys + Ferrum-relevant options.
pub fn summarize_index(model: &IndexModel) -> String {
    let keys = format_keys(&model.keys);
    let mut parts = vec![keys];
    if let Some(opts) = model.options.as_ref() {
        if opts.unique.unwrap_or(false) {
            parts.push("unique".to_string());
        }
        if opts.sparse.unwrap_or(false) {
            parts.push("sparse".to_string());
        }
        if let Some(filter) = opts.partial_filter_expression.as_ref() {
            parts.push(format!("partialFilterExpression={filter}"));
        }
    }
    parts.join(" ")
}

fn keys_only(collection: &'static str, keys: Document) -> RequiredMongoIndex {
    RequiredMongoIndex {
        collection,
        model: IndexModel::builder().keys(keys).build(),
        recreate_on_options_conflict: false,
    }
}

fn unique_keys(collection: &'static str, keys: Document) -> RequiredMongoIndex {
    RequiredMongoIndex {
        collection,
        model: IndexModel::builder()
            .keys(keys)
            .options(IndexOptions::builder().unique(true).build())
            .build(),
        recreate_on_options_conflict: false,
    }
}

fn unique_partial(
    collection: &'static str,
    keys: Document,
    partial: Document,
) -> RequiredMongoIndex {
    RequiredMongoIndex {
        collection,
        model: IndexModel::builder()
            .keys(keys)
            .options(
                IndexOptions::builder()
                    .unique(true)
                    .partial_filter_expression(partial)
                    .build(),
            )
            .build(),
        recreate_on_options_conflict: false,
    }
}

fn sparse_keys(collection: &'static str, keys: Document) -> RequiredMongoIndex {
    RequiredMongoIndex {
        collection,
        model: IndexModel::builder()
            .keys(keys)
            .options(IndexOptions::builder().sparse(true).build())
            .build(),
        recreate_on_options_conflict: false,
    }
}

fn format_keys(keys: &Document) -> String {
    let inner = keys
        .iter()
        .map(|(field, value)| format!("{field}: {value}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{{inner}}}")
}

fn effective_bool(value: Option<bool>) -> bool {
    value.unwrap_or(false)
}

fn compare_index_options(
    required: Option<&IndexOptions>,
    live: Option<&IndexOptions>,
) -> Result<(), String> {
    let req_unique = required.map(|o| effective_bool(o.unique)).unwrap_or(false);
    let live_unique = live.map(|o| effective_bool(o.unique)).unwrap_or(false);
    if req_unique != live_unique {
        return Err(format!("unique expected={req_unique} found={live_unique}"));
    }

    let req_sparse = required.map(|o| effective_bool(o.sparse)).unwrap_or(false);
    let live_sparse = live.map(|o| effective_bool(o.sparse)).unwrap_or(false);
    if req_sparse != live_sparse {
        return Err(format!("sparse expected={req_sparse} found={live_sparse}"));
    }

    let req_partial = required.and_then(|o| o.partial_filter_expression.as_ref());
    let live_partial = live.and_then(|o| o.partial_filter_expression.as_ref());
    match (req_partial, live_partial) {
        (None, None) => {}
        (Some(expected), Some(found)) if expected == found => {}
        (Some(expected), Some(found)) => {
            return Err(format!(
                "partialFilterExpression expected={expected} found={found}"
            ));
        }
        (Some(expected), None) => {
            return Err(format!(
                "partialFilterExpression expected={expected} found=<none>"
            ));
        }
        (None, Some(found)) => {
            return Err(format!(
                "partialFilterExpression expected=<none> found={found}"
            ));
        }
    }

    let req_expire = required.and_then(|o| o.expire_after);
    let live_expire = live.and_then(|o| o.expire_after);
    if req_expire != live_expire {
        return Err(format!(
            "expireAfterSeconds expected={req_expire:?} found={live_expire:?}"
        ));
    }

    let req_hidden = required.map(|o| effective_bool(o.hidden)).unwrap_or(false);
    let live_hidden = live.map(|o| effective_bool(o.hidden)).unwrap_or(false);
    if req_hidden != live_hidden {
        return Err(format!("hidden expected={req_hidden} found={live_hidden}"));
    }

    let req_wildcard = required.and_then(|o| o.wildcard_projection.as_ref());
    let live_wildcard = live.and_then(|o| o.wildcard_projection.as_ref());
    if req_wildcard != live_wildcard {
        return Err(format!(
            "wildcardProjection expected={req_wildcard:?} found={live_wildcard:?}"
        ));
    }

    let req_weights = required.and_then(|o| o.weights.as_ref());
    let live_weights = live.and_then(|o| o.weights.as_ref());
    if req_weights != live_weights {
        return Err(format!(
            "weights expected={req_weights:?} found={live_weights:?}"
        ));
    }

    let req_collation = required
        .and_then(|o| o.collation.as_ref())
        .map(mongodb::bson::to_bson)
        .transpose()
        .map_err(|error| format!("failed to encode required collation: {error}"))?;
    let live_collation = live
        .and_then(|o| o.collation.as_ref())
        .map(mongodb::bson::to_bson)
        .transpose()
        .map_err(|error| format!("failed to encode live collation: {error}"))?;
    if req_collation != live_collation {
        return Err(format!(
            "collation expected={req_collation:?} found={live_collation:?}"
        ));
    }

    Ok(())
}
