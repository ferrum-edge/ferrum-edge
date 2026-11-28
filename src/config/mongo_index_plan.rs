//! Canonical MongoDB index / collection plan for migrate `up`, dry-run, and status.
//!
//! `MongoStore::run_migrations`, migrate dry-run output, and migrate status all
//! consume [`required_mongo_indexes`] / [`required_guard_collections`] so the
//! operator-facing plan cannot drift from the indexes `up` actually ensures.
//!
//! The plan is versioned ([`MONGO_INDEX_PLAN_VERSION`]) and forward-only: `up`
//! records the version it applied, refuses a database that records a newer
//! one, and drops an old index only when a later version lists it in
//! [`RETIRED_MONGO_INDEXES`].

use mongodb::IndexModel;
use mongodb::bson::{Document, doc};
use mongodb::options::IndexOptions;

/// Projection field stamped onto consumer documents for the HMAC secret-hash
/// uniqueness index. Must stay identical to the field written by
/// `MongoStore` consumer encode paths.
pub const HMAC_SECRET_HASHES_FIELD: &str = "_ferrum_hmac_secret_hashes";

/// Empty shell collections that must exist before transactional writes. MongoDB
/// 4.4+ can create a collection implicitly inside a transaction, but not in a
/// cross-shard write transaction, and concurrent first writes can conflict, so
/// migrations create them up front.
pub const REQUIRED_GUARD_COLLECTIONS: &[&str] = &[
    "proxy_route_locks",
    "upstream_ref_guards",
    "mtls_dns_admission_locks",
    "config_change_counters",
];

/// One required index in the baseline MongoDB migration plan.
#[derive(Clone, Debug)]
pub struct RequiredMongoIndex {
    pub collection: &'static str,
    pub model: IndexModel,
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
    /// Plan version recorded by the last successful `up`, or `None` when the
    /// database has never been initialized by a version-recording release.
    pub recorded_plan_version: Option<i64>,
    /// Target version of an upgrade that started changing indexes and has not
    /// recorded completion, if any.
    pub in_progress_plan_version: Option<i64>,
    /// Plan version this binary applies ([`MONGO_INDEX_PLAN_VERSION`]).
    pub plan_version: i64,
}

// ---------------------------------------------------------------------------
// Versioned, forward-only index plan
// ---------------------------------------------------------------------------

/// Version of the canonical MongoDB index plan this binary applies.
///
/// `up` (and `database` / `cp` startup) marks the target version in progress
/// in [`MONGO_INDEX_PLAN_VERSION_COLLECTION`] before its first schema change,
/// and records it as applied (clearing the marker in the same update) only
/// after the plan is fully ensured. Startup, `up`, `status`, and every
/// reconnect refuse a database whose applied or in-progress version is higher
/// than this one (an older binary against a database a newer release started
/// or finished upgrading).
///
/// Forward changes from 1.0.0 onward, each in one release, bump this by one:
/// - add an index: add it to [`required_mongo_indexes`];
/// - drop an index: remove it from the plan and add a [`RetiredMongoIndex`]
///   naming its exact index name with `retired_in` = the new version;
/// - replace an index (new keys or options): retire the old name and add the
///   new definition under a **new** name. A planned index may never reuse a
///   retired name (an explicit `name` option is required when the new
///   definition keeps the old keys), so retrying a retirement can never drop
///   the replacement.
///
/// Never edit or remove a shipped entry of [`RETIRED_MONGO_INDEXES`], and
/// never change an existing plan entry's keys or options in place: MongoDB
/// refuses a `createIndex` whose keys match an existing index with different
/// options, and old definitions are dropped only through retirements.
pub const MONGO_INDEX_PLAN_VERSION: i64 = 1;

/// Collection holding the recorded index-plan version.
pub const MONGO_INDEX_PLAN_VERSION_COLLECTION: &str = "_ferrum_migrations";

/// `_id` of the single document in [`MONGO_INDEX_PLAN_VERSION_COLLECTION`]
/// that records the core index-plan version (`version`) and, while an `up` is
/// between its first change and its version record, the target version it is
/// applying (`in_progress_version`).
pub const MONGO_INDEX_PLAN_VERSION_DOCUMENT_ID: &str = "core_index_plan";

/// Collections a 0.9.x release wrote Ferrum documents into.
///
/// 1.0.0 is the first release that records an index-plan version, and every
/// 1.0.0+ `up` writes its `in_progress_version` marker before it creates a
/// collection or a document. A database that holds a document in any of these
/// collections but has **no** `core_index_plan` record (neither `version` nor
/// `in_progress_version`) was therefore initialized by a 0.9.x release; see
/// [`MongoIndexPlanError::PreReleaseDatabase`]. An empty database (none of these
/// collections holds a document) is a new database and is never refused.
pub const PRE_RELEASE_MARKER_COLLECTIONS: &[&str] = &[
    "proxies",
    "consumers",
    "plugin_configs",
    "upstreams",
    "api_specs",
    "gateway_trust_bundles",
    "namespaces",
    "config_changes",
    "consumer_identity_index",
    "audit_events",
];

/// Refuse a populated database that carries no index-plan record (see
/// [`PRE_RELEASE_MARKER_COLLECTIONS`]). `populated_collection` is the first
/// marker collection found holding a document, or `None` when all are empty.
pub fn refuse_pre_release_database(
    recorded: &RecordedIndexPlanState,
    populated_collection: Option<&'static str>,
) -> Result<(), MongoIndexPlanError> {
    if recorded.version.is_some() || recorded.in_progress.is_some() {
        return Ok(());
    }
    match populated_collection {
        Some(collection) => Err(MongoIndexPlanError::PreReleaseDatabase { collection }),
        None => Ok(()),
    }
}

/// An index an earlier plan created that a later plan version drops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetiredMongoIndex {
    /// The plan version that no longer has this index. Always at least 2.
    pub retired_in: i64,
    pub collection: &'static str,
    /// The exact index name the earlier plan created (the driver default
    /// `field_1_other_-1` form unless that plan set an explicit name).
    pub name: &'static str,
}

/// Indexes dropped by later plan versions, oldest first. Empty at version 1.
pub const RETIRED_MONGO_INDEXES: &[RetiredMongoIndex] = &[];

/// The index-plan state a database records.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordedIndexPlanState {
    /// Last plan version applied completely; `None` for a fresh database or
    /// one initialized before plan versions were recorded.
    pub version: Option<i64>,
    /// Target version of an `up` that made schema changes but has not yet
    /// recorded completion (an interrupted or running upgrade).
    pub in_progress: Option<i64>,
}

/// The name an index is created under: its explicit `name` option, or the
/// driver default derived from its keys.
pub fn planned_index_name(model: &IndexModel) -> String {
    model
        .options
        .as_ref()
        .and_then(|options| options.name.clone())
        .unwrap_or_else(|| default_index_name(&model.keys))
}

/// One complete versioned index plan: what `up` ensures and what it drops.
#[derive(Clone, Debug)]
pub struct MongoIndexPlan {
    pub version: i64,
    pub indexes: Vec<RequiredMongoIndex>,
    pub retired: Vec<RetiredMongoIndex>,
}

impl MongoIndexPlan {
    /// The plan this binary ships.
    pub fn current() -> Self {
        Self {
            version: MONGO_INDEX_PLAN_VERSION,
            indexes: required_mongo_indexes(),
            retired: RETIRED_MONGO_INDEXES.to_vec(),
        }
    }

    /// Reject a malformed plan declaration.
    pub fn validate(&self) -> Result<(), MongoIndexPlanError> {
        if self.version < 1 {
            return Err(MongoIndexPlanError::InvalidPlanVersion {
                version: self.version,
            });
        }
        for retired in &self.retired {
            if retired.retired_in < 2 || retired.retired_in > self.version {
                return Err(MongoIndexPlanError::InvalidRetirement {
                    retired_in: retired.retired_in,
                    version: self.version,
                });
            }
            if self.indexes.iter().any(|entry| {
                entry.collection == retired.collection
                    && planned_index_name(&entry.model) == retired.name
            }) {
                return Err(MongoIndexPlanError::RetiredNameReused {
                    collection: retired.collection,
                    name: retired.name,
                });
            }
        }
        Ok(())
    }

    /// Decide the forward step from a database's last applied plan version.
    ///
    /// `None` (a fresh database, or one initialized before versions were
    /// recorded) is treated as version 0. Returns the retirements to drop,
    /// in declaration order: every entry with `recorded < retired_in`. A
    /// recorded version above [`Self::version`] is refused, never "repaired".
    pub fn upgrade_from(
        &self,
        recorded: Option<i64>,
    ) -> Result<Vec<RetiredMongoIndex>, MongoIndexPlanError> {
        self.validate()?;
        let recorded = match recorded {
            None => 0,
            Some(version) if version < 1 => {
                return Err(MongoIndexPlanError::InvalidRecordedVersion);
            }
            Some(version) if version > self.version => {
                return Err(MongoIndexPlanError::RecordedVersionNewer {
                    recorded: version,
                    supported: self.version,
                });
            }
            Some(version) => version,
        };
        Ok(self
            .retired
            .iter()
            .filter(|retired| retired.retired_in > recorded)
            .copied()
            .collect())
    }

    /// [`Self::upgrade_from`] for a full recorded state: an in-progress
    /// upgrade to a version above [`Self::version`] is refused too, so an
    /// older binary never runs against (or "repairs") a half-applied newer
    /// plan. An in-progress version at or below this plan is resumed.
    pub fn upgrade_from_state(
        &self,
        recorded: &RecordedIndexPlanState,
    ) -> Result<Vec<RetiredMongoIndex>, MongoIndexPlanError> {
        let retirements = self.upgrade_from(recorded.version)?;
        if let Some(in_progress) = recorded.in_progress
            && in_progress > self.version
        {
            return Err(MongoIndexPlanError::InProgressVersionNewer {
                in_progress,
                supported: self.version,
            });
        }
        Ok(retirements)
    }
}

/// A MongoDB index-plan version the binary cannot safely act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MongoIndexPlanError {
    /// The database records a newer plan than this binary applies.
    RecordedVersionNewer { recorded: i64, supported: i64 },
    /// A newer release started upgrading this database and has not finished.
    InProgressVersionNewer { in_progress: i64, supported: i64 },
    /// The recorded version document is not a positive integer version.
    InvalidRecordedVersion,
    /// The database holds Ferrum documents but no index-plan record, so a
    /// 0.9.x release initialized it (see [`PRE_RELEASE_MARKER_COLLECTIONS`]).
    PreReleaseDatabase { collection: &'static str },
    /// A plan declares a version below 1.
    InvalidPlanVersion { version: i64 },
    /// A retirement is declared outside `2..=version`.
    InvalidRetirement { retired_in: i64, version: i64 },
    /// A planned index reuses the name of a retired index.
    RetiredNameReused {
        collection: &'static str,
        name: &'static str,
    },
}

impl std::fmt::Display for MongoIndexPlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RecordedVersionNewer {
                recorded,
                supported,
            } => write!(
                f,
                "MongoDB index plan version \"{recorded}\" recorded in this database is newer \
                 than version \"{supported}\" applied by this binary; refusing to run an older \
                 binary against a database a newer release upgraded. Run that newer release, \
                 or restore the backup taken before the upgrade (docs/admin_backup_restore.md)"
            ),
            Self::InProgressVersionNewer {
                in_progress,
                supported,
            } => write!(
                f,
                "an upgrade to MongoDB index plan version \"{in_progress}\" started on this \
                 database and has not finished, and this binary applies version \
                 \"{supported}\"; refusing to run an older binary against a partly upgraded \
                 database. Rerun the newer release to finish the upgrade, or restore the \
                 backup taken before it (docs/admin_backup_restore.md)"
            ),
            Self::PreReleaseDatabase { collection } => write!(
                f,
                "migration history integrity check failed: kind=pre_release_database \
                 backend=mongodb: collection `{collection}` holds Ferrum documents but the \
                 database records no index plan version (`_ferrum_migrations` \
                 `core_index_plan`), so a 0.9.x release created it. This release refuses it: \
                 rebuild the database and restore it from a `GET /backup` export as described \
                 in docs/upgrade_guide.md (\"Every 0.9.x database is rebuilt and restored\") \
                 and docs/admin_backup_restore.md"
            ),
            Self::InvalidRecordedVersion => f.write_str(
                "MongoDB index plan version record is not a positive integer; refusing to \
                 guess which indexes this database has",
            ),
            Self::InvalidPlanVersion { version } => {
                write!(
                    f,
                    "MongoDB index plan declares invalid version \"{version}\""
                )
            }
            Self::InvalidRetirement {
                retired_in,
                version,
            } => write!(
                f,
                "MongoDB index plan version \"{version}\" declares a retirement in version \
                 \"{retired_in}\" outside 2..={version}"
            ),
            Self::RetiredNameReused { collection, name } => write!(
                f,
                "MongoDB index plan reuses retired index name `{name}` on `{collection}`; a \
                 replacement index needs a new name"
            ),
        }
    }
}

impl std::error::Error for MongoIndexPlanError {}

fn recorded_version_field(
    document: &Document,
    field: &str,
) -> Result<Option<i64>, MongoIndexPlanError> {
    let version = match document.get(field) {
        None => return Ok(None),
        Some(mongodb::bson::Bson::Int64(version)) => *version,
        Some(mongodb::bson::Bson::Int32(version)) => i64::from(*version),
        Some(_) => return Err(MongoIndexPlanError::InvalidRecordedVersion),
    };
    if version < 1 {
        return Err(MongoIndexPlanError::InvalidRecordedVersion);
    }
    Ok(Some(version))
}

/// Parse the recorded plan state from its document. A missing document is the
/// default (nothing recorded). A present document needs a positive
/// Int32/Int64 `version` unless only an `in_progress_version` is recorded (a
/// first upgrade that was interrupted); any other shape is refused.
pub fn recorded_plan_state_from_document(
    document: Option<&Document>,
) -> Result<RecordedIndexPlanState, MongoIndexPlanError> {
    let Some(document) = document else {
        return Ok(RecordedIndexPlanState::default());
    };
    let state = RecordedIndexPlanState {
        version: recorded_version_field(document, "version")?,
        in_progress: recorded_version_field(document, "in_progress_version")?,
    };
    if state.version.is_none() && state.in_progress.is_none() {
        return Err(MongoIndexPlanError::InvalidRecordedVersion);
    }
    Ok(state)
}

/// Parse only the applied plan version (see
/// [`recorded_plan_state_from_document`]).
pub fn recorded_plan_version_from_document(
    document: Option<&Document>,
) -> Result<Option<i64>, MongoIndexPlanError> {
    Ok(recorded_plan_state_from_document(document)?.version)
}

/// Build the baseline index plan. This is the single source of truth for
/// `up`, dry-run, and status.
pub fn required_mongo_indexes() -> Vec<RequiredMongoIndex> {
    let mut plan = Vec::with_capacity(48);

    // proxies — names remain unique within a namespace. Stream ports are
    // intentionally non-unique because one validated SNI/L4 listener group is
    // represented by multiple proxy documents.
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
    plan.push(non_unique_partial(
        "proxies",
        doc! { "namespace": 1, "listen_port": 1 },
        doc! { "listen_port": { "$type": "number" } },
    ));
    plan.push(keys_only(
        "proxies",
        doc! { "namespace": 1, "updated_at": 1 },
    ));
    plan.push(keys_only("proxies", doc! { "namespace": 1, "_id": 1 }));
    // Non-unique (namespace, listen_path) covers check_listen_path_unique
    // candidate filters. Uniqueness stays application-enforced because
    // conflict is host-overlap, not path equality (issue #4234).
    plan.push(keys_only(
        "proxies",
        doc! { "namespace": 1, "listen_path": 1 },
    ));

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
    // non-unique {namespace} index supports namespace wipes / cleanup filters,
    // and {namespace, consumer_id} serves transactional `delete_consumer`
    // cleanup without scanning the entire namespace.
    plan.push(keys_only(
        "consumer_identity_index",
        doc! { "namespace": 1 },
    ));
    plan.push(keys_only(
        "consumer_identity_index",
        doc! { "namespace": 1, "consumer_id": 1 },
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

    // api_specs — unique (namespace, proxy_id) for attached specifications.
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
    plan.push(keys_only("api_specs", doc! { "namespace": 1, "_id": 1 }));
    plan.push(keys_only("api_specs", doc! { "namespace": 1, "tags": 1 }));

    // audit_events — include `id` so list and retention prune share deterministic
    // `(ts, id)` keyset behavior with SQL `idx_audit_events_namespace_ts_id`.
    plan.push(keys_only(
        "audit_events",
        doc! { "namespace": 1, "ts": -1, "id": -1 },
    ));
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

    // gateway_trust_bundles (issue #3727).
    //
    // No unique index is declared for the singleton rule: `_id` IS the
    // namespace, so the implicit `_id` index already enforces one record per
    // namespace atomically. This compound index serves the addressed
    // `{namespace, id}` admin reads and deletes.
    plan.push(keys_only(
        "gateway_trust_bundles",
        doc! { "namespace": 1, "id": 1 },
    ));

    // namespaces registry (issue #3955). `_id` IS the name, so the implicit
    // `_id` index already enforces uniqueness. This index serves the embedded
    // `name` half of split-identity reads and vacancy checks; listing merges
    // registry and derived names in memory before sorting.
    plan.push(keys_only("namespaces", doc! { "name": 1 }));

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
        let summary = summarize_index(&entry.model);
        lines.push(format!("    - {summary}"));
    }

    lines.push("  collections ensured (empty shell):".to_string());
    for name in REQUIRED_GUARD_COLLECTIONS {
        lines.push(format!("    - {name}"));
    }

    // Destructive steps are listed too. Dry-run stays offline, so it cannot
    // know the database's recorded version: each retirement runs only when
    // the recorded plan version is below the version that retired it.
    let plan = MongoIndexPlan::current();
    lines.push(format!(
        "  index plan version applied and recorded: {}",
        plan.version
    ));
    if plan.retired.is_empty() {
        lines.push("  indexes dropped (retired by a later plan version): none".to_string());
    } else {
        lines.push(
            "  indexes dropped (by exact name, only when the recorded plan version is below \
             the retiring version):"
                .to_string(),
        );
        for retired in &plan.retired {
            lines.push(format!(
                "    - {}.{} (retired in plan version {})",
                retired.collection, retired.name, retired.retired_in
            ));
        }
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
    }
}

fn unique_keys(collection: &'static str, keys: Document) -> RequiredMongoIndex {
    RequiredMongoIndex {
        collection,
        model: IndexModel::builder()
            .keys(keys)
            .options(IndexOptions::builder().unique(true).build())
            .build(),
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
    }
}

fn non_unique_partial(
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
                    .partial_filter_expression(partial)
                    .build(),
            )
            .build(),
    }
}

fn sparse_keys(collection: &'static str, keys: Document) -> RequiredMongoIndex {
    RequiredMongoIndex {
        collection,
        model: IndexModel::builder()
            .keys(keys)
            .options(IndexOptions::builder().sparse(true).build())
            .build(),
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
