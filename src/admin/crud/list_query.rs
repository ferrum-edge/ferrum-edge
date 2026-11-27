//! Query parameters and handlers for the four config-collection list routes
//! (`GET /proxies`, `/consumers`, `/upstreams`, `/plugins/config`):
//!
//! - `q`: server-side search (see [`crate::config::list_query`] for the
//!   matching rule shared by every backend and the cached-config path);
//! - `ids`: bulk reference resolution (at most
//!   [`list_query::MAX_LIST_IDS`] ids; missing ids are simply absent);
//! - `if_revision`: answer `409` unless the collection revision still equals
//!   the given value;
//! - `applies_to_proxy` (plugin configs only): the effective plugin configs
//!   of one proxy, computed by the plugin cache's own scope rule
//!   ([`crate::plugin_cache::plugin_configs_applied_to_proxy`]).
//!
//! Every response's `pagination` carries `revision`, an opaque token that
//! changes whenever a create/update/delete commits in the listed collection
//! of the namespace. Database-served lists derive it from the durable
//! `config_changes` log (`s<sequence>`); lists served from the in-memory
//! config (`file`/`dp`/`mesh` modes and the database-outage fallback) derive
//! it from a SHA-256 of the collection's `viewer` projection (`c<hex>`),
//! which carries no secret material and is identical on replicas holding the
//! same config. A database-served page is bracketed by two revision reads and
//! retried until both agree, so the page reflects exactly the revision it
//! reports.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use serde_json::{Value, json};

use super::{AdminResource, DbResult};
use crate::admin::AdminState;
use crate::admin::jwt_auth::AdminRole;
use crate::config::db_backend::{DatabaseBackend, PaginatedResult};
use crate::config::list_query::{
    self, ListSearchable, ResourceListFilter, SearchTerm, parse_list_ids,
};
use crate::config::types::{
    Consumer, GatewayConfig, PluginConfig, Proxy, Upstream, validate_resource_id,
};

/// Revision reads bracketing one database page before the route gives up
/// with `503`. Each retry means a write to the same collection committed
/// while the page was being read.
const LIST_REVISION_READ_ATTEMPTS: usize = 5;

/// Longest accepted `if_revision` value.
const MAX_REVISION_TOKEN_BYTES: usize = 80;

/// Bound on memoized cached-config revisions (namespace x kind entries) for
/// one config generation.
const MAX_CACHED_REVISION_ENTRIES: usize = 4096;

/// Parsed list query parameters. Unknown parameters stay ignored, as on
/// every other Admin API route.
#[derive(Debug, Clone, Default)]
pub(crate) struct ListQuery {
    pub(crate) filter: ResourceListFilter,
    pub(crate) if_revision: Option<String>,
    pub(crate) applies_to_proxy: Option<String>,
    pub(crate) proxy_id: Option<String>,
}

/// Parse `q`, `ids`, `if_revision` and (when `plugin_config_route`)
/// `applies_to_proxy` from a list route's query string. Each may appear at
/// most once. `proxy_id` is parsed by the route itself.
pub(crate) fn parse_list_query(
    query: Option<&str>,
    plugin_config_route: bool,
) -> Result<ListQuery, String> {
    let mut parsed = ListQuery::default();
    let Some(query) = query else {
        return Ok(parsed);
    };
    let mut seen_q = false;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "q" => {
                if seen_q {
                    return Err("q must not be supplied more than once".to_string());
                }
                seen_q = true;
                parsed.filter.search = SearchTerm::parse(&value)?;
            }
            "ids" => {
                if parsed.filter.ids.is_some() {
                    return Err("ids must not be supplied more than once".to_string());
                }
                parsed.filter.ids = Some(parse_list_ids(&value)?);
            }
            "if_revision" => {
                if parsed.if_revision.is_some() {
                    return Err("if_revision must not be supplied more than once".to_string());
                }
                if value.is_empty()
                    || value.len() > MAX_REVISION_TOKEN_BYTES
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
                {
                    return Err(
                        "if_revision must be a revision token returned in pagination.revision"
                            .to_string(),
                    );
                }
                parsed.if_revision = Some(value.into_owned());
            }
            "applies_to_proxy" if plugin_config_route => {
                if parsed.applies_to_proxy.is_some() {
                    return Err("applies_to_proxy must not be supplied more than once".to_string());
                }
                validate_resource_id(&value)
                    .map_err(|error| format!("applies_to_proxy: {error}"))?;
                parsed.applies_to_proxy = Some(value.into_owned());
            }
            _ => {}
        }
    }
    Ok(parsed)
}

/// A list route resource: one of the four config collections.
#[allow(clippy::double_must_use)] // async-trait adds a bare #[must_use]
#[async_trait::async_trait]
pub(crate) trait QueryableListResource: AdminResource + ListSearchable {
    /// `config_changes.resource_type` of this collection.
    const RESOURCE_TYPE: &'static str;
    /// Whether this kind's `viewer` projection strips URL userinfo from
    /// `name` (proxies and upstreams), which `q` must then not probe.
    const VIEWER_STRIPS_NAME_USERINFO: bool = false;

    async fn db_list_query(
        db: &dyn DatabaseBackend,
        namespace: &str,
        filter: &ResourceListFilter,
        proxy_id: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> DbResult<PaginatedResult<Self>>;

    /// In-memory `proxy_id` filter; only plugin configs have one.
    fn matches_proxy_id(_resource: &Self, _proxy_id: Option<&str>) -> bool {
        true
    }
}

#[async_trait::async_trait]
impl QueryableListResource for Proxy {
    const RESOURCE_TYPE: &'static str = list_query::PROXY_RESOURCE_TYPE;
    const VIEWER_STRIPS_NAME_USERINFO: bool = true;

    async fn db_list_query(
        db: &dyn DatabaseBackend,
        namespace: &str,
        filter: &ResourceListFilter,
        _proxy_id: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> DbResult<PaginatedResult<Self>> {
        db.list_proxies_filtered(namespace, filter, limit, offset)
            .await
    }
}

#[async_trait::async_trait]
impl QueryableListResource for Consumer {
    const RESOURCE_TYPE: &'static str = list_query::CONSUMER_RESOURCE_TYPE;

    async fn db_list_query(
        db: &dyn DatabaseBackend,
        namespace: &str,
        filter: &ResourceListFilter,
        _proxy_id: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> DbResult<PaginatedResult<Self>> {
        db.list_consumers_filtered(namespace, filter, limit, offset)
            .await
    }
}

#[async_trait::async_trait]
impl QueryableListResource for Upstream {
    const RESOURCE_TYPE: &'static str = list_query::UPSTREAM_RESOURCE_TYPE;
    const VIEWER_STRIPS_NAME_USERINFO: bool = true;

    async fn db_list_query(
        db: &dyn DatabaseBackend,
        namespace: &str,
        filter: &ResourceListFilter,
        _proxy_id: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> DbResult<PaginatedResult<Self>> {
        db.list_upstreams_filtered(namespace, filter, limit, offset)
            .await
    }
}

#[async_trait::async_trait]
impl QueryableListResource for PluginConfig {
    const RESOURCE_TYPE: &'static str = list_query::PLUGIN_CONFIG_RESOURCE_TYPE;

    async fn db_list_query(
        db: &dyn DatabaseBackend,
        namespace: &str,
        filter: &ResourceListFilter,
        proxy_id: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> DbResult<PaginatedResult<Self>> {
        db.list_plugin_configs_filtered(namespace, filter, proxy_id, limit, offset)
            .await
    }

    fn matches_proxy_id(resource: &Self, proxy_id: Option<&str>) -> bool {
        proxy_id.is_none_or(|proxy_id| resource.proxy_id.as_deref() == Some(proxy_id))
    }
}

/// The caller's filter with the role-dependent `name` guard applied.
fn filter_for_role<R: QueryableListResource>(
    filter: &ResourceListFilter,
    role: AdminRole,
) -> ResourceListFilter {
    let mut filter = filter.clone();
    filter.exclude_at_sign_names = R::VIEWER_STRIPS_NAME_USERINFO && role == AdminRole::Viewer;
    filter
}

/// Revision token for a database-served list.
pub(crate) fn store_revision_token(sequence: u64) -> String {
    format!("s{sequence}")
}

type ReadFuture<'f, T> = Pin<Box<dyn Future<Output = DbResult<T>> + Send + 'f>>;

enum RevisionedRead<T> {
    Read { value: T, revision: String },
    Mismatch { current: String },
    Unstable,
}

/// Read `read()` bracketed by two revision reads of `resource_types`,
/// retrying until both agree (so the value reflects exactly that revision).
/// With `if_revision`, a revision that no longer equals it answers
/// [`RevisionedRead::Mismatch`] before (or instead of) reading.
async fn revisioned_db_read<'f, T, F>(
    db: &'f dyn DatabaseBackend,
    namespace: &'f str,
    resource_types: &'f [&'f str],
    if_revision: Option<&'f str>,
    read: F,
) -> DbResult<RevisionedRead<T>>
where
    F: Fn() -> ReadFuture<'f, T> + Send + Sync,
    T: Send,
{
    for _ in 0..LIST_REVISION_READ_ATTEMPTS {
        let before = db
            .config_collection_revision(namespace, resource_types)
            .await?;
        let token = store_revision_token(before);
        if let Some(expected) = if_revision
            && expected != token
        {
            return Ok(RevisionedRead::Mismatch { current: token });
        }
        let value = read().await?;
        let after = db
            .config_collection_revision(namespace, resource_types)
            .await?;
        if before == after {
            return Ok(RevisionedRead::Read {
                value,
                revision: token,
            });
        }
    }
    Ok(RevisionedRead::Unstable)
}

fn revision_mismatch_response(current: &str) -> Response<Full<Bytes>> {
    crate::admin::json_response(
        StatusCode::CONFLICT,
        &json!({
            "error": "Collection revision no longer matches if_revision",
            "revision": current,
        }),
    )
}

fn revision_unstable_response() -> Response<Full<Bytes>> {
    crate::admin::json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        &json!({
            "error": "Collection changed repeatedly while the page was being read; retry the request"
        }),
    )
}

fn no_source_response() -> Response<Full<Bytes>> {
    crate::admin::json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        &json!({"error": "No database and no cached config available"}),
    )
}

fn envelope(
    data: Vec<Value>,
    total: i64,
    pagination: &crate::admin::PaginationParams,
    revision: &str,
) -> Value {
    json!({
        "data": data,
        "pagination": {
            "offset": pagination.query_offset_i64(),
            "limit": pagination.response_limit(),
            "total": total,
            "revision": revision,
        }
    })
}

/// Paginate an in-memory, already filtered and ordered slice.
fn in_memory_page<'a, R: AdminResource>(
    items: &[&'a R],
    pagination: &crate::admin::PaginationParams,
) -> Vec<&'a R> {
    match pagination.in_memory_offset() {
        Some(offset) => items
            .iter()
            .skip(offset)
            .take(pagination.in_memory_limit())
            .copied()
            .collect(),
        None => Vec::new(),
    }
}

fn total_i64(count: usize) -> i64 {
    i64::try_from(count).unwrap_or(i64::MAX)
}

/// `GET /proxies`, `/consumers`, `/upstreams`, `/plugins/config` (without
/// `applies_to_proxy`).
pub(crate) async fn handle_list_query<R: QueryableListResource>(
    state: &AdminState,
    pagination: &crate::admin::PaginationParams,
    role: AdminRole,
    namespace: &str,
    query: &ListQuery,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let filter = filter_for_role::<R>(&query.filter, role);
    let proxy_id = query.proxy_id.as_deref();

    if let Some(ref db) = state.db {
        let db: &dyn DatabaseBackend = db.as_ref();
        let resource_types = [R::RESOURCE_TYPE];
        let filter_ref = &filter;
        let limit = pagination.query_limit_i64();
        let offset = pagination.query_offset_i64();
        let read = move || R::db_list_query(db, namespace, filter_ref, proxy_id, limit, offset);
        match revisioned_db_read(
            db,
            namespace,
            &resource_types,
            query.if_revision.as_deref(),
            read,
        )
        .await
        {
            Ok(RevisionedRead::Read { value, revision }) => {
                let items: Vec<Value> = value
                    .items
                    .iter()
                    .map(|resource| super::response_body_for_role(resource, role))
                    .collect();
                let body = envelope(items, value.total, pagination, &revision);
                return Ok(crate::admin::json_response(StatusCode::OK, &body));
            }
            Ok(RevisionedRead::Mismatch { current }) => {
                return Ok(revision_mismatch_response(&current));
            }
            Ok(RevisionedRead::Unstable) => return Ok(revision_unstable_response()),
            Err(error) => {
                if !R::allow_cached_read_fallback(&error) {
                    return Ok(R::map_precheck_db_error(&error));
                }
                crate::admin::warn_persistence_failure_redacted(
                    "admin_resource_list_query_cached_fallback",
                );
            }
        }
    }

    let Some(config) = state.cached_gateway_config() else {
        return Ok(no_source_response());
    };
    let revision = cached_collection_revision::<R>(&config, namespace);
    if let Some(expected) = query.if_revision.as_deref()
        && expected != revision
    {
        return Ok(revision_mismatch_response(&revision));
    }
    let matching: Vec<&R> = R::cached_items(&config)
        .iter()
        .filter(|resource| {
            resource.namespace() == namespace
                && filter.matches(*resource)
                && R::matches_proxy_id(resource, proxy_id)
        })
        .collect();
    let page: Vec<Value> = in_memory_page(&matching, pagination)
        .into_iter()
        .map(|resource| super::response_body_for_role(resource, role))
        .collect();
    let body = envelope(page, total_i64(matching.len()), pagination, &revision);
    Ok(crate::admin::json_response_with_stale(
        StatusCode::OK,
        &body,
    ))
}

/// Outcome of evaluating `applies_to_proxy` against one source.
enum AppliesTo {
    ProxyNotFound,
    Configs(Vec<PluginConfig>),
}

/// The effective plugin configs of `proxy` among `candidates`, narrowed by
/// the caller's `q` / `ids` / `proxy_id` filters, ordered by id.
fn applied_and_filtered(
    proxy: &Proxy,
    candidates: &[PluginConfig],
    filter: &ResourceListFilter,
    proxy_id: Option<&str>,
) -> Vec<PluginConfig> {
    crate::plugin_cache::plugin_configs_applied_to_proxy(proxy, candidates)
        .into_iter()
        .filter(|pc| filter.matches(*pc) && PluginConfig::matches_proxy_id(pc, proxy_id))
        .cloned()
        .collect()
}

/// `GET /plugins/config?applies_to_proxy=<id>`: the global, proxy-group and
/// proxy-scoped plugin configs the plugin cache applies to that proxy, in
/// the shared list envelope. Unknown proxy → `404`.
pub(crate) async fn handle_plugin_configs_applied_to_proxy(
    state: &AdminState,
    pagination: &crate::admin::PaginationParams,
    role: AdminRole,
    namespace: &str,
    query: &ListQuery,
    proxy_id_target: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let filter = filter_for_role::<PluginConfig>(&query.filter, role);
    let proxy_id = query.proxy_id.as_deref();
    // A proxy's effective set depends on the plugin configs AND on the
    // proxy's own association list.
    let resource_types = [
        list_query::PLUGIN_CONFIG_RESOURCE_TYPE,
        list_query::PROXY_RESOURCE_TYPE,
    ];

    if let Some(ref db) = state.db {
        let db: &dyn DatabaseBackend = db.as_ref();
        let filter_ref = &filter;
        let read = move || {
            let future: ReadFuture<'_, AppliesTo> = Box::pin(async move {
                let Some(proxy) = db.get_proxy(namespace, proxy_id_target).await? else {
                    return Ok(AppliesTo::ProxyNotFound);
                };
                let attached: Vec<String> = proxy
                    .plugins
                    .iter()
                    .map(|association| association.plugin_config_id.clone())
                    .collect();
                let candidates = db
                    .list_plugin_config_candidates_for_proxy(namespace, &attached)
                    .await?;
                Ok(AppliesTo::Configs(applied_and_filtered(
                    &proxy,
                    &candidates,
                    filter_ref,
                    proxy_id,
                )))
            });
            future
        };
        match revisioned_db_read(
            db,
            namespace,
            &resource_types,
            query.if_revision.as_deref(),
            read,
        )
        .await
        {
            Ok(RevisionedRead::Read {
                value: AppliesTo::ProxyNotFound,
                ..
            }) => return Ok(super::not_found_response::<Proxy>()),
            Ok(RevisionedRead::Read {
                value: AppliesTo::Configs(configs),
                revision,
            }) => {
                let refs: Vec<&PluginConfig> = configs.iter().collect();
                let page: Vec<Value> = in_memory_page(&refs, pagination)
                    .into_iter()
                    .map(|resource| super::response_body_for_role(resource, role))
                    .collect();
                let body = envelope(page, total_i64(refs.len()), pagination, &revision);
                return Ok(crate::admin::json_response(StatusCode::OK, &body));
            }
            Ok(RevisionedRead::Mismatch { current }) => {
                return Ok(revision_mismatch_response(&current));
            }
            Ok(RevisionedRead::Unstable) => return Ok(revision_unstable_response()),
            Err(error) => {
                if !PluginConfig::allow_cached_read_fallback(&error) {
                    return Ok(PluginConfig::map_precheck_db_error(&error));
                }
                crate::admin::warn_persistence_failure_redacted(
                    "admin_plugin_config_applies_to_cached_fallback",
                );
            }
        }
    }

    let Some(config) = state.cached_gateway_config() else {
        return Ok(no_source_response());
    };
    let Some(proxy) = config
        .proxies
        .iter()
        .find(|proxy| proxy.namespace == namespace && proxy.id == proxy_id_target)
    else {
        return Ok(super::not_found_response::<Proxy>());
    };
    let revision = format!(
        "{}{}",
        cached_collection_revision::<PluginConfig>(&config, namespace),
        cached_collection_revision::<Proxy>(&config, namespace)
    );
    if let Some(expected) = query.if_revision.as_deref()
        && expected != revision
    {
        return Ok(revision_mismatch_response(&revision));
    }
    let configs = applied_and_filtered(proxy, &config.plugin_configs, &filter, proxy_id);
    let refs: Vec<&PluginConfig> = configs.iter().collect();
    let page: Vec<Value> = in_memory_page(&refs, pagination)
        .into_iter()
        .map(|resource| super::response_body_for_role(resource, role))
        .collect();
    let body = envelope(page, total_i64(refs.len()), pagination, &revision);
    Ok(crate::admin::json_response_with_stale(
        StatusCode::OK,
        &body,
    ))
}

/// Memoized cached-config revisions for one config generation, identified by
/// allocation: holding the `Weak` keeps the allocation alive, so a later
/// generation can never reuse the address while the memo refers to it.
struct CachedRevisionMemo {
    config: Weak<GatewayConfig>,
    entries: HashMap<(String, &'static str), String>,
}

static CACHED_REVISION_MEMO: Mutex<Option<CachedRevisionMemo>> = Mutex::new(None);

/// Revision of `R`'s collection in `namespace` within an in-memory config:
/// `c` + the first 16 bytes (hex) of a SHA-256 over the id-ordered `viewer`
/// projections. The `viewer` projection is the most redacted one, so the
/// digest is no oracle for withheld secrets; it covers `updated_at`, so any
/// write that reached this config changes it.
pub(crate) fn cached_collection_revision<R: QueryableListResource>(
    config: &Arc<GatewayConfig>,
    namespace: &str,
) -> String {
    let key = (namespace.to_string(), R::RESOURCE_TYPE);
    {
        let memo = CACHED_REVISION_MEMO
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(memo) = memo.as_ref()
            && std::ptr::eq(memo.config.as_ptr(), Arc::as_ptr(config))
            && let Some(revision) = memo.entries.get(&key)
        {
            return revision.clone();
        }
    }
    let revision = compute_cached_collection_revision::<R>(config, namespace);
    let mut memo = CACHED_REVISION_MEMO
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let same_generation = memo
        .as_ref()
        .is_some_and(|memo| std::ptr::eq(memo.config.as_ptr(), Arc::as_ptr(config)));
    if !same_generation {
        *memo = Some(CachedRevisionMemo {
            config: Arc::downgrade(config),
            entries: HashMap::new(),
        });
    }
    if let Some(memo) = memo.as_mut() {
        if memo.entries.len() >= MAX_CACHED_REVISION_ENTRIES {
            memo.entries.clear();
        }
        memo.entries.insert(key, revision.clone());
    }
    revision
}

fn compute_cached_collection_revision<R: QueryableListResource>(
    config: &GatewayConfig,
    namespace: &str,
) -> String {
    let mut items: Vec<&R> = R::cached_items(config)
        .iter()
        .filter(|resource| resource.namespace() == namespace)
        .collect();
    items.sort_by(|left, right| left.id().cmp(right.id()));
    let mut hasher = crate::fips::approved::Sha256::new();
    hasher.update(R::RESOURCE_TYPE.as_bytes());
    for item in items {
        let projection = super::response_body_for_role(item, AdminRole::Viewer);
        // serde_json orders object keys (no `preserve_order` feature), so the
        // bytes are canonical for a given value.
        let bytes = serde_json::to_vec(&projection).unwrap_or_default();
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
    }
    let digest = hasher.finalize();
    let mut token = String::with_capacity(33);
    token.push('c');
    for byte in &digest[..16] {
        token.push_str(&format!("{byte:02x}"));
    }
    token
}
