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
//! it from a SHA-256 of the collection's caller-role projection (`c<hex>`),
//! so viewer tokens never depend on withheld secret fields while privileged
//! callers observe secret updates even when `updated_at` is unchanged, and
//! tokens remain identical on replicas holding the same config. A
//! database-served page is bracketed by two revision reads on the same read
//! source and retried until both agree, so the page reflects exactly the
//! revision it reports.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use serde_json::{Value, json};

use super::{AdminResource, DbResult};
use crate::admin::AdminState;
use crate::admin::jwt_auth::AdminRole;
use crate::config::db_backend::{
    DatabaseBackend, PaginatedResult, RevisionedListRead, store_revision_token,
};
use crate::config::list_query::{
    self, ListSearchable, ResourceListFilter, SearchTerm, parse_list_ids,
    validate_list_query_resource_id,
};
use crate::config::types::{Consumer, GatewayConfig, PluginConfig, Proxy, Upstream};

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
                validate_list_query_resource_id(&value)
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
    /// searchable text fields (proxies and upstreams), which `q` must then not
    /// probe.
    const VIEWER_STRIPS_NAME_USERINFO: bool = false;

    async fn db_list_query_revisioned(
        db: &dyn DatabaseBackend,
        namespace: &str,
        filter: &ResourceListFilter,
        proxy_id: Option<&str>,
        limit: i64,
        offset: i64,
        if_revision: Option<&str>,
    ) -> DbResult<RevisionedListRead<PaginatedResult<Self>>>;

    /// In-memory `proxy_id` filter; only plugin configs have one.
    fn matches_proxy_id(_resource: &Self, _proxy_id: Option<&str>) -> bool {
        true
    }
}

#[async_trait::async_trait]
impl QueryableListResource for Proxy {
    const RESOURCE_TYPE: &'static str = list_query::PROXY_RESOURCE_TYPE;
    const VIEWER_STRIPS_NAME_USERINFO: bool = true;

    async fn db_list_query_revisioned(
        db: &dyn DatabaseBackend,
        namespace: &str,
        filter: &ResourceListFilter,
        _proxy_id: Option<&str>,
        limit: i64,
        offset: i64,
        if_revision: Option<&str>,
    ) -> DbResult<RevisionedListRead<PaginatedResult<Self>>> {
        db.list_proxies_revisioned(namespace, filter, limit, offset, if_revision)
            .await
    }
}

#[async_trait::async_trait]
impl QueryableListResource for Consumer {
    const RESOURCE_TYPE: &'static str = list_query::CONSUMER_RESOURCE_TYPE;

    async fn db_list_query_revisioned(
        db: &dyn DatabaseBackend,
        namespace: &str,
        filter: &ResourceListFilter,
        _proxy_id: Option<&str>,
        limit: i64,
        offset: i64,
        if_revision: Option<&str>,
    ) -> DbResult<RevisionedListRead<PaginatedResult<Self>>> {
        db.list_consumers_revisioned(namespace, filter, limit, offset, if_revision)
            .await
    }
}

#[async_trait::async_trait]
impl QueryableListResource for Upstream {
    const RESOURCE_TYPE: &'static str = list_query::UPSTREAM_RESOURCE_TYPE;
    const VIEWER_STRIPS_NAME_USERINFO: bool = true;

    async fn db_list_query_revisioned(
        db: &dyn DatabaseBackend,
        namespace: &str,
        filter: &ResourceListFilter,
        _proxy_id: Option<&str>,
        limit: i64,
        offset: i64,
        if_revision: Option<&str>,
    ) -> DbResult<RevisionedListRead<PaginatedResult<Self>>> {
        db.list_upstreams_revisioned(namespace, filter, limit, offset, if_revision)
            .await
    }
}

#[async_trait::async_trait]
impl QueryableListResource for PluginConfig {
    const RESOURCE_TYPE: &'static str = list_query::PLUGIN_CONFIG_RESOURCE_TYPE;

    async fn db_list_query_revisioned(
        db: &dyn DatabaseBackend,
        namespace: &str,
        filter: &ResourceListFilter,
        proxy_id: Option<&str>,
        limit: i64,
        offset: i64,
        if_revision: Option<&str>,
    ) -> DbResult<RevisionedListRead<PaginatedResult<Self>>> {
        db.list_plugin_configs_revisioned(namespace, filter, proxy_id, limit, offset, if_revision)
            .await
    }

    fn matches_proxy_id(resource: &Self, proxy_id: Option<&str>) -> bool {
        proxy_id.is_none_or(|proxy_id| resource.proxy_id.as_deref() == Some(proxy_id))
    }
}

/// The caller's filter with the role-dependent `@` userinfo guard applied.
fn filter_for_role<R: QueryableListResource>(
    filter: &ResourceListFilter,
    role: AdminRole,
) -> ResourceListFilter {
    let mut filter = filter.clone();
    filter.exclude_at_sign_names = R::VIEWER_STRIPS_NAME_USERINFO && role == AdminRole::Viewer;
    filter
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
        let limit = pagination.query_limit_i64();
        let offset = pagination.query_offset_i64();
        match R::db_list_query_revisioned(
            db,
            namespace,
            &filter,
            proxy_id,
            limit,
            offset,
            query.if_revision.as_deref(),
        )
        .await
        {
            Ok(RevisionedListRead::Read { value, revision }) => {
                let items: Vec<Value> = value
                    .items
                    .iter()
                    .map(|resource| super::response_body_for_role(resource, role))
                    .collect();
                let revision = store_revision_token(revision);
                let body = envelope(items, value.total, pagination, &revision);
                return Ok(crate::admin::json_response(StatusCode::OK, &body));
            }
            Ok(RevisionedListRead::Mismatch { current }) => {
                let current = store_revision_token(current);
                return Ok(revision_mismatch_response(&current));
            }
            Ok(RevisionedListRead::Unstable) => return Ok(revision_unstable_response()),
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
    let revision = cached_collection_revision::<R>(&config, namespace, role);
    if let Some(expected) = query.if_revision.as_deref()
        && expected != revision
    {
        return Ok(revision_mismatch_response(&revision));
    }
    let mut matching: Vec<&R> = R::cached_items(&config)
        .iter()
        .filter(|resource| {
            resource.namespace() == namespace
                && filter.matches(*resource)
                && R::matches_proxy_id(resource, proxy_id)
        })
        .collect();
    matching.sort_by(|left, right| left.id().cmp(right.id()));
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
/// the shared list envelope. Unknown proxy → `404` (or `503` during a database
/// outage fallback when the cached snapshot may be stale).
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
    let mut store_read_failed = false;

    if let Some(ref db) = state.db {
        let db: &dyn DatabaseBackend = db.as_ref();
        match db
            .list_plugin_configs_applied_to_proxy_revisioned(
                namespace,
                proxy_id_target,
                query.if_revision.as_deref(),
            )
            .await
        {
            Ok(RevisionedListRead::Read { value: None, .. }) => {
                return Ok(super::not_found_response::<Proxy>());
            }
            Ok(RevisionedListRead::Read {
                value: Some((proxy, candidates)),
                revision,
            }) => {
                let configs = applied_and_filtered(&proxy, &candidates, &filter, proxy_id);
                let refs: Vec<&PluginConfig> = configs.iter().collect();
                let page: Vec<Value> = in_memory_page(&refs, pagination)
                    .into_iter()
                    .map(|resource| super::response_body_for_role(resource, role))
                    .collect();
                let revision = store_revision_token(revision);
                let body = envelope(page, total_i64(refs.len()), pagination, &revision);
                return Ok(crate::admin::json_response(StatusCode::OK, &body));
            }
            Ok(RevisionedListRead::Mismatch { current }) => {
                let current = store_revision_token(current);
                return Ok(revision_mismatch_response(&current));
            }
            Ok(RevisionedListRead::Unstable) => return Ok(revision_unstable_response()),
            Err(error) => {
                if !PluginConfig::allow_cached_read_fallback(&error) {
                    return Ok(PluginConfig::map_precheck_db_error(&error));
                }
                store_read_failed = true;
                crate::admin::warn_persistence_failure_redacted(
                    "admin_plugin_config_applies_to_cached_fallback",
                );
            }
        }
    }

    let Some(config) = state.cached_gateway_config() else {
        return Ok(no_source_response());
    };
    let revision = format!(
        "{}{}",
        cached_collection_revision::<PluginConfig>(&config, namespace, role),
        cached_collection_revision::<Proxy>(&config, namespace, role)
    );
    if let Some(expected) = query.if_revision.as_deref()
        && expected != revision
    {
        return Ok(revision_mismatch_response(&revision));
    }
    let Some(proxy) = config
        .proxies
        .iter()
        .find(|proxy| proxy.namespace == namespace && proxy.id == proxy_id_target)
    else {
        if store_read_failed {
            return Ok(super::super::cached_fallback_miss_response());
        }
        return Ok(super::not_found_response::<Proxy>());
    };
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

fn role_memo_key(role: AdminRole) -> u8 {
    match role {
        AdminRole::Viewer => 0,
        AdminRole::Operator => 1,
        AdminRole::Admin => 2,
    }
}

/// Memoized cached-config revisions for one config generation, identified by
/// allocation: holding the `Weak` keeps the allocation alive, so a later
/// generation can never reuse the address while the memo refers to it.
struct CachedRevisionMemo {
    config: Weak<GatewayConfig>,
    entries: HashMap<(String, &'static str, u8), String>,
}

static CACHED_REVISION_MEMO: Mutex<Option<CachedRevisionMemo>> = Mutex::new(None);

/// Revision of `R`'s collection in `namespace` within an in-memory config:
/// `c` + the first 16 bytes (hex) of a SHA-256 over the id-ordered caller-role
/// projections. Viewers hash only the viewer projection so the digest never
/// acts as an oracle for withheld secrets; privileged callers hash their own
/// projection so secret-only updates change the revision even when
/// `updated_at` is unchanged.
pub(crate) fn cached_collection_revision<R: QueryableListResource>(
    config: &Arc<GatewayConfig>,
    namespace: &str,
    role: AdminRole,
) -> String {
    let key = (namespace.to_string(), R::RESOURCE_TYPE, role_memo_key(role));
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
    let revision = compute_cached_collection_revision::<R>(config, namespace, role);
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
    role: AdminRole,
) -> String {
    let mut items: Vec<&R> = R::cached_items(config)
        .iter()
        .filter(|resource| resource.namespace() == namespace)
        .collect();
    items.sort_by(|left, right| left.id().cmp(right.id()));
    let mut hasher = crate::fips::approved::Sha256::new();
    hasher.update(R::RESOURCE_TYPE.as_bytes());
    hasher.update([role_memo_key(role)]);
    for item in items {
        let projection = super::response_body_for_role(item, role);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::PaginationParams;
    use crate::admin::jwt_auth::{JwtConfig, JwtManager};
    use crate::config::db_loader::{DatabaseStore, DbPoolConfig};
    use crate::config::types::{PluginScope, Proxy, Upstream};
    use arc_swap::ArcSwap;
    use http_body_util::BodyExt;

    fn make_test_admin_state(
        cached: GatewayConfig,
        db: Option<Arc<dyn DatabaseBackend>>,
    ) -> AdminState {
        AdminState {
            db,
            jwt_manager: JwtManager::new(JwtConfig {
                secret: "list-query-unit-test-secret-0123456789abcdef".to_string(),
                issuer: "list-query-unit-test".to_string(),
                audience: None,
                max_ttl_seconds: 3600,
                algorithm: jsonwebtoken::Algorithm::HS256,
            }),
            metrics_auth: Default::default(),
            cached_config: Some(Arc::new(ArcSwap::new(Arc::new(cached)))),
            proxy_state: None,
            mode: "file".to_string(),
            read_only: true,
            admin_audit_enabled: false,
            admin_audit_fallback_dir: None,
            admin_require_namespace_claim: false,
            startup_ready: None,
            serving_degraded: None,
            serving_listener_failures: None,
            gateway_listener_status: None,
            gateway_listener_failure_fails_readiness: false,
            db_available: None,
            config_rejected: None,
            admin_restore_max_body_size_mib: 100,
            admin_spec_max_body_size_mib: 25,
            reserved_ports: std::collections::HashSet::new(),
            stream_proxy_bind_address: "0.0.0.0".to_string(),
            admin_allowed_cidrs: Arc::new(crate::proxy::client_ip::TrustedProxies::none()),
            cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
            db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
            dp_registry: None,
            mesh_registry: None,
            cp_connection_state: None,
            admin_http_header_read_timeout_seconds: 10,
            mesh_runtime_state: None,
            admin_tls_handshake_timeout_seconds: 10,
            admin_request_limits: Default::default(),
            backend_allow_ips: crate::config::BackendEgressPolicy::unrestricted(),
            external_ref_policy: Arc::new(
                crate::admin::api_specs::ExternalRefProcessPolicy::default(),
            ),
            external_ref_loader: Arc::new(
                crate::admin::api_specs::DefaultExternalDocumentLoader::default(),
            ),
            runtime_config_apply: None,
        }
    }

    async fn read_json(response: Response<Full<Bytes>>) -> (StatusCode, Value) {
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    fn make_upstream(id: &str) -> Upstream {
        serde_json::from_value(json!({
            "id": id,
            "namespace": "ferrum",
            "name": format!("Upstream {id}"),
            "targets": [{"host": "10.0.0.1", "port": 8080}]
        }))
        .unwrap()
    }

    #[test]
    fn parse_list_query_accepts_generated_mesh_ids_and_rejects_invalid_ones() {
        let parsed = parse_list_query(
            Some("ids=__mesh-outbound-default-app-80,__mesh_authz&applies_to_proxy=__mesh-outbound-default-app-80"),
            true,
        )
        .expect("mesh-generated IDs must be accepted");
        assert_eq!(
            parsed.filter.ids.as_deref(),
            Some(
                &[
                    "__mesh-outbound-default-app-80".to_string(),
                    "__mesh_authz".to_string()
                ][..]
            )
        );
        assert_eq!(
            parsed.applies_to_proxy.as_deref(),
            Some("__mesh-outbound-default-app-80")
        );
        assert!(parse_list_query(Some("applies_to_proxy=a..b"), true).is_err());
        assert!(parse_list_query(Some("applies_to_proxy=a/b"), true).is_err());
        assert!(
            parse_list_query(Some(&format!("applies_to_proxy={}", "a".repeat(255))), true).is_err()
        );
    }

    #[tokio::test]
    async fn cached_list_sorts_canonically_by_id_independent_of_config_order() {
        let mut cfg_ab = GatewayConfig::default();
        cfg_ab.upstreams = vec![make_upstream("u-a"), make_upstream("u-b")];
        let mut cfg_ba = GatewayConfig::default();
        cfg_ba.upstreams = vec![make_upstream("u-b"), make_upstream("u-a")];

        let state_ab = make_test_admin_state(cfg_ab, None);
        let state_ba = make_test_admin_state(cfg_ba, None);
        let pagination = PaginationParams::default();
        let query = ListQuery::default();

        let (status_ab, body_ab) = read_json(
            handle_list_query::<Upstream>(
                &state_ab,
                &pagination,
                AdminRole::Admin,
                "ferrum",
                &query,
            )
            .await
            .unwrap(),
        )
        .await;
        let (status_ba, body_ba) = read_json(
            handle_list_query::<Upstream>(
                &state_ba,
                &pagination,
                AdminRole::Admin,
                "ferrum",
                &query,
            )
            .await
            .unwrap(),
        )
        .await;
        assert_eq!(status_ab, StatusCode::OK);
        assert_eq!(status_ba, StatusCode::OK);
        let ids_ab: Vec<&str> = body_ab["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap())
            .collect();
        let ids_ba: Vec<&str> = body_ba["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids_ab, vec!["u-a", "u-b"]);
        assert_eq!(ids_ba, vec!["u-a", "u-b"]);
        assert_eq!(
            body_ab["pagination"]["revision"],
            body_ba["pagination"]["revision"]
        );
    }

    #[test]
    fn cached_revision_is_role_scoped_for_redacted_secrets() {
        let ts = crate::time_compat::UtcTimestamp::now();
        let make_cfg = |secret: &str| {
            let mut cfg = GatewayConfig::default();
            let mut pc: PluginConfig = serde_json::from_value(json!({
                "id": "pc-auth",
                "namespace": "ferrum",
                "plugin_name": "jwt",
                "scope": "global",
                "config": {
                    "secret": secret
                }
            }))
            .unwrap();
            pc.scope = PluginScope::Global;
            pc.created_at = ts;
            pc.updated_at = ts;
            cfg.plugin_configs.push(pc);
            Arc::new(cfg)
        };
        let cfg1 = make_cfg("secret-one-value");
        let cfg2 = make_cfg("secret-two-value");

        // Viewer never observes redacted secret changes (no oracle).
        assert_eq!(
            cached_collection_revision::<PluginConfig>(&cfg1, "ferrum", AdminRole::Viewer),
            cached_collection_revision::<PluginConfig>(&cfg2, "ferrum", AdminRole::Viewer)
        );
        // Privileged roles observe secret changes even with unchanged updated_at.
        assert_ne!(
            cached_collection_revision::<PluginConfig>(&cfg1, "ferrum", AdminRole::Admin),
            cached_collection_revision::<PluginConfig>(&cfg2, "ferrum", AdminRole::Admin)
        );
        assert_ne!(
            cached_collection_revision::<PluginConfig>(&cfg1, "ferrum", AdminRole::Operator),
            cached_collection_revision::<PluginConfig>(&cfg2, "ferrum", AdminRole::Operator)
        );
    }

    #[tokio::test]
    async fn cached_applies_to_proxy_checks_if_revision_before_miss_and_returns_503_on_db_fallback()
    {
        let mut cfg = GatewayConfig::default();
        let mut p: Proxy = serde_json::from_value(json!({
            "id": "px-1",
            "namespace": "ferrum",
            "name": "Proxy 1",
            "backend_host": "127.0.0.1",
            "backend_port": 8080
        }))
        .unwrap();
        p.normalize_fields();
        cfg.proxies.push(p);
        let state = make_test_admin_state(cfg.clone(), None);
        let pagination = PaginationParams::default();

        // Stale if_revision must return 409 even when the target proxy is absent.
        let stale_query = ListQuery {
            if_revision: Some("c00000000000000000000000000000000".to_string()),
            ..ListQuery::default()
        };
        let (status, body) = read_json(
            handle_plugin_configs_applied_to_proxy(
                &state,
                &pagination,
                AdminRole::Admin,
                "ferrum",
                &stale_query,
                "px-missing",
            )
            .await
            .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(body["revision"].as_str().unwrap().starts_with('c'));

        // Without stale if_revision in pure file/cached mode, missing proxy returns 404.
        let (status, _) = read_json(
            handle_plugin_configs_applied_to_proxy(
                &state,
                &pagination,
                AdminRole::Admin,
                "ferrum",
                &ListQuery::default(),
                "px-missing",
            )
            .await
            .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // During a database-outage cached fallback, a missing proxy in the
        // stale cache must answer 503 Service Unavailable (not a false 404),
        // while stale if_revision still answers 409 first.
        let store = DatabaseStore::connect_with_pool_config(
            "sqlite",
            "sqlite::memory:",
            DbPoolConfig::default(),
        )
        .await
        .expect("in-memory sqlite store");
        store.pool().close().await;
        let db_outage_state = make_test_admin_state(cfg, Some(Arc::new(store)));
        let (status, _) = read_json(
            handle_plugin_configs_applied_to_proxy(
                &db_outage_state,
                &pagination,
                AdminRole::Admin,
                "ferrum",
                &ListQuery::default(),
                "px-missing",
            )
            .await
            .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

        let (status, _) = read_json(
            handle_plugin_configs_applied_to_proxy(
                &db_outage_state,
                &pagination,
                AdminRole::Admin,
                "ferrum",
                &stale_query,
                "px-missing",
            )
            .await
            .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }
}
