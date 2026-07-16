use bytes::Bytes;
use chrono::{DateTime, Utc};
use http_body_util::Full;
use hyper::{Response, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::collections::{HashSet, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::sync::OnceLock;
use tokio::sync::{Mutex, MutexGuard};
use uuid::Uuid;

use crate::admin::AdminState;
use crate::admin::audit::{self, AuditActor, AuditEvent};
use crate::admin::jwt_auth::AdminRole;
use crate::config::db_backend::{
    BatchConfigWriteMode, DatabaseBackend, PROXY_ROUTE_CONFLICT_ERROR, PaginatedResult,
    MTLS_DNS_ADMISSION_UNAVAILABLE_MESSAGE, is_mtls_dns_admission_unavailable,
    is_mtls_dns_identity_conflict,
};
use crate::config::db_loader::is_proxy_plugin_association_load_error;
use crate::config::types::{
    Consumer, GatewayConfig, PluginConfig, PluginScope, Proxy, RetryConfig, Upstream,
    first_effective_mesh_transport_conflict_with_mesh, mesh_transport_retry_conflict_message,
    proxy_retry_is_effective, proxy_with_resolved_port_caps, validate_resource_id,
};
use crate::plugins::mesh_route_dispatch::MeshRouteDispatchConfig;

pub(crate) type DbResult<T> = Result<T, anyhow::Error>;

pub(crate) struct ValidationCtx<'a> {
    pub reserved_ports: &'a HashSet<u16>,
    pub stream_bind_address: &'a str,
    pub mode: &'a str,
    /// Backend egress policy, so per-resource admin writes screen literal-IP
    /// backend targets the same way the file/db/restore loaders do.
    pub backend_allow_ips: &'a crate::config::BackendEgressPolicy,
}

impl<'a> ValidationCtx<'a> {
    pub(crate) fn from_state(state: &'a AdminState) -> Self {
        Self {
            reserved_ports: &state.reserved_ports,
            stream_bind_address: &state.stream_proxy_bind_address,
            mode: &state.mode,
            backend_allow_ips: &state.backend_allow_ips,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum WriteAction<'a> {
    Create,
    Update { id: &'a str },
}

pub(crate) enum AfterValidateError {
    BadRequest(Vec<String>),
    Conflict(Vec<String>),
    Db(anyhow::Error),
    Response(Box<Response<Full<Bytes>>>),
}

/// Validation outcomes for resource-specific checks and generic field validation.
pub(crate) enum ValidationError {
    Fields(Vec<String>),
    Message(String),
}

/// A write-preparation failure whose origin determines the HTTP status.
pub(crate) enum PrepareWriteError {
    InvalidRequest(String),
    Internal(String),
}

impl PrepareWriteError {
    fn status(&self) -> StatusCode {
        match self {
            Self::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn message(&self) -> &str {
        match self {
            Self::InvalidRequest(message) | Self::Internal(message) => message,
        }
    }
}

pub(crate) enum BatchPreparationError {
    Validation(Vec<String>),
    Internal(String),
}

const MTLS_ADMISSION_LOCK_SHARDS: usize = 64;
static MTLS_ADMISSION_LOCKS: OnceLock<Vec<Mutex<()>>> = OnceLock::new();

/// Same-process serialization of mTLS-sensitive admin mutations for a namespace
/// from candidate validation through persistence. A bounded process-global
/// lock set covers every `AdminState` served by this process without retaining
/// attacker-chosen namespace strings indefinitely.
///
/// SQL transactions and MongoDB leases provide the authoritative cross-process
/// backstop. The additional ASCII-folded `san_dns` constraint is conditional on
/// effective plugin associations, so it cannot use an unconditional case-folded
/// unique index without rejecting valid case variants used by exact-match
/// policies. This lock avoids redundant same-process candidate work while the
/// backend serialization covers separate admin processes.
/// Every credential mutation takes this lock, even for non-mTLS types, because
/// those endpoints persist the complete `Consumer` and could otherwise replay
/// stale `mtls_auth` entries loaded before a concurrent mTLS mutation.
pub(crate) async fn lock_mtls_admission(namespace: &str) -> MutexGuard<'static, ()> {
    let locks = MTLS_ADMISSION_LOCKS.get_or_init(|| {
        (0..MTLS_ADMISSION_LOCK_SHARDS)
            .map(|_| Mutex::new(()))
            .collect()
    });
    let mut hasher = DefaultHasher::new();
    namespace.hash(&mut hasher);
    let shard = hasher.finish() as usize % MTLS_ADMISSION_LOCK_SHARDS;
    locks[shard].lock().await
}

async fn validate_mtls_auth_candidate(
    db: &dyn DatabaseBackend,
    namespace: &str,
    proxy: Option<&Proxy>,
    plugin: Option<&PluginConfig>,
    removed_plugin_id: Option<&str>,
) -> Result<(), AfterValidateError> {
    let mut config = db
        .load_namespace_snapshot(namespace)
        .await
        .map_err(AfterValidateError::Db)?;
    if let Some(proxy) = proxy {
        if let Some(existing) = config.proxies.iter_mut().find(|item| item.id == proxy.id) {
            *existing = proxy.clone();
        } else {
            config.proxies.push(proxy.clone());
        }
    }
    if let Some(plugin) = plugin {
        if let Some(existing) = config
            .plugin_configs
            .iter_mut()
            .find(|item| item.id == plugin.id)
        {
            *existing = plugin.clone();
        } else {
            config.plugin_configs.push(plugin.clone());
        }
    }
    if let Some(removed_plugin_id) = removed_plugin_id {
        config
            .plugin_configs
            .retain(|plugin| plugin.id != removed_plugin_id);
    }
    if proxy
        .is_some_and(|candidate| !config.has_effective_mtls_auth_for_proxy(candidate.id.as_str()))
    {
        return Ok(());
    }
    let compatibility_errors = config
        .validate_mtls_auth_compatibility()
        .err()
        .unwrap_or_default();
    if !compatibility_errors.is_empty() {
        return Err(AfterValidateError::BadRequest(compatibility_errors));
    }
    config
        .validate_unique_mtls_credentials()
        .map_err(AfterValidateError::Conflict)
}

pub(crate) async fn validate_hmac_request_transform_candidates(
    db: &dyn DatabaseBackend,
    state: &AdminState,
    namespace: &str,
    proxies: &[Proxy],
    plugins: &[PluginConfig],
    removed_plugin_id: Option<&str>,
) -> Result<(), AfterValidateError> {
    // Global plugin scope is global within one runtime namespace. CP snapshots
    // are filtered before broadcast and file/database modes load one namespace,
    // so cross-namespace plugins must never create false admission conflicts.
    let mut candidate = db
        .load_namespace_snapshot(namespace)
        .await
        .map_err(AfterValidateError::Db)?;

    if let Some(removed_plugin_id) = removed_plugin_id {
        candidate
            .plugin_configs
            .retain(|plugin| plugin.namespace != namespace || plugin.id != removed_plugin_id);
    }

    for proxy in proxies {
        if let Some(existing) = candidate
            .proxies
            .iter_mut()
            .find(|item| item.namespace == namespace && item.id == proxy.id)
        {
            *existing = proxy.clone();
        } else {
            candidate.proxies.push(proxy.clone());
        }
    }
    for plugin in plugins {
        if let Some(existing) = candidate
            .plugin_configs
            .iter_mut()
            .find(|item| item.namespace == namespace && item.id == plugin.id)
        {
            *existing = plugin.clone();
        } else {
            candidate.plugin_configs.push(plugin.clone());
        }
    }

    let http_client = super::plugin_validation_http_client(state);
    crate::plugin_cache::validate_hmac_request_transform_candidate(&candidate, &http_client)
        .map_err(|error| AfterValidateError::BadRequest(vec![error]))
}

/// Validate the exact post-PUT API-spec replacement candidate.
///
/// The persistence contract deletes plugin configs owned by the replaced spec,
/// removes associations declared only by the previous spec, preserves manual
/// associations, and then overlays the incoming proxy and plugins. Build that
/// same graph here so admission neither rejects a valid replacement because of
/// removed globals nor admits an invalid chain by dropping retained manual
/// associations.
pub(crate) async fn validate_hmac_request_transform_api_spec_replacement_candidate(
    db: &dyn DatabaseBackend,
    state: &AdminState,
    namespace: &str,
    existing_spec: &crate::config::types::ApiSpec,
    proxy: &Proxy,
    plugins: &[PluginConfig],
) -> Result<(), AfterValidateError> {
    let mut candidate = db
        .load_namespace_snapshot(namespace)
        .await
        .map_err(AfterValidateError::Db)?;
    let replaced_plugins = db
        .list_spec_owned_plugin_configs(namespace, &existing_spec.id)
        .await
        .map_err(AfterValidateError::Db)?;
    let replaced_plugin_ids: HashSet<String> = replaced_plugins
        .into_iter()
        .map(|plugin| plugin.id)
        .collect();

    // Only plugin configs owned by this spec are replaceable. Treating an
    // incoming same-ID plugin as an overlay on a manual or differently owned
    // config would make the in-memory candidate diverge from persistence,
    // where the insert is rejected by the plugin-config primary key.
    if let Some(plugin) = plugins.iter().find(|plugin| {
        !replaced_plugin_ids.contains(&plugin.id)
            && candidate
                .plugin_configs
                .iter()
                .any(|existing| existing.namespace == namespace && existing.id == plugin.id)
    }) {
        return Err(AfterValidateError::BadRequest(vec![format!(
            "plugin_config id '{}' already exists in namespace '{}' outside api_spec '{}'; replacement cannot take ownership of it",
            plugin.id, namespace, existing_spec.id
        )]));
    }

    candidate
        .plugin_configs
        .retain(|plugin| !replaced_plugin_ids.contains(&plugin.id));
    for candidate_proxy in &mut candidate.proxies {
        candidate_proxy
            .plugins
            .retain(|association| !replaced_plugin_ids.contains(&association.plugin_config_id));
    }

    let previous_declared_assoc_ids =
        crate::admin::api_specs::declared_proxy_plugin_association_ids_from_stored_spec(
            existing_spec,
        );
    let incoming_assoc_ids: HashSet<&str> = proxy
        .plugins
        .iter()
        .map(|association| association.plugin_config_id.as_str())
        .collect();
    let mut replacement_proxy = proxy.clone();
    let mut preserved_associations = candidate
        .proxies
        .iter()
        .find(|item| item.namespace == namespace && item.id == proxy.id)
        .map(|item| item.plugins.clone())
        .unwrap_or_default();
    preserved_associations.retain(|association| {
        !previous_declared_assoc_ids.contains(&association.plugin_config_id)
            && !incoming_assoc_ids.contains(association.plugin_config_id.as_str())
    });
    preserved_associations.extend(proxy.plugins.iter().cloned());
    replacement_proxy.plugins = preserved_associations;

    if let Some(existing) = candidate
        .proxies
        .iter_mut()
        .find(|item| item.namespace == namespace && item.id == proxy.id)
    {
        *existing = replacement_proxy;
    } else {
        candidate.proxies.push(replacement_proxy);
    }
    for plugin in plugins {
        if let Some(existing) = candidate
            .plugin_configs
            .iter_mut()
            .find(|item| item.namespace == namespace && item.id == plugin.id)
        {
            *existing = plugin.clone();
        } else {
            candidate.plugin_configs.push(plugin.clone());
        }
    }

    let http_client = super::plugin_validation_http_client(state);
    crate::plugin_cache::validate_hmac_request_transform_candidate(&candidate, &http_client)
        .map_err(|error| AfterValidateError::BadRequest(vec![error]))
}

/// Validate a wholesale namespace replacement without retaining resources that
/// the restore will delete. Runtime plugin chains are namespace-scoped, so the
/// normalized replacement is the complete authoritative candidate.
pub(crate) fn validate_hmac_request_transform_restore_candidate(
    state: &AdminState,
    replacement: &GatewayConfig,
) -> Result<(), AfterValidateError> {
    let http_client = super::plugin_validation_http_client(state);
    crate::plugin_cache::validate_hmac_request_transform_candidate(replacement, &http_client)
        .map_err(|error| AfterValidateError::BadRequest(vec![error]))
}

async fn consumer_candidate_config(
    db: &dyn DatabaseBackend,
    namespace: &str,
    consumer: &Consumer,
) -> DbResult<GatewayConfig> {
    let mut config = db.load_namespace_snapshot(namespace).await?;
    if let Some(existing) = config
        .consumers
        .iter_mut()
        .find(|item| item.id == consumer.id)
    {
        *existing = consumer.clone();
    } else {
        config.consumers.push(consumer.clone());
    }
    Ok(config)
}

pub(crate) async fn mtls_consumer_candidate_errors(
    db: &dyn DatabaseBackend,
    namespace: &str,
    consumer: &Consumer,
) -> DbResult<Vec<String>> {
    Ok(consumer_candidate_config(db, namespace, consumer)
        .await?
        .validate_unique_mtls_credentials()
        .err()
        .unwrap_or_default())
}

/// Reject an admin Consumer/credential write whose hmac_auth secret is
/// already claimed by another consumer in the namespace. Snapshot-based like
/// the mTLS candidate check (rather than a credential-index probe) so
/// pre-existing rows written before hmac secrets were policed are still
/// authoritative. `lock_mtls_admission` serializes same-process prechecks;
/// namespace-scoped SQL/Mongo uniqueness constraints are the cross-process
/// persistence backstop.
pub(crate) async fn hmac_consumer_candidate_errors(
    db: &dyn DatabaseBackend,
    namespace: &str,
    consumer: &Consumer,
) -> DbResult<Vec<String>> {
    Ok(consumer_candidate_config(db, namespace, consumer)
        .await?
        .validate_unique_hmac_credentials()
        .err()
        .unwrap_or_default())
}

impl ValidationError {
    fn into_messages(self) -> Vec<String> {
        match self {
            Self::Fields(errors) => errors,
            Self::Message(message) => vec![message],
        }
    }
}

#[allow(async_fn_in_trait)]
pub(crate) trait AdminResource:
    Send + Sync + Serialize + DeserializeOwned + Clone + Sized + 'static
{
    const RESOURCE_NAME: &'static str;
    const RESOURCE_LABEL: &'static str;
    const VALIDATION_ERROR_LABEL: &'static str;
    const NOT_FOUND_MESSAGE: &'static str;
    const ID_CONFLICT_LABEL: &'static str = Self::RESOURCE_LABEL;
    const SERIALIZE_MTLS_ADMISSION: bool = false;

    fn id(&self) -> &str;
    fn set_id(&mut self, id: String);
    fn namespace(&self) -> &str;
    fn set_namespace(&mut self, ns: String);
    fn set_created_at(&mut self, now: DateTime<Utc>);
    fn set_updated_at(&mut self, now: DateTime<Utc>);
    fn normalize(&mut self);
    fn validate(&self, ctx: &ValidationCtx<'_>) -> Result<(), ValidationError>;
    fn cached_items(config: &GatewayConfig) -> &[Self];

    fn response_body(resource: &Self) -> Value {
        json!(resource)
    }

    fn response_body_for_role(resource: &Self, _role: AdminRole) -> Value {
        Self::response_body(resource)
    }

    fn audit_body(resource: &Self) -> Value {
        Self::response_body(resource)
    }

    /// Inspect the raw request body *before* it is deserialized into `Self`.
    /// Return `Err` to reject the request with a 400 Bad Request. Default is
    /// a no-op. Override on resources that need schema-specific raw checks.
    fn validate_raw_body(_body: &[u8]) -> Result<(), String> {
        Ok(())
    }

    fn prepare_for_update(&mut self, _existing: &Self) {}

    fn prepare_for_write(&mut self) -> Result<(), PrepareWriteError> {
        Ok(())
    }

    fn map_validation_error(error: &ValidationError) -> Response<Full<Bytes>> {
        match error {
            ValidationError::Fields(errors) => validation_error_response::<Self>(errors),
            ValidationError::Message(message) => {
                validation_error_response::<Self>(std::slice::from_ref(message))
            }
        }
    }

    fn map_after_validate_errors(errors: &[String]) -> Response<Full<Bytes>> {
        validation_error_response::<Self>(errors)
    }

    fn map_precheck_db_error(error: &anyhow::Error) -> Response<Full<Bytes>> {
        super::json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &super::db_error_response(error),
        )
    }

    fn map_persist_db_error(
        error: &anyhow::Error,
        _action: WriteAction<'_>,
    ) -> Response<Full<Bytes>> {
        if is_mtls_dns_admission_unavailable(error) {
            return super::mtls_dns_admission_unavailable_response();
        }
        // Unique-constraint violations at persist time are conflicts, not
        // server faults: the admission prechecks are namespace-scoped and
        // raceable, so the DB constraint is the authoritative backstop (e.g.
        // reusing a proxy/upstream id that exists in another namespace, or a
        // concurrent create winning the race after the precheck passed).
        // Surface the constraint message (it names the conflicting key);
        // everything else stays a redacted 500.
        let message = error.to_string();
        if is_mtls_dns_identity_conflict(error) || super::is_unique_constraint_violation(&message) {
            super::json_response(StatusCode::CONFLICT, &json!({ "error": message }))
        } else {
            super::json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &super::db_error_response(error),
            )
        }
    }

    fn map_delete_db_error(error: &anyhow::Error) -> Response<Full<Bytes>> {
        if is_mtls_dns_admission_unavailable(error) {
            super::mtls_dns_admission_unavailable_response()
        } else if is_mtls_dns_identity_conflict(error) {
            super::json_response(StatusCode::CONFLICT, &json!({"error": error.to_string()}))
        } else {
            super::json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &super::db_error_response(error),
            )
        }
    }

    fn allow_cached_read_fallback(_error: &anyhow::Error) -> bool {
        true
    }

    // Reads/deletes are namespace-predicated at the query level (issue #2122
    // DB-M1): the backend WHERE clause / filter document carries the tenant
    // boundary, so no post-read namespace comparison is needed here.
    async fn db_get(db: &dyn DatabaseBackend, namespace: &str, id: &str) -> DbResult<Option<Self>>;
    async fn db_get_for_write(
        db: &dyn DatabaseBackend,
        namespace: &str,
        id: &str,
    ) -> DbResult<Option<Self>> {
        Self::db_get(db, namespace, id).await
    }
    async fn db_list(
        db: &dyn DatabaseBackend,
        namespace: &str,
        pagination: &super::PaginationParams,
    ) -> DbResult<PaginatedResult<Self>>;
    async fn db_create(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<()>;
    /// Returns `Ok(false)` when no row/document matched `(namespace, id)` —
    /// a PUT racing a concurrent delete surfaces as not-found instead of a
    /// phantom success (issue #2122 DB-M4).
    async fn db_update(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<bool>;
    async fn db_delete(db: &dyn DatabaseBackend, namespace: &str, id: &str) -> DbResult<bool>;

    async fn check_uniqueness(
        db: &dyn DatabaseBackend,
        namespace: &str,
        resource: &Self,
        exclude_id: Option<&str>,
    ) -> DbResult<Option<String>>;

    async fn after_validate(
        _db: &dyn DatabaseBackend,
        _state: &AdminState,
        _namespace: &str,
        _resource: &Self,
        _existing: Option<&Self>,
        _ctx: &ValidationCtx<'_>,
    ) -> Result<(), AfterValidateError> {
        Ok(())
    }

    async fn before_delete(
        _db: &dyn DatabaseBackend,
        _state: &AdminState,
        _namespace: &str,
        _existing: &Self,
        _ctx: &ValidationCtx<'_>,
    ) -> Result<(), AfterValidateError> {
        Ok(())
    }

    async fn after_write(
        _db: &dyn DatabaseBackend,
        _state: &AdminState,
        _namespace: &str,
        _resource: &Self,
        _existing: Option<&Self>,
        _action: WriteAction<'_>,
    ) -> DbResult<()> {
        Ok(())
    }
}

pub(crate) async fn handle_list<R: AdminResource>(
    state: &AdminState,
    pagination: &super::PaginationParams,
    role: AdminRole,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(ref db) = state.db {
        match R::db_list(db.as_ref(), namespace, pagination).await {
            Ok(result) => {
                let items: Vec<Value> = result
                    .items
                    .iter()
                    .map(|resource| R::response_body_for_role(resource, role))
                    .collect();
                let body = super::paginate_db_response(&items, result.total, pagination);
                return Ok(super::json_response(StatusCode::OK, &body));
            }
            Err(error) => {
                if !R::allow_cached_read_fallback(&error) {
                    return Ok(R::map_precheck_db_error(&error));
                }
                tracing::warn!(
                    "Database unavailable for list {}, falling back to cached config: {}",
                    R::RESOURCE_NAME,
                    error
                );
            }
        }
    }

    if let Some(config) = state.cached_gateway_config() {
        let items: Vec<Value> = R::cached_items(&config)
            .iter()
            .filter(|resource| resource.namespace() == namespace)
            .map(|resource| R::response_body_for_role(resource, role))
            .collect();
        let body = super::paginate_response(&json!(items), pagination);
        Ok(super::json_response_with_stale(StatusCode::OK, &body))
    } else {
        Ok(super::json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "No database and no cached config available"}),
        ))
    }
}

pub(crate) async fn handle_get<R: AdminResource>(
    state: &AdminState,
    id: &str,
    role: AdminRole,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Err(message) = validate_resource_id(id) {
        return Ok(super::json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": message}),
        ));
    }

    if let Some(ref db) = state.db {
        match R::db_get(db.as_ref(), namespace, id).await {
            Ok(Some(resource)) => {
                let body = R::response_body_for_role(&resource, role);
                return Ok(super::json_response(StatusCode::OK, &body));
            }
            Ok(None) => {
                return Ok(not_found_response::<R>());
            }
            Err(error) => {
                if !R::allow_cached_read_fallback(&error) {
                    return Ok(R::map_precheck_db_error(&error));
                }
                tracing::warn!(
                    "Database unavailable for get {}, falling back to cached config: {}",
                    R::RESOURCE_NAME,
                    error
                );
            }
        }
    }

    if let Some(config) = state.cached_gateway_config() {
        match R::cached_items(&config)
            .iter()
            .find(|resource| resource.id() == id && resource.namespace() == namespace)
        {
            Some(resource) => {
                let body = R::response_body_for_role(resource, role);
                Ok(super::json_response_with_stale(StatusCode::OK, &body))
            }
            None => Ok(not_found_response::<R>()),
        }
    } else {
        Ok(super::json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "No database and no cached config available"}),
        ))
    }
}

pub(crate) async fn handle_create<R: AdminResource>(
    state: &AdminState,
    actor: &AuditActor,
    body: &[u8],
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    handle_write::<R>(state, actor, body, namespace, WriteAction::Create).await
}

pub(crate) async fn handle_update<R: AdminResource>(
    state: &AdminState,
    actor: &AuditActor,
    id: &str,
    body: &[u8],
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    handle_write::<R>(state, actor, body, namespace, WriteAction::Update { id }).await
}

pub(crate) async fn handle_delete<R: AdminResource>(
    state: &AdminState,
    actor: &AuditActor,
    id: &str,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(response) = state.check_write_allowed() {
        return Ok(response);
    }

    if let Err(message) = validate_resource_id(id) {
        return Ok(super::json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": message}),
        ));
    }

    let db_arc = match state.db.as_ref() {
        Some(db) => db.clone(),
        None => {
            return Ok(super::json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };
    let db = db_arc.as_ref();
    let _mtls_admission_guard = if R::SERIALIZE_MTLS_ADMISSION {
        Some(lock_mtls_admission(namespace).await)
    } else {
        None
    };

    let existing = match R::db_get_for_write(db, namespace, id).await {
        Ok(None) => {
            return Ok(not_found_response::<R>());
        }
        Err(error) => {
            return Ok(R::map_precheck_db_error(&error));
        }
        Ok(Some(resource)) => resource,
    };

    let validation_ctx = ValidationCtx::from_state(state);
    if let Err(error) = R::before_delete(db, state, namespace, &existing, &validation_ctx).await {
        return Ok(map_after_validate_error::<R>(error));
    }

    match R::db_delete(db, namespace, id).await {
        Ok(true) => {
            let event = AuditEvent::new(
                actor,
                "delete",
                R::RESOURCE_NAME.replace(' ', "_"),
                id,
                namespace,
                audit::delete_diff(R::audit_body(&existing)),
            );
            if let Err(error) = audit::record(state.admin_audit_enabled, db_arc, event) {
                super::log_audit_enqueue_failure(&error);
            }
            Ok(super::empty_response(StatusCode::NO_CONTENT))
        }
        Ok(false) => Ok(not_found_response::<R>()),
        Err(error) => Ok(R::map_delete_db_error(&error)),
    }
}

pub(crate) fn prepare_batch_resource<R: AdminResource>(
    resource: &mut R,
    namespace: &str,
    now: DateTime<Utc>,
    validation_ctx: &ValidationCtx<'_>,
) -> Result<(), BatchPreparationError> {
    if resource.id().is_empty() {
        resource.set_id(Uuid::new_v4().to_string());
    } else if let Err(message) = validate_resource_id(resource.id()) {
        return Err(BatchPreparationError::Validation(vec![message]));
    }

    resource.normalize();
    resource.set_namespace(namespace.to_string());
    resource
        .validate(validation_ctx)
        .map_err(ValidationError::into_messages)
        .map_err(BatchPreparationError::Validation)?;
    if let Err(error) = resource.prepare_for_write() {
        return Err(match error {
            PrepareWriteError::InvalidRequest(message) => {
                BatchPreparationError::Validation(vec![message])
            }
            PrepareWriteError::Internal(message) => BatchPreparationError::Internal(message),
        });
    }
    resource.set_created_at(now);
    resource.set_updated_at(now);
    Ok(())
}

pub(crate) fn redact_consumer_for_response(consumer: &Consumer) -> Consumer {
    super::redact_consumer_credentials(consumer)
}

pub(crate) fn consumer_response_body(consumer: &Consumer) -> Value {
    json!(redact_consumer_for_response(consumer))
}

pub(crate) fn consumer_audit_body(consumer: &Consumer) -> Value {
    json!(super::redact_consumer_credentials_for_audit(consumer))
}

pub(crate) fn consumer_persist_error_response(error: &anyhow::Error) -> Response<Full<Bytes>> {
    if config_update_target_was_not_found(error) {
        return not_found_response::<Consumer>();
    }
    if is_mtls_dns_admission_unavailable(error) {
        return super::mtls_dns_admission_unavailable_response();
    }
    let unique_conflict = is_mtls_dns_identity_conflict(error)
        || super::is_unique_constraint_violation(&error.to_string());
    let message = consumer_persist_error_message(error);
    let status = if unique_conflict {
        StatusCode::CONFLICT
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    super::json_response(status, &json!({"error": message}))
}

/// Redact persistence-level uniqueness diagnostics before they reach an admin
/// response. MongoDB duplicate-key errors can echo indexed credential-derived
/// values; callers need the conflict disposition, never credential or index
/// metadata.
pub(crate) fn consumer_persist_error_message(error: &anyhow::Error) -> String {
    if is_mtls_dns_admission_unavailable(error) {
        MTLS_DNS_ADMISSION_UNAVAILABLE_MESSAGE.to_string()
    } else if is_mtls_dns_identity_conflict(error) {
        error.to_string()
    } else if super::is_unique_constraint_violation(&error.to_string()) {
        "Consumer identity or credential conflicts with another Consumer in the namespace"
            .to_string()
    } else {
        error.to_string()
    }
}

pub(crate) fn hash_consumer_credentials(
    consumer: &mut Consumer,
) -> Result<(), crate::config::types::BasicAuthCredentialPreparationError> {
    super::hash_consumer_secrets(consumer)
}

pub(crate) fn hash_basic_auth_credentials(
    cred: &mut Value,
) -> Result<(), crate::config::types::BasicAuthCredentialPreparationError> {
    super::hash_credential_passwords(cred)
}

pub(crate) fn validate_plugin_config_definition(
    state: &AdminState,
    pc: &PluginConfig,
) -> Result<(), String> {
    super::validate_plugin_config_definition(pc, super::plugin_validation_http_client(state))
}

async fn validate_openapi_validator_precondition(
    db: &dyn DatabaseBackend,
    namespace: &str,
    resource: &PluginConfig,
) -> Result<(), AfterValidateError> {
    if resource.plugin_name != "openapi_validator" {
        return Ok(());
    }
    if resource.scope != PluginScope::Proxy {
        return Err(AfterValidateError::BadRequest(vec![
            "openapi_validator requires scope 'proxy'".to_string(),
        ]));
    }
    let Some(proxy_id) = resource.proxy_id.as_deref() else {
        return Err(AfterValidateError::BadRequest(vec![
            "openapi_validator requires proxy_id".to_string(),
        ]));
    };
    // The lookup is namespace-predicated, so a proxy living in another
    // namespace is indistinguishable from a missing one — cross-namespace
    // references are rejected without disclosing other tenants' resources.
    match db.get_proxy(namespace, proxy_id).await {
        Ok(Some(proxy)) if proxy.api_spec_id.is_none() => {
            Err(AfterValidateError::BadRequest(vec![
                "openapi_validator requires a proxy with an attached api_spec".to_string(),
            ]))
        }
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(AfterValidateError::BadRequest(vec![format!(
            "proxy_id '{}' does not exist in namespace '{}'",
            proxy_id, namespace
        )])),
        Err(error) => Err(AfterValidateError::Db(error)),
    }
}

pub(crate) async fn validate_mesh_route_dispatch_plugin_upstream_references(
    db: &dyn DatabaseBackend,
    namespace: &str,
    plugin_config: &PluginConfig,
    batch_upstream_ids: Option<&HashSet<&str>>,
) -> DbResult<Vec<String>> {
    if !plugin_config.enabled || plugin_config.plugin_name != "mesh_route_dispatch" {
        return Ok(Vec::new());
    }

    let dispatch_config = match MeshRouteDispatchConfig::from_value(&plugin_config.config) {
        Ok(config) => config,
        Err(_) => return Ok(Vec::new()),
    };

    let mut errors = Vec::new();
    for (rule_idx, rule) in dispatch_config.rules.iter().enumerate() {
        let Some(upstream_id) = rule.destination.upstream_id.as_deref() else {
            continue;
        };
        if batch_upstream_ids.is_some_and(|ids| ids.contains(upstream_id)) {
            continue;
        }

        match db.check_upstream_exists(upstream_id, namespace).await {
            Ok(true) => {}
            Ok(false) => {
                // Reads are namespace-predicated, so an upstream in another
                // namespace reports as non-existent (cross-namespace
                // references are equally forbidden either way).
                errors.push(format!(
                    "PluginConfig '{}' (mesh_route_dispatch) rule {} references upstream_id '{}' that does not exist in namespace '{}'",
                    plugin_config.id, rule_idx, upstream_id, namespace
                ));
            }
            Err(error) => return Err(error),
        }
    }

    Ok(errors)
}

/// Reject a `mesh_route_dispatch` plugin write that would route a retry-enabled
/// proxy's matched traffic to an upstream requiring a mesh transport
/// (`mesh.hbone` / `mesh.mtls`). At runtime effective retry forces that transport
/// off and the request 502s (issue #1669); the existence-only reference
/// validator does not catch this, so a plugin update can otherwise persist the
/// forbidden combination.
///
/// Scans the proxies this plugin applies to (its `proxy_id` for proxy scope,
/// `proxy.plugins` associations for proxy-group scope, every proxy for global
/// scope) and evaluates each mesh-overriding rule's effective retry — honoring
/// the rule's own `retry` / `retry_disabled` and the proxy's per-port retry cap.
async fn validate_mesh_route_dispatch_plugin_retry_conflicts(
    db: &dyn DatabaseBackend,
    namespace: &str,
    plugin_config: &PluginConfig,
    mesh_model: Option<&crate::modes::mesh::config::MeshConfig>,
) -> Result<Vec<String>, AfterValidateError> {
    if !plugin_config.enabled || plugin_config.plugin_name != "mesh_route_dispatch" {
        // Disabling (or renaming away from `mesh_route_dispatch`) a proxy-scoped /
        // proxy_group instance that the proxy ATTACHES stops it shadowing global
        // `mesh_route_dispatch` plugins of the same name (`PluginCache::build_cache`
        // removes a global only while a same-name local instance is enabled). A
        // retry-enabled proxy can therefore start inheriting an existing global rule
        // that routes to a mesh-tagged upstream, which the runtime would 502. The
        // enabled-rule scan below never runs for this write, so re-check the
        // newly-unshadowed globals for the proxies that attach this plugin. (A
        // disabled GLOBAL instance cannot ADD a conflict — it only stops its own
        // rules running — so this only applies to proxy / proxy_group scope.)
        if matches!(
            plugin_config.scope,
            PluginScope::Proxy | PluginScope::ProxyGroup
        ) {
            return validate_unshadowed_globals_for_plugin(
                db,
                namespace,
                plugin_config,
                mesh_model,
            )
            .await;
        }
        return Ok(Vec::new());
    }
    let dispatch = match MeshRouteDispatchConfig::from_value(&plugin_config.config) {
        Ok(config) => config,
        Err(_) => return Ok(Vec::new()),
    };
    // Rules that override the upstream; the rest can't introduce this conflict.
    // A redirect rule answers the request before any upstream override is applied
    // (`build_redirect_response` short-circuits), so it never dispatches to its
    // `destination.upstream_id` and must be skipped.
    let override_rules: Vec<_> = dispatch
        .rules
        .iter()
        .filter(|rule| rule.redirect.is_none() && rule.destination.upstream_id.is_some())
        .collect();
    if override_rules.is_empty() {
        return Ok(Vec::new());
    }

    let mut errors = Vec::new();
    match plugin_config.scope {
        PluginScope::Proxy => {
            // A proxy-scoped instance only runs when the named proxy's `plugins`
            // association list contains this config id — `PluginCache::build_cache`
            // gates instantiation on that association (it does not auto-attach by
            // `proxy_id`). An inert/staged enabled config that the proxy has not
            // attached never dispatches, so it must NOT trigger a conflict.
            if let Some(proxy_id) = plugin_config.proxy_id.as_deref()
                && let Some(proxy) = db
                    .get_proxy(namespace, proxy_id)
                    .await
                    .map_err(AfterValidateError::Db)?
                && proxy
                    .plugins
                    .iter()
                    .any(|assoc| assoc.plugin_config_id == plugin_config.id)
            {
                evaluate_mesh_route_dispatch_rules_for_proxy(
                    db,
                    namespace,
                    &proxy,
                    &override_rules,
                    mesh_model,
                    &mut errors,
                )
                .await
                .map_err(AfterValidateError::Db)?;
            }
        }
        PluginScope::Global | PluginScope::ProxyGroup => {
            // Global runs on every proxy; proxy-group runs on proxies that
            // associate this plugin id via `proxy.plugins`.
            let mut offset = 0_i64;
            const PAGE_SIZE: i64 = 1_000;
            loop {
                let page = db
                    .list_proxies_paginated(namespace, PAGE_SIZE, offset)
                    .await
                    .map_err(AfterValidateError::Db)?;
                let items_len = page.items.len() as i64;
                for proxy in &page.items {
                    let applies = if plugin_config.scope == PluginScope::Global {
                        // A global instance is shadowed on any proxy that attaches
                        // its own enabled `mesh_route_dispatch` (PluginCache removes
                        // globals of the same name), so it never runs there.
                        !proxy_shadows_global_mesh_route_dispatch(db, namespace, proxy)
                            .await
                            .map_err(AfterValidateError::Db)?
                    } else {
                        // proxy_group: only proxies that associate this plugin id.
                        proxy
                            .plugins
                            .iter()
                            .any(|assoc| assoc.plugin_config_id == plugin_config.id)
                    };
                    if applies {
                        evaluate_mesh_route_dispatch_rules_for_proxy(
                            db,
                            namespace,
                            proxy,
                            &override_rules,
                            mesh_model,
                            &mut errors,
                        )
                        .await
                        .map_err(AfterValidateError::Db)?;
                    }
                }
                if items_len == 0 {
                    break;
                }
                offset += items_len;
                if offset >= page.total {
                    break;
                }
            }
        }
    }

    Ok(errors)
}

/// Re-validate retry/mesh-transport conflicts that a proxy/proxy_group
/// `mesh_route_dispatch` plugin write *unshadows* by ceasing to be an enabled
/// `mesh_route_dispatch` (it was disabled or renamed to a different plugin).
///
/// While a proxy attaches an enabled `mesh_route_dispatch` instance,
/// `PluginCache::build_cache` removes every global `mesh_route_dispatch` of the
/// same name from that proxy's chain. Disabling the local instance therefore lets
/// the proxy inherit those globals again — and a global rule routing matched
/// traffic to a mesh-tagged upstream (`mesh.hbone` / `mesh.mtls`) 502s on a
/// retry-enabled proxy. The normal enabled-rule scan does not run for this write,
/// so check the now-applicable globals for every proxy that attaches this plugin.
///
/// `after_validate` runs BEFORE the DB write, so the DB still reports this plugin
/// as the old enabled `mesh_route_dispatch`; the shadow recomputation deliberately
/// ignores `plugin_config.id` (the instance being unshadowed) while still honoring
/// any OTHER enabled `mesh_route_dispatch` the proxy attaches.
async fn validate_unshadowed_globals_for_plugin(
    db: &dyn DatabaseBackend,
    namespace: &str,
    plugin_config: &PluginConfig,
    mesh_model: Option<&crate::modes::mesh::config::MeshConfig>,
) -> Result<Vec<String>, AfterValidateError> {
    // Collect the override rules of every enabled global `mesh_route_dispatch`.
    // Parsed configs are kept owned so the borrowed rule slice stays valid.
    let mut global_dispatch_configs: Vec<MeshRouteDispatchConfig> = Vec::new();
    {
        let mut offset = 0_i64;
        const PAGE_SIZE: i64 = 1_000;
        loop {
            let page = db
                .list_plugin_configs_paginated(namespace, PAGE_SIZE, offset)
                .await
                .map_err(AfterValidateError::Db)?;
            let items_len = page.items.len() as i64;
            for plugin in &page.items {
                if plugin.scope == PluginScope::Global
                    && plugin.enabled
                    && plugin.plugin_name == "mesh_route_dispatch"
                    && let Ok(dispatch) = MeshRouteDispatchConfig::from_value(&plugin.config)
                {
                    global_dispatch_configs.push(dispatch);
                }
            }
            if items_len == 0 {
                break;
            }
            offset += items_len;
            if offset >= page.total {
                break;
            }
        }
    }
    let global_override_rules: Vec<&crate::plugins::mesh_route_dispatch::RouteRule> =
        global_dispatch_configs
            .iter()
            .flat_map(|dispatch| dispatch.rules.iter())
            .filter(|rule| rule.redirect.is_none() && rule.destination.upstream_id.is_some())
            .collect();
    if global_override_rules.is_empty() {
        return Ok(Vec::new());
    }

    let mut errors = Vec::new();
    let mut offset = 0_i64;
    const PAGE_SIZE: i64 = 1_000;
    loop {
        let page = db
            .list_proxies_paginated(namespace, PAGE_SIZE, offset)
            .await
            .map_err(AfterValidateError::Db)?;
        let items_len = page.items.len() as i64;
        for proxy in &page.items {
            // Only proxies that ATTACH the plugin being unshadowed are affected.
            if !proxy
                .plugins
                .iter()
                .any(|assoc| assoc.plugin_config_id == plugin_config.id)
            {
                continue;
            }
            // If the proxy still attaches ANOTHER enabled `mesh_route_dispatch`
            // (one whose id differs from the plugin being disabled), the globals
            // remain shadowed and must not be evaluated.
            if proxy_shadows_global_mesh_route_dispatch_excluding(
                db,
                namespace,
                proxy,
                &plugin_config.id,
            )
            .await
            .map_err(AfterValidateError::Db)?
            {
                continue;
            }
            evaluate_mesh_route_dispatch_rules_for_proxy(
                db,
                namespace,
                proxy,
                &global_override_rules,
                mesh_model,
                &mut errors,
            )
            .await
            .map_err(AfterValidateError::Db)?;
        }
        if items_len == 0 {
            break;
        }
        offset += items_len;
        if offset >= page.total {
            break;
        }
    }
    Ok(errors)
}

/// Whether `proxy` attaches an enabled, namespace-local `mesh_route_dispatch`
/// instance whose id is NOT `excluded_id`. Used when a proxy/proxy_group
/// `mesh_route_dispatch` plugin is being disabled: the DB still shows that
/// instance as enabled, so it is excluded from the shadow computation while any
/// OTHER enabled local instance still shadows the globals.
async fn proxy_shadows_global_mesh_route_dispatch_excluding(
    db: &dyn DatabaseBackend,
    namespace: &str,
    proxy: &Proxy,
    excluded_id: &str,
) -> DbResult<bool> {
    for assoc in &proxy.plugins {
        if assoc.plugin_config_id == excluded_id {
            continue;
        }
        if let Some(plugin) = db
            .get_plugin_config(namespace, &assoc.plugin_config_id)
            .await?
            && plugin.enabled
            && plugin.plugin_name == "mesh_route_dispatch"
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Evaluate one proxy against a set of upstream-overriding `mesh_route_dispatch`
/// rules, pushing a retry/mesh-transport conflict message for each override that
/// would 502 at runtime. A rule conflicts when its EFFECTIVE retry (the rule's
/// `retry` / `retry_disabled`, else the proxy's base `retry`) stays effective for
/// the override upstream's mesh target after the proxy's per-port retry cap.
async fn evaluate_mesh_route_dispatch_rules_for_proxy(
    db: &dyn DatabaseBackend,
    namespace: &str,
    proxy: &Proxy,
    override_rules: &[&crate::plugins::mesh_route_dispatch::RouteRule],
    mesh_model: Option<&crate::modes::mesh::config::MeshConfig>,
    errors: &mut Vec<String>,
) -> DbResult<()> {
    for rule in override_rules {
        let Some(override_uid) = rule.destination.upstream_id.as_deref() else {
            continue;
        };
        // A rule pointing at the proxy's default upstream that leaves retry
        // untouched is covered by the proxy/upstream default-target checks. But a
        // same-upstream rule that adds or disables retry still has the runtime
        // overwrite `proxy.retry` via `route_override_retry` before dispatch, so
        // it must be evaluated here too.
        let rule_changes_retry = rule.retry.is_some() || rule.retry_disabled;
        if override_uid == proxy.upstream_id.as_deref().unwrap_or("") && !rule_changes_retry {
            continue;
        }
        let effective_retry = if rule.retry.is_some() {
            rule.retry.clone()
        } else if rule.retry_disabled {
            None
        } else {
            proxy.retry.clone()
        };
        // Cheap pre-filter before the upstream fetch.
        if !proxy_retry_is_effective(effective_retry.as_ref(), proxy.allowed_methods.as_deref()) {
            continue;
        }
        // Runtime preserves `proxy.upstream_subset` only for a same-upstream rule;
        // a different-upstream override drops it.
        let selected_subset = if override_uid == proxy.upstream_id.as_deref().unwrap_or("") {
            proxy.upstream_subset.as_deref()
        } else {
            None
        };
        match db.get_upstream(namespace, override_uid).await {
            Ok(Some(upstream)) => {
                // Runtime recomputes the per-port retry cap from the OVERRIDE
                // destination upstream, so derive the temporary proxy's port caps
                // from it before checking effectiveness.
                if let Some(conflict) = first_effective_mesh_transport_conflict_with_mesh(
                    &proxy_with_resolved_port_caps(proxy, &upstream),
                    &upstream,
                    selected_subset,
                    effective_retry.as_ref(),
                    proxy.allowed_methods.as_deref(),
                    mesh_model,
                ) {
                    errors.push(mesh_transport_retry_conflict_message(
                        &proxy.id,
                        override_uid,
                        &conflict,
                    ));
                }
            }
            // Missing / cross-namespace destinations are reported by the
            // existence validator; skip them here.
            Ok(_) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// A `mesh_route_dispatch` upstream override destination paired with the
/// effective retry policy the runtime applies when that rule matches.
struct MeshRouteOverrideDest {
    upstream_id: String,
    effective_retry: Option<RetryConfig>,
    /// Subset the runtime selects: `proxy.upstream_subset` for a same-upstream
    /// rule (preserved by `apply_route_overrides_inner`), else `None`.
    selected_subset: Option<String>,
}

/// List the enabled, namespace-local `mesh_route_dispatch` plugin configs whose
/// rules apply to `proxy`: its proxy-scoped/proxy_group associations plus every
/// **global** instance (the plugin cache merges globals into every proxy chain).
/// Used by the admin-side retry/mesh-transport conflict checks.
///
/// When the proxy attaches its own enabled `mesh_route_dispatch` instance,
/// `PluginCache::build_cache` shadows the globals of the same name, so they never
/// run for this proxy and are excluded here — otherwise a conflict in a shadowed
/// global would produce a spurious admission rejection.
async fn applicable_mesh_route_dispatch_plugins(
    db: &dyn DatabaseBackend,
    namespace: &str,
    proxy: &Proxy,
) -> DbResult<Vec<PluginConfig>> {
    let mut plugins: Vec<PluginConfig> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut shadows_global_dispatch = false;
    for assoc in &proxy.plugins {
        if let Some(plugin) = db
            .get_plugin_config(namespace, &assoc.plugin_config_id)
            .await?
            && plugin.enabled
            && plugin.plugin_name == "mesh_route_dispatch"
            && seen.insert(plugin.id.clone())
        {
            shadows_global_dispatch = true;
            plugins.push(plugin);
        }
    }
    // Global mesh_route_dispatch instances run on every proxy that does not
    // shadow them with a local instance of the same name.
    if !shadows_global_dispatch {
        let mut offset = 0_i64;
        const PAGE_SIZE: i64 = 1_000;
        loop {
            let page = db
                .list_plugin_configs_paginated(namespace, PAGE_SIZE, offset)
                .await?;
            let items_len = page.items.len() as i64;
            for plugin in page.items {
                if plugin.scope == PluginScope::Global
                    && plugin.namespace == namespace
                    && plugin.enabled
                    && plugin.plugin_name == "mesh_route_dispatch"
                    && seen.insert(plugin.id.clone())
                {
                    plugins.push(plugin);
                }
            }
            if items_len == 0 {
                break;
            }
            offset += items_len;
            if offset >= page.total {
                break;
            }
        }
    }
    Ok(plugins)
}

/// Whether `proxy` attaches its own enabled, namespace-local `mesh_route_dispatch`
/// instance via `proxy.plugins`. Such a local instance shadows every global
/// `mesh_route_dispatch` of the same name in `PluginCache::build_cache`, so the
/// globals never run for this proxy.
async fn proxy_shadows_global_mesh_route_dispatch(
    db: &dyn DatabaseBackend,
    namespace: &str,
    proxy: &Proxy,
) -> DbResult<bool> {
    for assoc in &proxy.plugins {
        if let Some(plugin) = db
            .get_plugin_config(namespace, &assoc.plugin_config_id)
            .await?
            && plugin.enabled
            && plugin.plugin_name == "mesh_route_dispatch"
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Collect the upstream overrides a proxy's enabled `mesh_route_dispatch` plugin
/// instances can route matched traffic to (via `route_override_upstream_id`),
/// each paired with the rule's effective retry policy. Considers proxy-scoped and
/// non-shadowed global instances, and includes same-default-upstream rules that
/// change retry. Used by the admin-side retry/mesh-transport conflict checks for
/// single-resource writes.
async fn mesh_route_dispatch_override_destinations(
    db: &dyn DatabaseBackend,
    namespace: &str,
    proxy: &Proxy,
) -> DbResult<Vec<MeshRouteOverrideDest>> {
    let default_uid = proxy.upstream_id.as_deref().unwrap_or("");
    let mut overrides: Vec<MeshRouteOverrideDest> = Vec::new();
    for plugin in applicable_mesh_route_dispatch_plugins(db, namespace, proxy).await? {
        let Ok(dispatch) = MeshRouteDispatchConfig::from_value(&plugin.config) else {
            continue;
        };
        for rule in &dispatch.rules {
            // A redirect rule answers the request itself before any upstream
            // override is applied, so it never dispatches to its destination
            // upstream; skip it to avoid a spurious conflict.
            if rule.redirect.is_some() {
                continue;
            }
            let Some(override_uid) = rule.destination.upstream_id.as_deref() else {
                continue;
            };
            // A rule pointing at the proxy's own default upstream is already
            // covered by the default-upstream conflict check when it inherits the
            // base retry. When it changes retry (adds its own or disables it),
            // runtime overwrites `proxy.retry` via `route_override_retry` before
            // dispatch, so it must still be evaluated here.
            let rule_changes_retry = rule.retry.is_some() || rule.retry_disabled;
            if override_uid == default_uid && !rule_changes_retry {
                continue;
            }
            let effective_retry = if rule.retry.is_some() {
                rule.retry.clone()
            } else if rule.retry_disabled {
                None
            } else {
                proxy.retry.clone()
            };
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
    }
    Ok(overrides)
}

fn plugin_config_audit_body(resource: &PluginConfig) -> Value {
    let mut body = json!(resource);
    if let Some(config) = body.get_mut("config") {
        redact_sensitive_plugin_config_fields(config);
    }
    body
}

fn upstream_audit_body(resource: &Upstream) -> Value {
    let mut body = json!(resource);
    if let Some(token) = body
        .get_mut("service_discovery")
        .and_then(|sd| sd.get_mut("consul"))
        .and_then(|consul| consul.get_mut("token"))
        && !token.is_null()
    {
        *token = json!(crate::plugins::utils::metadata_redaction::REDACTED_PLACEHOLDER);
    }
    body
}

fn redact_sensitive_plugin_config_fields(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if is_sensitive_plugin_config_key(key) {
                    *child = json!(crate::plugins::utils::metadata_redaction::REDACTED_PLACEHOLDER);
                } else {
                    redact_sensitive_plugin_config_fields(child);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_sensitive_plugin_config_fields(item);
            }
        }
        _ => {}
    }
}

fn is_sensitive_plugin_config_key(key: &str) -> bool {
    if crate::plugins::utils::metadata_redaction::is_sensitive_metadata_key(key) {
        return true;
    }

    let normalized = key.to_ascii_lowercase().replace(['-', '.'], "_");
    normalized == "key"
        || normalized.contains("api_key")
        || normalized.contains("apikey")
        || normalized.contains("access_key")
        || normalized.contains("client_secret")
        || normalized.contains("credential")
        || normalized.contains("private_key")
        || normalized.contains("webhook")
}

pub(crate) async fn check_port_available(
    port: u16,
    bind_address: &str,
    udp: bool,
) -> Result<(), String> {
    super::check_port_available(port, bind_address, udp).await
}

pub(crate) async fn check_consumer_credential_uniqueness(
    db: &dyn DatabaseBackend,
    namespace: &str,
    consumer: &Consumer,
    exclude_consumer_id: Option<&str>,
) -> DbResult<Option<String>> {
    for cred_type in ["keyauth", "mtls_auth"] {
        if let Some(cred_value) = consumer.credentials.get(cred_type)
            && let Some(message) = check_credential_value_uniqueness(
                db,
                namespace,
                cred_type,
                cred_value,
                exclude_consumer_id,
            )
            .await?
        {
            return Ok(Some(message));
        }
    }

    Ok(None)
}

pub(crate) async fn check_credential_value_uniqueness(
    db: &dyn DatabaseBackend,
    namespace: &str,
    cred_type: &str,
    cred_value: &Value,
    exclude_consumer_id: Option<&str>,
) -> DbResult<Option<String>> {
    let entries = Consumer::credential_entries_from_value(cred_value);

    match cred_type {
        "keyauth" => {
            for entry in entries {
                if let Some(key) = entry.get("key").and_then(|value| value.as_str()) {
                    match db
                        .check_keyauth_key_unique(namespace, key, exclude_consumer_id)
                        .await
                    {
                        Ok(true) => {}
                        Ok(false) => {
                            return Ok(Some(
                                "A consumer with this API key already exists".to_string(),
                            ));
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        "mtls_auth" => {
            for entry in entries {
                if let Some(identity) = entry.get("identity").and_then(|value| value.as_str()) {
                    match db
                        .check_mtls_identity_unique(namespace, identity, exclude_consumer_id)
                        .await
                    {
                        Ok(true) => {}
                        Ok(false) => {
                            return Ok(Some(
                                "A consumer with this mTLS identity already exists".to_string(),
                            ));
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        _ => {}
    }

    Ok(None)
}

// Strip api_spec_id from client-submitted resources.  This field is
// admin-only ownership metadata set exclusively by the spec import
// handlers.  Allowing clients to set it via regular CRUD endpoints
// would let them claim spec ownership of hand-managed resources,
// causing unintended deletion during spec lifecycle operations.
// SQL INSERT/UPDATE statements already exclude the column, but Mongo's
// replace_one serializes the full struct.

impl AdminResource for Upstream {
    const RESOURCE_NAME: &'static str = "upstream";
    const RESOURCE_LABEL: &'static str = "Upstream";
    const VALIDATION_ERROR_LABEL: &'static str = "upstream fields";
    const NOT_FOUND_MESSAGE: &'static str = "Upstream not found";

    fn id(&self) -> &str {
        &self.id
    }

    fn set_id(&mut self, id: String) {
        self.id = id;
    }

    fn namespace(&self) -> &str {
        &self.namespace
    }

    fn set_namespace(&mut self, ns: String) {
        self.namespace = ns;
    }

    fn set_created_at(&mut self, now: DateTime<Utc>) {
        self.created_at = now;
    }

    fn set_updated_at(&mut self, now: DateTime<Utc>) {
        self.updated_at = now;
    }

    fn normalize(&mut self) {
        self.api_spec_id = None;
        self.normalize_fields();
    }

    fn audit_body(resource: &Self) -> Value {
        upstream_audit_body(resource)
    }

    fn response_body_for_role(resource: &Self, role: AdminRole) -> Value {
        if role == AdminRole::Admin {
            Self::response_body(resource)
        } else {
            upstream_audit_body(resource)
        }
    }

    fn validate(&self, ctx: &ValidationCtx<'_>) -> Result<(), ValidationError> {
        if self.targets.is_empty() && self.service_discovery.is_none() {
            return Err(ValidationError::Message(
                "At least one target is required (or configure service_discovery)".to_string(),
            ));
        }
        // Reject mesh-projected fields on the admin write path. This is an
        // operator-provided admission entry point, so the projected-field rejection
        // is correct here (it is intentionally NOT in `validate_fields`, which also
        // runs on the mesh slice-apply path and would false-error there).
        self.validate_operator_provided_fields()
            .map_err(ValidationError::Fields)?;
        self.validate_fields().map_err(ValidationError::Fields)?;
        // Screen literal-IP targets against the backend egress policy so an
        // admin write cannot point an upstream at a denied (e.g. cloud-metadata)
        // address that file/restore loads would reject.
        self.validate_backend_egress_ips(ctx.backend_allow_ips)
            .map_err(ValidationError::Fields)
    }

    fn cached_items(config: &GatewayConfig) -> &[Self] {
        &config.upstreams
    }

    fn map_delete_db_error(error: &anyhow::Error) -> Response<Full<Bytes>> {
        if is_mtls_dns_admission_unavailable(error) {
            return super::mtls_dns_admission_unavailable_response();
        }
        let error_text = error.to_string();
        if error_text.contains("referenced by one or more proxies")
            || error_text.contains("referenced by mesh_route_dispatch plugin_config")
        {
            return super::json_response(
                StatusCode::CONFLICT,
                &json!({"error": format!("{}", error)}),
            );
        }
        super::json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &super::db_error_response(error),
        )
    }

    async fn db_get(db: &dyn DatabaseBackend, namespace: &str, id: &str) -> DbResult<Option<Self>> {
        db.get_upstream(namespace, id).await
    }

    async fn db_list(
        db: &dyn DatabaseBackend,
        namespace: &str,
        pagination: &super::PaginationParams,
    ) -> DbResult<PaginatedResult<Self>> {
        db.list_upstreams_paginated(
            namespace,
            pagination.query_limit_i64(),
            pagination.offset as i64,
        )
        .await
    }

    async fn db_create(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<()> {
        db.create_upstream(resource).await
    }

    async fn db_update(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<bool> {
        db.update_upstream(resource).await
    }

    async fn db_delete(db: &dyn DatabaseBackend, namespace: &str, id: &str) -> DbResult<bool> {
        db.delete_upstream(namespace, id).await
    }

    async fn check_uniqueness(
        db: &dyn DatabaseBackend,
        namespace: &str,
        resource: &Self,
        exclude_id: Option<&str>,
    ) -> DbResult<Option<String>> {
        if let Some(name) = resource.name.as_deref() {
            match db
                .check_upstream_name_unique(namespace, name, exclude_id)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return Ok(Some(format!("Upstream name '{}' already exists", name)));
                }
                Err(error) => return Err(error),
            }
        }

        Ok(None)
    }

    async fn after_validate(
        db: &dyn DatabaseBackend,
        state: &AdminState,
        namespace: &str,
        resource: &Self,
        _existing: Option<&Self>,
        _ctx: &ValidationCtx<'_>,
    ) -> Result<(), AfterValidateError> {
        let cached_config = state.cached_gateway_config();
        let mesh_model = cached_config
            .as_ref()
            .and_then(|config| config.mesh.as_deref());
        let subset_names: HashSet<&str> = resource
            .subsets
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|subset| subset.name.as_str())
            .collect();
        let mut errors = Vec::new();
        let mut offset = 0_i64;
        const PAGE_SIZE: i64 = 1_000;

        loop {
            let page = db
                .list_proxies_paginated(namespace, PAGE_SIZE, offset)
                .await
                .map_err(AfterValidateError::Db)?;
            let items_len = page.items.len() as i64;

            for proxy in page.items {
                if proxy.upstream_id.as_deref() == Some(resource.id.as_str()) {
                    if let Some(subset_name) = proxy.upstream_subset.as_deref()
                        && !subset_names.contains(subset_name)
                    {
                        errors.push(format!(
                            "upstream '{}' cannot remove subset '{}' while proxy '{}' references it",
                            resource.id, subset_name, proxy.id
                        ));
                    }
                    // Reject adding a mesh transport requirement to an upstream
                    // that a retry-enabled proxy already targets: at runtime
                    // retry forces the HBONE / SVID-mTLS transport off and those
                    // requests fail closed with 502 (issue #1669). Mirrors the
                    // full-config and proxy-write checks for the reverse write
                    // order. The proxy loaded from the DB has no resolved
                    // `dispatch_port_overrides`, so derive its per-port retry caps
                    // from the edited upstream definition (`resource`).
                    if let Some(conflict) = first_effective_mesh_transport_conflict_with_mesh(
                        &proxy_with_resolved_port_caps(&proxy, resource),
                        resource,
                        proxy.upstream_subset.as_deref(),
                        proxy.retry.as_ref(),
                        proxy.allowed_methods.as_deref(),
                        mesh_model,
                    ) {
                        errors.push(mesh_transport_retry_conflict_message(
                            &proxy.id,
                            &resource.id,
                            &conflict,
                        ));
                    }
                }

                // A retry-enabled proxy can also reach this upstream through an
                // enabled `mesh_route_dispatch` rule (proxy-scoped or global)
                // even when its DEFAULT upstream is different. Adding a mesh
                // transport tag to the upstream would 502 those matched requests
                // too, so check route-dispatch users for the reverse write order.
                for override_dest in
                    mesh_route_dispatch_override_destinations(db, namespace, &proxy)
                        .await
                        .map_err(AfterValidateError::Db)?
                {
                    if override_dest.upstream_id != resource.id {
                        continue;
                    }
                    if let Some(conflict) = first_effective_mesh_transport_conflict_with_mesh(
                        &proxy_with_resolved_port_caps(&proxy, resource),
                        resource,
                        override_dest.selected_subset.as_deref(),
                        override_dest.effective_retry.as_ref(),
                        proxy.allowed_methods.as_deref(),
                        mesh_model,
                    ) {
                        errors.push(mesh_transport_retry_conflict_message(
                            &proxy.id,
                            &resource.id,
                            &conflict,
                        ));
                    }
                }
            }

            if items_len == 0 {
                break;
            }
            offset += items_len;
            if offset >= page.total {
                break;
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(AfterValidateError::BadRequest(errors))
        }
    }
}

impl AdminResource for PluginConfig {
    const RESOURCE_NAME: &'static str = "plugin config";
    const RESOURCE_LABEL: &'static str = "Plugin config";
    const VALIDATION_ERROR_LABEL: &'static str = "plugin config fields";
    const NOT_FOUND_MESSAGE: &'static str = "Plugin config not found";
    const SERIALIZE_MTLS_ADMISSION: bool = true;
    const ID_CONFLICT_LABEL: &'static str = "PluginConfig";

    fn id(&self) -> &str {
        &self.id
    }

    fn set_id(&mut self, id: String) {
        self.id = id;
    }

    fn namespace(&self) -> &str {
        &self.namespace
    }

    fn set_namespace(&mut self, ns: String) {
        self.namespace = ns;
    }

    fn set_created_at(&mut self, now: DateTime<Utc>) {
        self.created_at = now;
    }

    fn set_updated_at(&mut self, now: DateTime<Utc>) {
        self.updated_at = now;
    }

    fn normalize(&mut self) {
        self.api_spec_id = None;
        self.normalize_fields();
    }

    fn validate(&self, ctx: &ValidationCtx<'_>) -> Result<(), ValidationError> {
        self.validate_fields().map_err(ValidationError::Fields)?;
        // A mesh_route_dispatch rule can override a matched request's backend to
        // an arbitrary literal IP; screen those against the egress policy here so
        // a direct/batch plugin write can't smuggle in a denied (e.g.
        // cloud-metadata) destination the whole-config loaders reject.
        if self.plugin_name == "mesh_route_dispatch" {
            crate::plugins::screen_mesh_route_dispatch_egress(&self.config, ctx.backend_allow_ips)
                .map_err(ValidationError::Fields)?;
        }
        // Redis-backed plugins (rate_limiting / request_deduplication /
        // ai_semantic_cache) build their client from `redis_url` without the
        // egress policy; screen a denied literal endpoint on direct/batch admin
        // writes too, matching the policy-aware whole-config / API-spec paths.
        crate::plugins::screen_redis_endpoint_egress(&self.config, ctx.backend_allow_ips)
            .map_err(|e| ValidationError::Fields(vec![e]))?;
        // ldap_auth (ldap_url) / kafka_logging (broker_list) dial their own
        // resolver outside the shared client + DnsCache; screen their literal
        // endpoints on direct/batch admin writes too.
        crate::plugins::screen_direct_client_endpoint_egress(
            &self.plugin_name,
            &self.config,
            ctx.backend_allow_ips,
        )
        .map_err(|e| ValidationError::Fields(vec![e]))?;
        Ok(())
    }

    fn cached_items(config: &GatewayConfig) -> &[Self] {
        &config.plugin_configs
    }

    fn audit_body(resource: &Self) -> Value {
        plugin_config_audit_body(resource)
    }

    fn response_body_for_role(resource: &Self, role: AdminRole) -> Value {
        if role == AdminRole::Admin {
            Self::response_body(resource)
        } else {
            plugin_config_audit_body(resource)
        }
    }

    fn map_after_validate_errors(errors: &[String]) -> Response<Full<Bytes>> {
        super::json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": errors.join("; ")}),
        )
    }

    async fn db_get(db: &dyn DatabaseBackend, namespace: &str, id: &str) -> DbResult<Option<Self>> {
        db.get_plugin_config(namespace, id).await
    }

    async fn db_list(
        db: &dyn DatabaseBackend,
        namespace: &str,
        pagination: &super::PaginationParams,
    ) -> DbResult<PaginatedResult<Self>> {
        db.list_plugin_configs_paginated(
            namespace,
            pagination.query_limit_i64(),
            pagination.offset as i64,
        )
        .await
    }

    async fn db_create(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<()> {
        db.create_plugin_config(resource).await
    }

    async fn db_update(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<bool> {
        db.update_plugin_config(resource).await
    }

    async fn db_delete(db: &dyn DatabaseBackend, namespace: &str, id: &str) -> DbResult<bool> {
        db.delete_plugin_config(namespace, id).await
    }

    async fn check_uniqueness(
        db: &dyn DatabaseBackend,
        namespace: &str,
        resource: &Self,
        exclude_id: Option<&str>,
    ) -> DbResult<Option<String>> {
        if resource.enabled
            && resource.plugin_name == "prometheus_metrics"
            && enabled_prometheus_metrics_owner_exists(db, namespace, exclude_id).await?
        {
            return Ok(Some(
                "prometheus_metrics permits at most one enabled global instance; another config already owns the process registry"
                    .to_string(),
            ));
        }
        Ok(None)
    }

    async fn after_validate(
        db: &dyn DatabaseBackend,
        state: &AdminState,
        namespace: &str,
        resource: &Self,
        existing: Option<&Self>,
        _ctx: &ValidationCtx<'_>,
    ) -> Result<(), AfterValidateError> {
        let known_plugins = crate::plugins::available_plugins();
        if !known_plugins.contains(&resource.plugin_name.as_str()) {
            return Err(AfterValidateError::BadRequest(vec![format!(
                "Unknown plugin name '{}'. Available plugins: {:?}",
                resource.plugin_name, known_plugins
            )]));
        }

        if let Some(proxy_id) = resource.proxy_id.as_deref() {
            match db.check_proxy_exists(proxy_id, namespace).await {
                Ok(true) => {}
                Ok(false) => {
                    // Proxy reads are namespace-predicated (issue #2122
                    // DB-M1): a proxy in another namespace reports as
                    // missing, so cross-namespace references are rejected
                    // without disclosing other tenants' resources.
                    return Err(AfterValidateError::BadRequest(vec![format!(
                        "proxy_id '{}' does not exist in namespace '{}'",
                        proxy_id, namespace
                    )]));
                }
                Err(error) => return Err(AfterValidateError::Db(error)),
            }
        }

        if let Err(error) = validate_plugin_config_definition(state, resource) {
            return Err(AfterValidateError::BadRequest(vec![format!(
                "Invalid plugin config: {}",
                error
            )]));
        }

        validate_openapi_validator_precondition(db, namespace, resource).await?;

        let upstream_errors =
            validate_mesh_route_dispatch_plugin_upstream_references(db, namespace, resource, None)
                .await
                .map_err(AfterValidateError::Db)?;
        if !upstream_errors.is_empty() {
            return Err(AfterValidateError::BadRequest(upstream_errors));
        }

        // Writing/updating a mesh_route_dispatch plugin can introduce the
        // retry/mesh-transport conflict after the retry-enabled proxy already
        // exists (e.g. repointing a rule at a mesh.hbone upstream). The reference
        // validator above only checks existence, so run the retry conflict check
        // for the proxies this plugin applies to.
        let cached_config = state.cached_gateway_config();
        let mesh_model = cached_config
            .as_ref()
            .and_then(|config| config.mesh.as_deref());
        let retry_errors = validate_mesh_route_dispatch_plugin_retry_conflicts(
            db, namespace, resource, mesh_model,
        )
        .await?;
        if !retry_errors.is_empty() {
            return Err(AfterValidateError::BadRequest(retry_errors));
        }

        if resource.plugin_name == "mtls_auth"
            || existing.is_some_and(|plugin| plugin.plugin_name == "mtls_auth")
        {
            validate_mtls_auth_candidate(db, namespace, None, Some(resource), None).await?;
        }
        validate_hmac_request_transform_candidates(
            db,
            state,
            namespace,
            &[],
            std::slice::from_ref(resource),
            None,
        )
        .await?;

        Ok(())
    }

    async fn before_delete(
        db: &dyn DatabaseBackend,
        state: &AdminState,
        namespace: &str,
        existing: &Self,
        _ctx: &ValidationCtx<'_>,
    ) -> Result<(), AfterValidateError> {
        if existing.plugin_name == "mtls_auth" {
            validate_mtls_auth_candidate(db, namespace, None, None, Some(&existing.id)).await?;
        }
        validate_hmac_request_transform_candidates(
            db,
            state,
            namespace,
            &[],
            &[],
            Some(&existing.id),
        )
        .await?;
        Ok(())
    }
}

/// Check for an enabled Prometheus registry owner already persisted anywhere.
///
/// Direct CRUD and batch admission both call this before writing so neither can
/// persist a snapshot that the runtime ownership validator will reject on the
/// next poll. `exclude_id` makes an in-place PUT of the current namespace owner
/// valid without exempting an identically named resource in another namespace.
pub(crate) async fn enabled_prometheus_metrics_owner_exists(
    db: &dyn DatabaseBackend,
    namespace: &str,
    exclude_id: Option<&str>,
) -> DbResult<bool> {
    enabled_prometheus_metrics_owner_exists_inner(db, namespace, exclude_id, false).await
}

/// Restore replaces one namespace wholesale, so owners in that namespace do
/// not conflict with the incoming payload; owners in every other namespace do.
pub(crate) async fn enabled_prometheus_metrics_owner_exists_outside_namespace(
    db: &dyn DatabaseBackend,
    namespace: &str,
) -> DbResult<bool> {
    enabled_prometheus_metrics_owner_exists_inner(db, namespace, None, true).await
}

async fn enabled_prometheus_metrics_owner_exists_inner(
    db: &dyn DatabaseBackend,
    namespace: &str,
    exclude_id: Option<&str>,
    exclude_current_namespace: bool,
) -> DbResult<bool> {
    const PAGE_SIZE: i64 = 1_000;
    let mut namespaces = db.list_namespaces_authoritative().await?;
    namespaces.push(namespace.to_string());
    namespaces.sort_unstable();
    namespaces.dedup();

    for candidate_namespace in namespaces {
        if exclude_current_namespace && candidate_namespace == namespace {
            continue;
        }
        let mut offset = 0_i64;
        loop {
            let page = db
                .list_plugin_configs_paginated(&candidate_namespace, PAGE_SIZE, offset)
                .await?;
            let items_len = page.items.len() as i64;
            if page.items.into_iter().any(|plugin| {
                plugin.enabled
                    && plugin.plugin_name == "prometheus_metrics"
                    && !(candidate_namespace == namespace && exclude_id == Some(plugin.id.as_str()))
            }) {
                return Ok(true);
            }
            if items_len == 0 {
                break;
            }
            offset += items_len;
            if offset >= page.total {
                break;
            }
        }
    }

    Ok(false)
}

impl AdminResource for Proxy {
    const RESOURCE_NAME: &'static str = "proxy";
    const RESOURCE_LABEL: &'static str = "Proxy";
    const VALIDATION_ERROR_LABEL: &'static str = "proxy fields";
    const NOT_FOUND_MESSAGE: &'static str = "Proxy not found";
    const SERIALIZE_MTLS_ADMISSION: bool = true;

    fn id(&self) -> &str {
        &self.id
    }

    fn set_id(&mut self, id: String) {
        self.id = id;
    }

    fn namespace(&self) -> &str {
        &self.namespace
    }

    fn set_namespace(&mut self, ns: String) {
        self.namespace = ns;
    }

    fn set_created_at(&mut self, now: DateTime<Utc>) {
        self.created_at = now;
    }

    fn set_updated_at(&mut self, now: DateTime<Utc>) {
        self.updated_at = now;
    }

    fn normalize(&mut self) {
        self.api_spec_id = None;
        if let Some(methods) = self.allowed_methods.as_mut() {
            for method in methods {
                *method = method.to_uppercase();
            }
        }
        self.normalize_fields();
    }

    fn validate(&self, ctx: &ValidationCtx<'_>) -> Result<(), ValidationError> {
        self.validate_fields().map_err(ValidationError::Fields)?;
        // Screen literal-IP backend_host / dns_override against the egress
        // policy so an admin write cannot target a denied (e.g. cloud-metadata)
        // address that file/restore loads would reject.
        self.validate_backend_egress_ips(ctx.backend_allow_ips)
            .map_err(ValidationError::Fields)?;

        for host in &self.hosts {
            if let Err(message) = crate::config::types::validate_host_entry(host) {
                return Err(ValidationError::Message(format!(
                    "Invalid proxy hosts: {}",
                    message
                )));
            }
        }

        if !self.dispatch_kind.is_stream()
            && let Some(path) = self.listen_path.as_deref()
            && let Some(pattern) = path.strip_prefix('~')
            && !pattern.is_empty()
        {
            let anchored = crate::config::types::anchor_regex_pattern(pattern);
            if let Err(error) = regex::Regex::new(&anchored) {
                return Err(ValidationError::Message(format!(
                    "Invalid proxy listen_path: invalid regex '{}': {}",
                    path, error
                )));
            }
        }

        if self.dispatch_kind.is_stream() {
            match self.listen_port {
                None => {
                    return Err(ValidationError::Message(format!(
                        "Stream proxy (scheme {}) must have a listen_port",
                        self.scheme_display()
                    )));
                }
                Some(0) => {
                    return Err(ValidationError::Message(
                        "listen_port 0 must be >= 1".to_string(),
                    ));
                }
                Some(_) => {}
            }
        } else if self.listen_port.is_some() {
            return Err(ValidationError::Message(format!(
                "HTTP proxy (scheme {}) must not set listen_port",
                self.scheme_display()
            )));
        }

        Ok(())
    }

    fn cached_items(config: &GatewayConfig) -> &[Self] {
        &config.proxies
    }

    fn map_after_validate_errors(errors: &[String]) -> Response<Full<Bytes>> {
        super::json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": errors.join("; ")}),
        )
    }

    async fn db_get(db: &dyn DatabaseBackend, namespace: &str, id: &str) -> DbResult<Option<Self>> {
        db.get_proxy(namespace, id).await
    }

    fn allow_cached_read_fallback(error: &anyhow::Error) -> bool {
        !is_proxy_plugin_association_load_error(error)
    }

    async fn db_get_for_write(
        db: &dyn DatabaseBackend,
        namespace: &str,
        id: &str,
    ) -> DbResult<Option<Self>> {
        db.get_proxy_for_write(namespace, id).await
    }

    async fn db_list(
        db: &dyn DatabaseBackend,
        namespace: &str,
        pagination: &super::PaginationParams,
    ) -> DbResult<PaginatedResult<Self>> {
        db.list_proxies_paginated(
            namespace,
            pagination.query_limit_i64(),
            pagination.offset as i64,
        )
        .await
    }

    async fn db_create(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<()> {
        db.create_proxy(resource).await
    }

    async fn db_update(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<bool> {
        db.update_proxy(resource).await
    }

    async fn db_delete(db: &dyn DatabaseBackend, namespace: &str, id: &str) -> DbResult<bool> {
        db.delete_proxy(namespace, id).await
    }

    async fn check_uniqueness(
        db: &dyn DatabaseBackend,
        namespace: &str,
        resource: &Self,
        exclude_id: Option<&str>,
    ) -> DbResult<Option<String>> {
        if !resource.dispatch_kind.is_stream() {
            match db
                .check_listen_path_unique(
                    namespace,
                    resource.listen_path.as_deref(),
                    &resource.hosts,
                    exclude_id,
                )
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return Ok(Some(PROXY_ROUTE_CONFLICT_ERROR.to_string()));
                }
                Err(error) => return Err(error),
            }
        }

        if let Some(name) = resource.name.as_deref() {
            match db
                .check_proxy_name_unique(namespace, name, exclude_id)
                .await
            {
                Ok(true) => {}
                Ok(false) => return Ok(Some(format!("Proxy name '{}' already exists", name))),
                Err(error) => return Err(error),
            }
        }

        if resource.dispatch_kind.is_stream()
            && let Some(port) = resource.listen_port
        {
            match db
                .check_listen_port_unique(namespace, port, exclude_id)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return Ok(Some(format!(
                        "listen_port {} is already in use by another proxy",
                        port
                    )));
                }
                Err(error) => return Err(error),
            }
        }

        Ok(None)
    }

    fn map_persist_db_error(
        error: &anyhow::Error,
        _action: WriteAction<'_>,
    ) -> Response<Full<Bytes>> {
        if is_mtls_dns_admission_unavailable(error) {
            return super::mtls_dns_admission_unavailable_response();
        }
        let message = error.to_string();
        if message.contains(PROXY_ROUTE_CONFLICT_ERROR) {
            return super::json_response(
                StatusCode::CONFLICT,
                &json!({"error": PROXY_ROUTE_CONFLICT_ERROR}),
            );
        }
        if is_mtls_dns_identity_conflict(error) || super::is_unique_constraint_violation(&message) {
            return super::json_response(StatusCode::CONFLICT, &json!({ "error": message }));
        }

        super::json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &super::db_error_response(error),
        )
    }

    async fn after_validate(
        db: &dyn DatabaseBackend,
        state: &AdminState,
        namespace: &str,
        resource: &Self,
        existing: Option<&Self>,
        ctx: &ValidationCtx<'_>,
    ) -> Result<(), AfterValidateError> {
        let cached_config = state.cached_gateway_config();
        let mesh_model = cached_config
            .as_ref()
            .and_then(|config| config.mesh.as_deref());
        if let Some(upstream_id) = resource.upstream_id.as_deref() {
            // Namespace-predicated lookup: an upstream in another namespace
            // reports as missing (cross-namespace references are equally
            // forbidden either way).
            match db.get_upstream(namespace, upstream_id).await {
                Ok(Some(upstream)) => {
                    if let Some(owner_spec_id) = upstream.api_spec_id.as_deref() {
                        let same_spec_proxy = existing
                            .and_then(|proxy| proxy.api_spec_id.as_deref())
                            == Some(owner_spec_id);
                        if !same_spec_proxy {
                            return Err(AfterValidateError::BadRequest(vec![format!(
                                "upstream_id '{}' is owned by api_spec '{}' and cannot be attached to proxy '{}'; create a hand-managed upstream or update the owning API spec",
                                upstream_id, owner_spec_id, resource.id
                            )]));
                        }
                    }
                    if let Some(subset_name) = resource.upstream_subset.as_deref() {
                        let subset_exists = upstream
                            .subsets
                            .as_ref()
                            .is_some_and(|subsets| subsets.iter().any(|s| s.name == subset_name));
                        if !subset_exists {
                            return Err(AfterValidateError::BadRequest(vec![format!(
                                "upstream_subset '{}' is not defined on upstream_id '{}'",
                                subset_name, upstream_id
                            )]));
                        }
                    }
                    // A retry-enabled proxy whose selected upstream targets
                    // require a mesh transport (`mesh.hbone` / `mesh.mtls`)
                    // would fail closed with 502 at runtime (issue #1669).
                    // Reject the combination at admission, matching the
                    // full-config `validate_upstream_references` check. A per-port
                    // `maxRetries = 0` cap on the mesh port disarms retry there,
                    // so `retry_is_effective_for_mesh_target` allows that config —
                    // but the per-resource `resource` arrives without its
                    // `#[serde(skip)]` `dispatch_port_overrides` resolved, so derive
                    // them from the referenced upstream first (the full-config path
                    // gets them via `resolve_dispatch_port_overrides`).
                    if let Some(conflict) = first_effective_mesh_transport_conflict_with_mesh(
                        &proxy_with_resolved_port_caps(resource, &upstream),
                        &upstream,
                        resource.upstream_subset.as_deref(),
                        resource.retry.as_ref(),
                        resource.allowed_methods.as_deref(),
                        mesh_model,
                    ) {
                        return Err(AfterValidateError::BadRequest(vec![
                            mesh_transport_retry_conflict_message(
                                &resource.id,
                                upstream_id,
                                &conflict,
                            ),
                        ]));
                    }
                }
                Ok(None) => {
                    return Err(AfterValidateError::BadRequest(vec![format!(
                        "upstream_id '{}' does not exist in namespace '{}'",
                        upstream_id, namespace
                    )]));
                }
                Err(error) => return Err(AfterValidateError::Db(error)),
            }
        }

        // Route-level upstream overrides (`mesh_route_dispatch`, proxy-scoped or
        // global) can route matched traffic to a different upstream than
        // `proxy.upstream_id`. Reject when the override destination requires a
        // mesh transport AND the rule's EFFECTIVE retry (after per-port caps)
        // stays on, mirroring the full-config check.
        for override_dest in mesh_route_dispatch_override_destinations(db, namespace, resource)
            .await
            .map_err(AfterValidateError::Db)?
        {
            match db.get_upstream(namespace, &override_dest.upstream_id).await {
                Ok(Some(upstream)) => {
                    if let Some(conflict) = first_effective_mesh_transport_conflict_with_mesh(
                        &proxy_with_resolved_port_caps(resource, &upstream),
                        &upstream,
                        override_dest.selected_subset.as_deref(),
                        override_dest.effective_retry.as_ref(),
                        resource.allowed_methods.as_deref(),
                        mesh_model,
                    ) {
                        return Err(AfterValidateError::BadRequest(vec![
                            mesh_transport_retry_conflict_message(
                                &resource.id,
                                &override_dest.upstream_id,
                                &conflict,
                            ),
                        ]));
                    }
                }
                // Missing / cross-namespace override upstreams are reported
                // by the dedicated mesh_route_dispatch reference validator;
                // skip them here.
                Ok(None) => {}
                Err(error) => return Err(AfterValidateError::Db(error)),
            }
        }

        match db
            .validate_proxy_plugin_associations(resource.id(), namespace, &resource.plugins)
            .await
        {
            Ok(errors) if !errors.is_empty() => {
                return Err(AfterValidateError::BadRequest(vec![format!(
                    "Invalid proxy plugin associations: {}",
                    errors.join("; ")
                )]));
            }
            Ok(_) => {}
            Err(error) => return Err(AfterValidateError::Db(error)),
        }

        // HTTP proxy associations can make a dormant/global `san_dns` policy
        // effective just as stream proxies can. The candidate helper checks
        // every transport but returns immediately when this proxy has no
        // effective `mtls_auth` association; compatibility validation itself
        // remains stream-specific.
        validate_mtls_auth_candidate(db, namespace, Some(resource), None, None).await?;
        validate_hmac_request_transform_candidates(
            db,
            state,
            namespace,
            std::slice::from_ref(resource),
            &[],
            None,
        )
        .await?;

        if resource.dispatch_kind.is_stream()
            && let Some(port) = resource.listen_port
            && ctx.mode != "cp"
        {
            if ctx.reserved_ports.contains(&port) {
                return Err(AfterValidateError::Response(Box::new(
                    super::json_response(
                        StatusCode::CONFLICT,
                        &json!({"error": format!(
                            "listen_port {} conflicts with a gateway reserved port (proxy/admin/gRPC listener)",
                            port
                        )}),
                    ),
                )));
            }

            let port_changed = existing.and_then(|proxy| proxy.listen_port) != Some(port);
            let transport_changed = existing
                .map(|proxy| proxy.dispatch_kind.is_udp() != resource.dispatch_kind.is_udp())
                .unwrap_or(false);
            let should_probe = existing.is_none() || port_changed || transport_changed;
            if should_probe
                && let Err(error) = check_port_available(
                    port,
                    ctx.stream_bind_address,
                    resource.dispatch_kind.is_udp(),
                )
                .await
            {
                return Err(AfterValidateError::Response(Box::new(
                    super::json_response(
                        StatusCode::CONFLICT,
                        &json!({"error": format!(
                            "listen_port {} is not available on the host: {}",
                            port, error
                        )}),
                    ),
                )));
            }
        }

        Ok(())
    }

    async fn after_write(
        db: &dyn DatabaseBackend,
        _state: &AdminState,
        _namespace: &str,
        resource: &Self,
        existing: Option<&Self>,
        action: WriteAction<'_>,
    ) -> DbResult<()> {
        if db.db_type() == "mongodb"
            && matches!(action, WriteAction::Update { .. })
            && let Some(old_proxy) = existing
            && let Some(old_upstream_id) = old_proxy.upstream_id.as_deref()
            && resource.upstream_id.as_deref() != Some(old_upstream_id)
        {
            // The previous upstream lives in the proxy's own namespace (the
            // write precheck loaded `existing` namespace-scoped).
            db.cleanup_orphaned_upstream(&old_proxy.namespace, old_upstream_id)
                .await?;
        }

        Ok(())
    }
}

impl AdminResource for Consumer {
    const RESOURCE_NAME: &'static str = "consumer";
    const RESOURCE_LABEL: &'static str = "Consumer";
    const VALIDATION_ERROR_LABEL: &'static str = "consumer fields";
    const NOT_FOUND_MESSAGE: &'static str = "Consumer not found";
    const SERIALIZE_MTLS_ADMISSION: bool = true;

    fn id(&self) -> &str {
        &self.id
    }

    fn set_id(&mut self, id: String) {
        self.id = id;
    }

    fn namespace(&self) -> &str {
        &self.namespace
    }

    fn set_namespace(&mut self, ns: String) {
        self.namespace = ns;
    }

    fn set_created_at(&mut self, now: DateTime<Utc>) {
        self.created_at = now;
    }

    fn set_updated_at(&mut self, now: DateTime<Utc>) {
        self.updated_at = now;
    }

    fn normalize(&mut self) {
        self.normalize_fields();
    }

    fn validate(&self, _ctx: &ValidationCtx<'_>) -> Result<(), ValidationError> {
        self.validate_fields().map_err(ValidationError::Fields)
    }

    fn cached_items(config: &GatewayConfig) -> &[Self] {
        &config.consumers
    }

    fn response_body(resource: &Self) -> Value {
        consumer_response_body(resource)
    }

    fn audit_body(resource: &Self) -> Value {
        consumer_audit_body(resource)
    }

    fn prepare_for_update(&mut self, existing: &Self) {
        // Ordinary Consumer responses omit Basic credentials entirely. Preserve
        // them when a client round-trips that response through PUT; explicit
        // credential replacement and deletion use the credential endpoints.
        if !self.credentials.contains_key("basicauth")
            && let Some(basic_credentials) = existing.credentials.get("basicauth")
        {
            self.credentials
                .insert("basicauth".to_string(), basic_credentials.clone());
        }
    }

    fn map_after_validate_errors(errors: &[String]) -> Response<Full<Bytes>> {
        super::json_response(StatusCode::CONFLICT, &json!({"error": errors.join("; ")}))
    }

    fn prepare_for_write(&mut self) -> Result<(), PrepareWriteError> {
        let consumer_id = self.id.clone();
        hash_consumer_credentials(self).map_err(|error| match error {
            crate::config::types::BasicAuthCredentialPreparationError::InvalidCredential(
                message,
            ) => PrepareWriteError::InvalidRequest(format!(
                "Failed to prepare Basic-auth credentials for consumer {}: {}",
                consumer_id, message
            )),
            crate::config::types::BasicAuthCredentialPreparationError::ServerConfiguration(
                message,
            ) => PrepareWriteError::Internal(format!(
                "Failed to prepare Basic-auth credentials for consumer {}: {}",
                consumer_id, message
            )),
        })
    }

    fn map_persist_db_error(
        error: &anyhow::Error,
        _action: WriteAction<'_>,
    ) -> Response<Full<Bytes>> {
        consumer_persist_error_response(error)
    }

    async fn db_get(db: &dyn DatabaseBackend, namespace: &str, id: &str) -> DbResult<Option<Self>> {
        db.get_consumer(namespace, id).await
    }

    async fn db_list(
        db: &dyn DatabaseBackend,
        namespace: &str,
        pagination: &super::PaginationParams,
    ) -> DbResult<PaginatedResult<Self>> {
        db.list_consumers_paginated(
            namespace,
            pagination.query_limit_i64(),
            pagination.offset as i64,
        )
        .await
    }

    async fn db_create(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<()> {
        db.create_consumer(resource).await
    }

    async fn db_update(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<bool> {
        db.update_consumer(resource, &BatchConfigWriteMode::Admission)
            .await
    }

    async fn db_delete(db: &dyn DatabaseBackend, namespace: &str, id: &str) -> DbResult<bool> {
        db.delete_consumer(namespace, id).await
    }

    async fn check_uniqueness(
        db: &dyn DatabaseBackend,
        namespace: &str,
        resource: &Self,
        exclude_id: Option<&str>,
    ) -> DbResult<Option<String>> {
        match db
            .check_consumer_identity_unique(
                namespace,
                &resource.id,
                &resource.username,
                resource.custom_id.as_deref(),
                exclude_id,
            )
            .await
        {
            Ok(Some(message)) => return Ok(Some(message)),
            Ok(None) => {}
            Err(error) => return Err(error),
        }

        check_consumer_credential_uniqueness(db, namespace, resource, exclude_id).await
    }

    async fn after_validate(
        db: &dyn DatabaseBackend,
        _state: &AdminState,
        namespace: &str,
        resource: &Self,
        _existing: Option<&Self>,
        _ctx: &ValidationCtx<'_>,
    ) -> Result<(), AfterValidateError> {
        let mut errors = Vec::new();
        if resource.has_credential("mtls_auth") {
            errors.extend(
                mtls_consumer_candidate_errors(db, namespace, resource)
                    .await
                    .map_err(AfterValidateError::Db)?,
            );
        }
        if resource.has_credential("hmac_auth") {
            errors.extend(
                hmac_consumer_candidate_errors(db, namespace, resource)
                    .await
                    .map_err(AfterValidateError::Db)?,
            );
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(AfterValidateError::BadRequest(errors))
        }
    }
}

fn not_found_response<R: AdminResource>() -> Response<Full<Bytes>> {
    super::json_response(
        StatusCode::NOT_FOUND,
        &json!({"error": R::NOT_FOUND_MESSAGE}),
    )
}

fn map_after_validate_error<R: AdminResource>(error: AfterValidateError) -> Response<Full<Bytes>> {
    match error {
        AfterValidateError::BadRequest(field_errors) => R::map_after_validate_errors(&field_errors),
        AfterValidateError::Conflict(errors) => {
            super::json_response(StatusCode::CONFLICT, &json!({"error": errors.join("; ")}))
        }
        AfterValidateError::Db(error) => R::map_precheck_db_error(&error),
        AfterValidateError::Response(response) => *response,
    }
}

fn config_update_target_was_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let message = cause.to_string();
        message.contains(" was not found in namespace '")
            || message.contains("proxy '") && message.ends_with("' was not found")
            || message.contains("consumer '") && message.ends_with("' was not found")
            || message.contains("plugin config '") && message.ends_with("' was not found")
            || message.contains("upstream '") && message.ends_with("' was not found")
    })
}

async fn handle_write<R: AdminResource>(
    state: &AdminState,
    actor: &AuditActor,
    body: &[u8],
    namespace: &str,
    action: WriteAction<'_>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(response) = state.check_write_allowed() {
        return Ok(response);
    }

    if let WriteAction::Update { id } = action
        && let Err(message) = validate_resource_id(id)
    {
        return Ok(super::json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": message}),
        ));
    }

    let db_arc = match state.db.as_ref() {
        Some(db) => db.clone(),
        None => {
            return Ok(super::json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };
    let db = db_arc.as_ref();
    let _mtls_admission_guard = if R::SERIALIZE_MTLS_ADMISSION {
        Some(lock_mtls_admission(namespace).await)
    } else {
        None
    };

    if let Err(message) = R::validate_raw_body(body) {
        return Ok(super::json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": message}),
        ));
    }

    let mut resource: R = match serde_json::from_slice(body) {
        Ok(resource) => resource,
        Err(error) => {
            return Ok(super::json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": format!("Invalid body: {}", error)}),
            ));
        }
    };

    let existing = match action {
        WriteAction::Create => None,
        WriteAction::Update { id } => match R::db_get_for_write(db, namespace, id).await {
            // Updating a resource that does not exist in this namespace is a
            // 404 — proceeding would let the persist step "succeed" against
            // zero rows (issue #2122 DB-M4 phantom update).
            Ok(None) => {
                return Ok(not_found_response::<R>());
            }
            Ok(existing) => existing,
            Err(error) => {
                return Ok(R::map_precheck_db_error(&error));
            }
        },
    };

    match action {
        WriteAction::Create => {
            if resource.id().is_empty() {
                resource.set_id(Uuid::new_v4().to_string());
            } else if let Err(message) = validate_resource_id(resource.id()) {
                return Ok(super::json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({"error": message}),
                ));
            }
        }
        WriteAction::Update { id } => {
            resource.set_id(id.to_string());
            if let Some(existing) = existing.as_ref() {
                resource.prepare_for_update(existing);
            }
        }
    }

    resource.normalize();
    resource.set_namespace(namespace.to_string());

    let validation_ctx = ValidationCtx::from_state(state);
    if let Err(validation_error) = resource.validate(&validation_ctx) {
        return Ok(R::map_validation_error(&validation_error));
    }

    if matches!(action, WriteAction::Create) {
        match R::db_get(db, namespace, resource.id()).await {
            Ok(Some(_)) => {
                return Ok(super::json_response(
                    StatusCode::CONFLICT,
                    &json!({"error": format!(
                        "{} with ID '{}' already exists",
                        R::ID_CONFLICT_LABEL,
                        resource.id()
                    )}),
                ));
            }
            Ok(None) => {}
            Err(error) => return Ok(R::map_precheck_db_error(&error)),
        }
    }

    let exclude_id = match action {
        WriteAction::Create => None,
        WriteAction::Update { id } => Some(id),
    };
    match R::check_uniqueness(db, namespace, &resource, exclude_id).await {
        Ok(Some(message)) => {
            return Ok(super::json_response(
                StatusCode::CONFLICT,
                &json!({"error": message}),
            ));
        }
        Ok(None) => {}
        Err(error) => return Ok(R::map_precheck_db_error(&error)),
    }

    if let Err(error) = R::after_validate(
        db,
        state,
        namespace,
        &resource,
        existing.as_ref(),
        &validation_ctx,
    )
    .await
    {
        return Ok(map_after_validate_error::<R>(error));
    }

    if let Err(error) = resource.prepare_for_write() {
        return Ok(super::json_response(
            error.status(),
            &json!({"error": error.message()}),
        ));
    }

    let now = Utc::now();
    match action {
        WriteAction::Create => {
            resource.set_created_at(now);
            resource.set_updated_at(now);
        }
        WriteAction::Update { .. } => {
            resource.set_updated_at(now);
        }
    }

    match action {
        WriteAction::Create => {
            if let Err(error) = R::db_create(db, &resource).await {
                return Ok(R::map_persist_db_error(&error, action));
            }
        }
        WriteAction::Update { .. } => match R::db_update(db, &resource).await {
            // The row vanished between the precheck and the write (concurrent
            // delete). The backend recorded no change — report not-found
            // rather than a phantom success (issue #2122 DB-M4).
            Ok(false) => {
                return Ok(not_found_response::<R>());
            }
            Ok(true) => {}
            Err(error) => {
                return Ok(R::map_persist_db_error(&error, action));
            }
        },
    }

    if let Err(error) =
        R::after_write(db, state, namespace, &resource, existing.as_ref(), action).await
    {
        tracing::warn!(
            "Post-write hook failed for {} '{}': {}",
            R::RESOURCE_NAME,
            resource.id(),
            error
        );
    }

    let (audit_action, diff) = match action {
        WriteAction::Create => ("create", audit::create_diff(R::audit_body(&resource))),
        WriteAction::Update { .. } => {
            let before = existing
                .as_ref()
                .map(R::audit_body)
                .unwrap_or_else(|| json!(null));
            (
                "update",
                audit::update_diff(before, R::audit_body(&resource)),
            )
        }
    };
    let event = AuditEvent::new(
        actor,
        audit_action,
        R::RESOURCE_NAME.replace(' ', "_"),
        resource.id(),
        namespace,
        diff,
    );
    if let Err(error) = audit::record(state.admin_audit_enabled, db_arc, event) {
        super::log_audit_enqueue_failure(&error);
    }

    let body = R::response_body_for_role(&resource, actor.role);
    let status = match action {
        WriteAction::Create => StatusCode::CREATED,
        WriteAction::Update { .. } => StatusCode::OK,
    };
    Ok(super::json_response(status, &body))
}

fn validation_error_response<R: AdminResource>(field_errors: &[String]) -> Response<Full<Bytes>> {
    super::json_response(
        StatusCode::BAD_REQUEST,
        &json!({"error": format!(
            "Invalid {}: {}",
            R::VALIDATION_ERROR_LABEL,
            field_errors.join("; ")
        )}),
    )
}
