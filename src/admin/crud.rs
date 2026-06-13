use bytes::Bytes;
use chrono::{DateTime, Utc};
use http_body_util::Full;
use hyper::{Response, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::collections::HashSet;
use uuid::Uuid;

use crate::admin::AdminState;
use crate::admin::audit::{self, AuditActor, AuditEvent};
use crate::admin::jwt_auth::AdminRole;
use crate::config::db_backend::{DatabaseBackend, PaginatedResult};
use crate::config::types::{
    Consumer, GatewayConfig, PluginConfig, PluginScope, Proxy, Upstream, validate_resource_id,
};
use crate::plugins::mesh_route_dispatch::MeshRouteDispatchConfig;

pub(crate) type DbResult<T> = Result<T, anyhow::Error>;

pub(crate) struct ValidationCtx<'a> {
    pub reserved_ports: &'a HashSet<u16>,
    pub stream_bind_address: &'a str,
    pub mode: &'a str,
}

impl<'a> ValidationCtx<'a> {
    pub(crate) fn from_state(state: &'a AdminState) -> Self {
        Self {
            reserved_ports: &state.reserved_ports,
            stream_bind_address: &state.stream_proxy_bind_address,
            mode: &state.mode,
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
    Db(anyhow::Error),
    Response(Response<Full<Bytes>>),
}

/// Validation outcomes for resource-specific checks and generic field validation.
pub(crate) enum ValidationError {
    Fields(Vec<String>),
    Message(String),
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

    fn prepare_for_write(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn map_validation_error(error: &ValidationError) -> Response<Full<Bytes>> {
        match error {
            ValidationError::Fields(errors) => validation_error_response::<Self>(errors),
            ValidationError::Message(message) => {
                validation_error_response::<Self>(&[message.to_string()])
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
        super::json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &super::db_error_response(error),
        )
    }

    fn map_delete_db_error(error: &anyhow::Error) -> Response<Full<Bytes>> {
        super::json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &super::db_error_response(error),
        )
    }

    async fn db_get(db: &dyn DatabaseBackend, id: &str) -> DbResult<Option<Self>>;
    async fn db_list(
        db: &dyn DatabaseBackend,
        namespace: &str,
        pagination: &super::PaginationParams,
    ) -> DbResult<PaginatedResult<Self>>;
    async fn db_create(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<()>;
    async fn db_update(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<()>;
    async fn db_delete(db: &dyn DatabaseBackend, id: &str) -> DbResult<bool>;

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
    if let Some(ref db) = state.db {
        match R::db_get(db.as_ref(), id).await {
            Ok(Some(resource)) => {
                if resource.namespace() != namespace {
                    return Ok(not_found_response::<R>());
                }
                let body = R::response_body_for_role(&resource, role);
                return Ok(super::json_response(StatusCode::OK, &body));
            }
            Ok(None) => {
                return Ok(not_found_response::<R>());
            }
            Err(error) => {
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

    let existing = match R::db_get(db, id).await {
        Ok(Some(resource)) if resource.namespace() != namespace => {
            return Ok(not_found_response::<R>());
        }
        Ok(None) => {
            return Ok(not_found_response::<R>());
        }
        Err(error) => {
            return Ok(R::map_precheck_db_error(&error));
        }
        Ok(Some(resource)) => resource,
    };

    match R::db_delete(db, id).await {
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
            Ok(super::json_response(StatusCode::NO_CONTENT, &json!({})))
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
) -> Result<(), Vec<String>> {
    if resource.id().is_empty() {
        resource.set_id(Uuid::new_v4().to_string());
    } else if let Err(message) = validate_resource_id(resource.id()) {
        return Err(vec![message]);
    }

    resource.normalize();
    resource.set_namespace(namespace.to_string());
    resource
        .validate(validation_ctx)
        .map_err(ValidationError::into_messages)?;
    if let Err(message) = resource.prepare_for_write() {
        return Err(vec![message]);
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

pub(crate) fn consumer_persist_error_response(error: &anyhow::Error) -> Response<Full<Bytes>> {
    let message = error.to_string();
    let status = if super::is_unique_constraint_violation(&message) {
        StatusCode::CONFLICT
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    super::json_response(status, &json!({"error": message}))
}

pub(crate) fn hash_consumer_credentials(consumer: &mut Consumer) -> Result<(), String> {
    super::hash_consumer_secrets(consumer)
}

pub(crate) fn hash_basic_auth_credentials(cred: &mut Value) -> Result<(), String> {
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
    match db.get_proxy(proxy_id).await {
        Ok(Some(proxy)) if proxy.namespace != namespace => {
            Err(AfterValidateError::BadRequest(vec![format!(
                "Cross-namespace reference forbidden: proxy_id '{}' belongs to namespace '{}' but plugin_config is in namespace '{}'",
                proxy_id, proxy.namespace, namespace
            )]))
        }
        Ok(Some(proxy)) if proxy.api_spec_id.is_none() => {
            Err(AfterValidateError::BadRequest(vec![
                "openapi_validator requires a proxy with an attached api_spec".to_string(),
            ]))
        }
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(AfterValidateError::BadRequest(vec![format!(
            "proxy_id '{}' does not exist",
            proxy_id
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
                let message = match db.get_upstream(upstream_id).await {
                    Ok(Some(other)) => format!(
                        "PluginConfig '{}' (mesh_route_dispatch) rule {} references upstream_id '{}' from namespace '{}' (plugin_config is in namespace '{}'); cross-namespace references are forbidden",
                        plugin_config.id, rule_idx, upstream_id, other.namespace, namespace
                    ),
                    _ => format!(
                        "PluginConfig '{}' (mesh_route_dispatch) rule {} references non-existent upstream_id '{}'",
                        plugin_config.id, rule_idx, upstream_id
                    ),
                };
                errors.push(message);
            }
            Err(error) => return Err(error),
        }
    }

    Ok(errors)
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

    fn validate(&self, _ctx: &ValidationCtx<'_>) -> Result<(), ValidationError> {
        if self.targets.is_empty() && self.service_discovery.is_none() {
            return Err(ValidationError::Message(
                "At least one target is required (or configure service_discovery)".to_string(),
            ));
        }
        self.validate_fields().map_err(ValidationError::Fields)
    }

    fn cached_items(config: &GatewayConfig) -> &[Self] {
        &config.upstreams
    }

    fn map_delete_db_error(error: &anyhow::Error) -> Response<Full<Bytes>> {
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

    async fn db_get(db: &dyn DatabaseBackend, id: &str) -> DbResult<Option<Self>> {
        db.get_upstream(id).await
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

    async fn db_update(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<()> {
        db.update_upstream(resource).await
    }

    async fn db_delete(db: &dyn DatabaseBackend, id: &str) -> DbResult<bool> {
        db.delete_upstream(id).await
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
        _state: &AdminState,
        namespace: &str,
        resource: &Self,
        _existing: Option<&Self>,
        _ctx: &ValidationCtx<'_>,
    ) -> Result<(), AfterValidateError> {
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
                if proxy.upstream_id.as_deref() != Some(resource.id.as_str()) {
                    continue;
                }
                if let Some(subset_name) = proxy.upstream_subset.as_deref()
                    && !subset_names.contains(subset_name)
                {
                    errors.push(format!(
                        "upstream '{}' cannot remove subset '{}' while proxy '{}' references it",
                        resource.id, subset_name, proxy.id
                    ));
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

    fn validate(&self, _ctx: &ValidationCtx<'_>) -> Result<(), ValidationError> {
        self.validate_fields().map_err(ValidationError::Fields)
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

    async fn db_get(db: &dyn DatabaseBackend, id: &str) -> DbResult<Option<Self>> {
        db.get_plugin_config(id).await
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

    async fn db_update(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<()> {
        db.update_plugin_config(resource).await
    }

    async fn db_delete(db: &dyn DatabaseBackend, id: &str) -> DbResult<bool> {
        db.delete_plugin_config(id).await
    }

    async fn check_uniqueness(
        _db: &dyn DatabaseBackend,
        _namespace: &str,
        _resource: &Self,
        _exclude_id: Option<&str>,
    ) -> DbResult<Option<String>> {
        Ok(None)
    }

    async fn after_validate(
        db: &dyn DatabaseBackend,
        _state: &AdminState,
        namespace: &str,
        resource: &Self,
        _existing: Option<&Self>,
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
                    // Distinguish "missing" from "wrong namespace" so the
                    // operator can fix the actual problem instead of
                    // chasing a phantom "does not exist".
                    let message = match db.get_proxy(proxy_id).await {
                        Ok(Some(other)) => format!(
                            "Cross-namespace reference forbidden: proxy_id '{}' belongs to namespace '{}' but plugin_config is in namespace '{}'",
                            proxy_id, other.namespace, namespace
                        ),
                        _ => format!("proxy_id '{}' does not exist", proxy_id),
                    };
                    return Err(AfterValidateError::BadRequest(vec![message]));
                }
                Err(error) => return Err(AfterValidateError::Db(error)),
            }
        }

        if let Err(error) = validate_plugin_config_definition(_state, resource) {
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

        Ok(())
    }
}

impl AdminResource for Proxy {
    const RESOURCE_NAME: &'static str = "proxy";
    const RESOURCE_LABEL: &'static str = "Proxy";
    const VALIDATION_ERROR_LABEL: &'static str = "proxy fields";
    const NOT_FOUND_MESSAGE: &'static str = "Proxy not found";

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

    fn validate(&self, _ctx: &ValidationCtx<'_>) -> Result<(), ValidationError> {
        self.validate_fields().map_err(ValidationError::Fields)?;

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

    async fn db_get(db: &dyn DatabaseBackend, id: &str) -> DbResult<Option<Self>> {
        db.get_proxy(id).await
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

    async fn db_update(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<()> {
        db.update_proxy(resource).await
    }

    async fn db_delete(db: &dyn DatabaseBackend, id: &str) -> DbResult<bool> {
        db.delete_proxy(id).await
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
                    return Ok(Some(
                        "A proxy with overlapping hosts and listen_path already exists".to_string(),
                    ));
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

    async fn after_validate(
        db: &dyn DatabaseBackend,
        _state: &AdminState,
        namespace: &str,
        resource: &Self,
        existing: Option<&Self>,
        ctx: &ValidationCtx<'_>,
    ) -> Result<(), AfterValidateError> {
        if let Some(upstream_id) = resource.upstream_id.as_deref() {
            match db.get_upstream(upstream_id).await {
                Ok(Some(upstream)) if upstream.namespace != namespace => {
                    return Err(AfterValidateError::BadRequest(vec![format!(
                        "Cross-namespace reference forbidden: upstream_id '{}' belongs to namespace '{}' but proxy is in namespace '{}'",
                        upstream_id, upstream.namespace, namespace
                    )]));
                }
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
                }
                Ok(None) => {
                    return Err(AfterValidateError::BadRequest(vec![format!(
                        "upstream_id '{}' does not exist",
                        upstream_id
                    )]));
                }
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

        if resource.dispatch_kind.is_stream()
            && let Some(port) = resource.listen_port
            && ctx.mode != "cp"
        {
            if ctx.reserved_ports.contains(&port) {
                return Err(AfterValidateError::Response(super::json_response(
                    StatusCode::CONFLICT,
                    &json!({"error": format!(
                        "listen_port {} conflicts with a gateway reserved port (proxy/admin/gRPC listener)",
                        port
                    )}),
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
                return Err(AfterValidateError::Response(super::json_response(
                    StatusCode::CONFLICT,
                    &json!({"error": format!(
                        "listen_port {} is not available on the host: {}",
                        port, error
                    )}),
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
        if matches!(action, WriteAction::Update { .. })
            && let Some(old_proxy) = existing
            && let Some(old_upstream_id) = old_proxy.upstream_id.as_deref()
            && resource.upstream_id.as_deref() != Some(old_upstream_id)
        {
            db.cleanup_orphaned_upstream(old_upstream_id).await?;
        }

        Ok(())
    }
}

impl AdminResource for Consumer {
    const RESOURCE_NAME: &'static str = "consumer";
    const RESOURCE_LABEL: &'static str = "Consumer";
    const VALIDATION_ERROR_LABEL: &'static str = "consumer fields";
    const NOT_FOUND_MESSAGE: &'static str = "Consumer not found";

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

    fn prepare_for_write(&mut self) -> Result<(), String> {
        hash_consumer_credentials(self)
    }

    fn map_persist_db_error(
        error: &anyhow::Error,
        _action: WriteAction<'_>,
    ) -> Response<Full<Bytes>> {
        consumer_persist_error_response(error)
    }

    async fn db_get(db: &dyn DatabaseBackend, id: &str) -> DbResult<Option<Self>> {
        db.get_consumer(id).await
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

    async fn db_update(db: &dyn DatabaseBackend, resource: &Self) -> DbResult<()> {
        db.update_consumer(resource).await
    }

    async fn db_delete(db: &dyn DatabaseBackend, id: &str) -> DbResult<bool> {
        db.delete_consumer(id).await
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
}

fn not_found_response<R: AdminResource>() -> Response<Full<Bytes>> {
    super::json_response(
        StatusCode::NOT_FOUND,
        &json!({"error": R::NOT_FOUND_MESSAGE}),
    )
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
        WriteAction::Update { id } => match R::db_get(db, id).await {
            Ok(Some(existing)) if existing.namespace() != namespace => {
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
        match R::db_get(db, resource.id()).await {
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
        return Ok(match error {
            AfterValidateError::BadRequest(field_errors) => {
                R::map_after_validate_errors(&field_errors)
            }
            AfterValidateError::Db(error) => R::map_precheck_db_error(&error),
            AfterValidateError::Response(response) => response,
        });
    }

    if let Err(message) = resource.prepare_for_write() {
        return Ok(super::json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({"error": message}),
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

    let persist_result = match action {
        WriteAction::Create => R::db_create(db, &resource).await,
        WriteAction::Update { .. } => R::db_update(db, &resource).await,
    };
    if let Err(error) = persist_result {
        return Ok(R::map_persist_db_error(&error, action));
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
