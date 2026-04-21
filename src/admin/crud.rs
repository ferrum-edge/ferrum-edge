use bytes::Bytes;
use chrono::{DateTime, Utc};
use http_body_util::Full;
use hyper::{Response, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::collections::HashSet;
use uuid::Uuid;

use crate::admin::AdminState;
use crate::config::db_backend::{DatabaseBackend, PaginatedResult};
use crate::config::types::{
    Consumer, GatewayConfig, PluginConfig, Proxy, Upstream, validate_resource_id,
};

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

/// Validation outcomes that preserve legacy plain-message responses for
/// resource-specific checks while still supporting the generic field wrapper.
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

    /// Inspect the raw request body *before* it is deserialized into `Self`.
    /// Return `Err` to reject the request with a 400 Bad Request. Used to
    /// catch renamed / removed fields that `serde(default)` would otherwise
    /// silently ignore, so operators get a clean migration error instead of
    /// a confusingly no-op request.
    ///
    /// Default is a no-op. Override on resources that have renamed fields.
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
                super::json_response(StatusCode::BAD_REQUEST, &json!({"error": message}))
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
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(ref db) = state.db {
        match R::db_list(db.as_ref(), namespace, pagination).await {
            Ok(result) => {
                let items: Vec<Value> = result.items.iter().map(R::response_body).collect();
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
            .map(R::response_body)
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
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(ref db) = state.db {
        match R::db_get(db.as_ref(), id).await {
            Ok(Some(resource)) => {
                if resource.namespace() != namespace {
                    return Ok(not_found_response::<R>());
                }
                let body = R::response_body(&resource);
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
                let body = R::response_body(resource);
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
    body: &[u8],
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    handle_write::<R>(state, body, namespace, WriteAction::Create).await
}

pub(crate) async fn handle_update<R: AdminResource>(
    state: &AdminState,
    id: &str,
    body: &[u8],
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    handle_write::<R>(state, body, namespace, WriteAction::Update { id }).await
}

pub(crate) async fn handle_delete<R: AdminResource>(
    state: &AdminState,
    id: &str,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(response) = state.check_write_allowed() {
        return Ok(response);
    }

    let db = match state.db.as_ref() {
        Some(db) => db.as_ref(),
        None => {
            return Ok(super::json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
    };

    match R::db_get(db, id).await {
        Ok(Some(resource)) if resource.namespace() != namespace => {
            return Ok(not_found_response::<R>());
        }
        Ok(None) => {
            return Ok(not_found_response::<R>());
        }
        Err(error) => {
            return Ok(R::map_precheck_db_error(&error));
        }
        Ok(Some(_)) => {}
    }

    match R::db_delete(db, id).await {
        Ok(true) => Ok(super::json_response(StatusCode::NO_CONTENT, &json!({}))),
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

pub(crate) fn validate_plugin_config_definition(pc: &PluginConfig) -> Result<(), String> {
    super::validate_plugin_config_definition(pc)
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
        self.normalize_fields();
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
        if error
            .to_string()
            .contains("referenced by one or more proxies")
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
        db.list_upstreams_paginated(namespace, pagination.limit as i64, pagination.offset as i64)
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
        self.normalize_fields();
    }

    fn validate(&self, _ctx: &ValidationCtx<'_>) -> Result<(), ValidationError> {
        self.validate_fields().map_err(ValidationError::Fields)
    }

    fn cached_items(config: &GatewayConfig) -> &[Self] {
        &config.plugin_configs
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
            pagination.limit as i64,
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
        _namespace: &str,
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
            match db.check_proxy_exists(proxy_id).await {
                Ok(true) => {}
                Ok(false) => {
                    return Err(AfterValidateError::BadRequest(vec![format!(
                        "proxy_id '{}' does not exist",
                        proxy_id
                    )]));
                }
                Err(error) => return Err(AfterValidateError::Db(error)),
            }
        }

        if let Err(error) = validate_plugin_config_definition(resource) {
            return Err(AfterValidateError::BadRequest(vec![format!(
                "Invalid plugin config: {}",
                error
            )]));
        }

        Ok(())
    }
}

impl AdminResource for Proxy {
    const RESOURCE_NAME: &'static str = "proxy";
    const RESOURCE_LABEL: &'static str = "Proxy";
    const VALIDATION_ERROR_LABEL: &'static str = "proxy fields";
    const NOT_FOUND_MESSAGE: &'static str = "Proxy not found";

    /// Reject legacy field names that were renamed in the scheme refactor.
    /// Without this, `#[serde(default)]` would silently ignore a
    /// `backend_protocol` key and leave the Proxy with its default scheme,
    /// so operators upgrading from older tooling would see a confusing
    /// no-op instead of a clear migration message.
    fn validate_raw_body(body: &[u8]) -> Result<(), String> {
        // Only inspect the top-level object — don't pay the cost of a full
        // JSON walk here. A malformed body will be caught by the real
        // deserialize below.
        if let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(body)
            && map.contains_key("backend_protocol")
        {
            return Err(
                "Field 'backend_protocol' was renamed to 'backend_scheme' (6-variant enum: \
                 http, https, tcp, tcps, udp, dtls). gRPC and WebSocket are now detected at \
                 runtime from the request; HTTP/3 is opt-in via 'backend_prefer_h3: true'."
                    .to_string(),
            );
        }
        Ok(())
    }

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
        db.list_proxies_paginated(namespace, pagination.limit as i64, pagination.offset as i64)
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
        _namespace: &str,
        resource: &Self,
        existing: Option<&Self>,
        ctx: &ValidationCtx<'_>,
    ) -> Result<(), AfterValidateError> {
        if let Some(upstream_id) = resource.upstream_id.as_deref() {
            match db.check_upstream_exists(upstream_id).await {
                Ok(true) => {}
                Ok(false) => {
                    return Err(AfterValidateError::BadRequest(vec![format!(
                        "upstream_id '{}' does not exist",
                        upstream_id
                    )]));
                }
                Err(error) => return Err(AfterValidateError::Db(error)),
            }
        }

        match db
            .validate_proxy_plugin_associations(resource.id(), &resource.plugins)
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
        db.list_consumers_paginated(namespace, pagination.limit as i64, pagination.offset as i64)
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
    body: &[u8],
    namespace: &str,
    action: WriteAction<'_>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(response) = state.check_write_allowed() {
        return Ok(response);
    }

    let db = match state.db.as_ref() {
        Some(db) => db.as_ref(),
        None => {
            return Ok(super::json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                &json!({"error": "No database"}),
            ));
        }
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

    let body = R::response_body(&resource);
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
