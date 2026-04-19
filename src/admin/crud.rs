#![allow(dead_code)]

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
use crate::config::types::{Consumer, GatewayConfig, PluginConfig, Upstream, validate_resource_id};

pub(crate) type DbResult<T> = Result<T, anyhow::Error>;

pub(crate) struct ValidationCtx<'a> {
    pub reserved_ports: &'a HashSet<u16>,
    pub stream_bind_address: &'a str,
    pub mode: &'a str,
}

impl<'a> ValidationCtx<'a> {
    fn from_state(state: &'a AdminState) -> Self {
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
    fn validate(&self, ctx: &ValidationCtx<'_>) -> Result<(), Vec<String>>;
    fn cached_items(config: &GatewayConfig) -> &[Self];

    fn response_body(resource: &Self) -> Value {
        json!(resource)
    }

    fn prepare_for_update(&mut self, _existing: &Self) {}

    fn prepare_for_write(&mut self) -> Result<(), String> {
        Ok(())
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
    ) -> Result<(), Vec<String>> {
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

pub(crate) fn redact_consumer_for_response(consumer: &Consumer) -> Consumer {
    super::redact_consumer_credentials(consumer)
}

pub(crate) fn consumer_response_body(consumer: &Consumer) -> Value {
    json!(redact_consumer_for_response(consumer))
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
    for key_creds in consumer.credential_entries("keyauth") {
        if let Some(key) = key_creds.get("key").and_then(|value| value.as_str()) {
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

    for mtls_creds in consumer.credential_entries("mtls_auth") {
        if let Some(identity) = mtls_creds.get("identity").and_then(|value| value.as_str()) {
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

    fn validate(&self, _ctx: &ValidationCtx<'_>) -> Result<(), Vec<String>> {
        if self.targets.is_empty() && self.service_discovery.is_none() {
            return Err(vec![
                "At least one target is required (or configure service_discovery)".to_string(),
            ]);
        }
        self.validate_fields()
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
    if let Err(field_errors) = resource.validate(&validation_ctx) {
        return Ok(validation_error_response::<R>(&field_errors));
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

    if let Err(field_errors) = R::after_validate(
        db,
        state,
        namespace,
        &resource,
        existing.as_ref(),
        &validation_ctx,
    )
    .await
    {
        return Ok(validation_error_response::<R>(&field_errors));
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
