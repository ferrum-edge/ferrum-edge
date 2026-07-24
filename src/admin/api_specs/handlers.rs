//! HTTP handlers for the `/api-specs` admin endpoints (Wave 3).
//!
//! Six endpoints:
//!   POST   /api-specs                     — submit new spec
//!   PUT    /api-specs/{id}                — replace existing spec
//!   GET    /api-specs                     — list (paginated)
//!   GET    /api-specs/{id}                — fetch one spec (with content negotiation)
//!   GET    /api-specs/by-proxy/{proxy_id} — lookup by proxy
//!   DELETE /api-specs/{id}                — delete

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;
use uuid::Uuid;

use crate::admin::api_specs::extractor::{MAX_YAML_EXPANDED_NODES, count_value_nodes};
use crate::admin::api_specs::{
    ExtractError, ExtractedBundle, SpecFormat, extract, hash_resource_bundle,
};
use crate::admin::audit::{self, AuditActor};
use crate::admin::spec_codec;
use crate::admin::{AdminState, log_audit_enqueue_failure};
use crate::config::db_backend::{
    ApiSpecListFilter, ApiSpecSortBy, DatabaseBackend, PROXY_ROUTE_CONFLICT_ERROR, SortOrder,
    is_mtls_dns_admission_unavailable, is_mtls_dns_identity_conflict,
    tcp_connection_throttle_attachment_conflict, validate_api_spec_proxy_plugin_association,
    validate_api_spec_restore_inputs,
};
use crate::config::types::{ApiSpec, PluginAssociation, PluginScope, Upstream};

// ---------------------------------------------------------------------------
// Internal error type
// ---------------------------------------------------------------------------

/// Handler-local error type that maps cleanly to HTTP statuses.
///
/// All arms are converted to `Response<Full<Bytes>>` before leaving this
/// module; callers never see `ApiSpecError` directly.
#[derive(Debug)]
enum ApiSpecError {
    /// Body too large (413)
    PayloadTooLarge(usize),
    /// Body collection idle timeout (408)
    BodyTimedOut,
    /// Body collection error (non-size)
    BodyCollect,
    /// Extraction/parse error (400)
    Extract(ExtractError),
    /// Generic 400 (invalid query params, etc.)
    BadRequest(String),
    /// Validation failures (422)
    ValidationFailures {
        spec_version: String,
        failures: Vec<ValidationFailure>,
    },
    /// Resource not found (404)
    NotFound,
    /// Unique constraint / conflict (409)
    Conflict(String),
    /// MongoDB doc size limit (413)
    MongoDocTooLarge,
    /// FK or business-logic violation (422)
    Unprocessable(String),
    /// Authoritative plugin-composition validation failure (422)
    PluginComposition(Vec<String>),
    /// No DB configured (503)
    NoDatabase,
    /// Namespace admission is currently fenced (503)
    AdmissionUnavailable(String),
    /// Generic DB or internal error (500)
    Internal(String),
}

#[derive(Debug, serde::Serialize)]
struct ValidationFailure {
    resource_type: &'static str,
    id: String,
    errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApiSpecLateWriteRecovery {
    Retained,
    NotRetained,
}

// ---------------------------------------------------------------------------
// Helper: map anyhow::Error from DB calls to ApiSpecError
// ---------------------------------------------------------------------------

fn classify_db_error(e: anyhow::Error) -> ApiSpecError {
    if is_mtls_dns_admission_unavailable(&e) {
        return ApiSpecError::AdmissionUnavailable(
            "namespace config admission unavailable".to_string(),
        );
    }
    if is_mtls_dns_identity_conflict(&e) {
        return ApiSpecError::Conflict("mTLS DNS identity conflict".to_string());
    }
    if let Some(conflict) = tcp_connection_throttle_attachment_conflict(&e) {
        return ApiSpecError::PluginComposition(conflict.errors().to_vec());
    }
    if e.chain().any(|cause| {
        cause
            .downcast_ref::<sqlx::Error>()
            .is_some_and(|err| matches!(err, sqlx::Error::RowNotFound))
    }) {
        return ApiSpecError::NotFound;
    }

    for cause in e.chain() {
        let classified = classify_db_error_str(&cause.to_string());
        if !matches!(classified, ApiSpecError::Internal(_)) {
            return classified;
        }
    }
    ApiSpecError::Internal("database operation failed".to_string())
}

fn classify_db_error_str(msg: &str) -> ApiSpecError {
    let lower = msg.to_lowercase();
    if msg.contains(PROXY_ROUTE_CONFLICT_ERROR)
        || lower.contains("unique constraint")
        || lower.contains("duplicate key")
        || lower.contains("duplicate entry")
    {
        ApiSpecError::Conflict("resource conflict".to_string())
    } else if msg.contains("MongoDB document limit") {
        ApiSpecError::MongoDocTooLarge
    } else if lower.contains("foreign key constraint")
        || lower.contains("foreign key")
        || lower.contains("references a")
    {
        ApiSpecError::Unprocessable("referential integrity violation".to_string())
    } else if is_row_missing_error_message(&lower) {
        ApiSpecError::NotFound
    } else {
        ApiSpecError::Internal("database operation failed".to_string())
    }
}

fn restore_snapshot_validation_failure(
    spec: &ApiSpec,
    resource_id: String,
    error: String,
) -> ApiSpecError {
    ApiSpecError::ValidationFailures {
        spec_version: spec.spec_version.clone(),
        failures: vec![ValidationFailure {
            resource_type: "restore_snapshot",
            id: resource_id,
            errors: vec![error],
        }],
    }
}

async fn run_api_spec_persistence_while_held<T, F, C>(
    db: Arc<dyn DatabaseBackend>,
    namespace: &str,
    guard: crate::admin::crud::NamespaceConfigAdmissionGuard,
    future: F,
    compensation: C,
    compensate_after_intervening_write: bool,
) -> Result<T, ApiSpecError>
where
    F: Future<Output = Result<T, anyhow::Error>>,
    C: Future<Output = Result<ApiSpecLateWriteRecovery, anyhow::Error>>,
{
    match guard.run_to_completion_while_held(future).await {
        Ok(crate::admin::crud::NamespaceConfigAdmissionCompletion::Held(result)) => {
            result.map_err(classify_db_error)
        }
        Ok(crate::admin::crud::NamespaceConfigAdmissionCompletion::Lost { result, error: _ }) => {
            crate::admin::warn_persistence_failure_redacted("api_spec_namespace_admission_lost");
            match result {
                Ok(result) => {
                    let lost_generation = guard.generation();
                    drop(guard);
                    let recovery_guard =
                        crate::admin::crud::lock_namespace_config_admission(db, namespace)
                            .await
                            .map_err(|_recovery_error| {
                                crate::admin::error_persistence_failure_redacted(
                                    "api_spec_namespace_admission_reacquire_after_late_write",
                                );
                                ApiSpecError::AdmissionUnavailable(
                                    "namespace config admission unavailable".to_string(),
                                )
                            })?;
                    if recovery_guard.immediately_succeeds_generation(lost_generation) {
                        return Ok(result);
                    }
                    if !compensate_after_intervening_write {
                        return Err(ApiSpecError::AdmissionUnavailable(
                            "namespace config admission unavailable".to_string(),
                        ));
                    }
                    match recovery_guard
                        .run_to_completion_while_held(compensation)
                        .await
                    {
                        Ok(crate::admin::crud::NamespaceConfigAdmissionCompletion::Held(Ok(
                            ApiSpecLateWriteRecovery::Retained,
                        ))) => return Ok(result),
                        Ok(crate::admin::crud::NamespaceConfigAdmissionCompletion::Held(Ok(
                            ApiSpecLateWriteRecovery::NotRetained,
                        ))) => {}
                        Ok(crate::admin::crud::NamespaceConfigAdmissionCompletion::Lost {
                            result: Ok(_),
                            error: _,
                        }) => {
                            crate::admin::error_persistence_failure_redacted(
                                "api_spec_late_write_compensation_admission_lost",
                            );
                        }
                        Ok(crate::admin::crud::NamespaceConfigAdmissionCompletion::Held(Err(
                            _,
                        )))
                        | Ok(crate::admin::crud::NamespaceConfigAdmissionCompletion::Lost {
                            result: Err(_),
                            ..
                        })
                        | Err(_) => {
                            crate::admin::error_persistence_failure_redacted(
                                "api_spec_late_write_compensation",
                            );
                        }
                    }
                    Err(ApiSpecError::AdmissionUnavailable(
                        "namespace config admission unavailable".to_string(),
                    ))
                }
                Err(error) => Err(classify_db_error(error)),
            }
        }
        Err(_error) => {
            crate::admin::warn_persistence_failure_redacted(
                "api_spec_namespace_admission_before_persist",
            );
            Err(ApiSpecError::AdmissionUnavailable(
                "namespace config admission unavailable".to_string(),
            ))
        }
    }
}

async fn stored_api_spec_bundle_matches(
    db: &dyn DatabaseBackend,
    bundle: &ExtractedBundle,
    spec: &ApiSpec,
) -> Result<bool, anyhow::Error> {
    let Some(current_spec) = db.get_api_spec(&spec.namespace, &spec.id).await? else {
        return Ok(false);
    };
    if current_spec.updated_at != spec.updated_at || current_spec.content_hash != spec.content_hash
    {
        return Ok(false);
    }
    let Some(current_proxy) = db
        .get_proxy_for_write(&spec.namespace, &bundle.proxy.id)
        .await?
    else {
        return Ok(false);
    };
    if current_proxy.updated_at != bundle.proxy.updated_at {
        return Ok(false);
    }
    if let Some(upstream) = bundle.upstream.as_ref() {
        let Some(current) = db.get_upstream(&spec.namespace, &upstream.id).await? else {
            return Ok(false);
        };
        if current.updated_at != upstream.updated_at {
            return Ok(false);
        }
    }
    for plugin in &bundle.plugins {
        let Some(current) = db.get_plugin_config(&spec.namespace, &plugin.id).await? else {
            return Ok(false);
        };
        if current.updated_at != plugin.updated_at {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn compensate_late_api_spec_create(
    db: Arc<dyn DatabaseBackend>,
    bundle: ExtractedBundle,
    spec: ApiSpec,
    state: &AdminState,
) -> Result<ApiSpecLateWriteRecovery, anyhow::Error> {
    if crate::admin::crud::current_transaction_log_schema_graph_is_valid(
        db.as_ref(),
        state,
        &spec.namespace,
    )
    .await?
    {
        return if stored_api_spec_bundle_matches(db.as_ref(), &bundle, &spec).await? {
            Ok(ApiSpecLateWriteRecovery::Retained)
        } else {
            Ok(ApiSpecLateWriteRecovery::NotRetained)
        };
    }
    match crate::admin::crud::validate_transaction_log_schema_api_spec_deletion_candidate(
        db.as_ref(),
        state,
        &spec.namespace,
        &spec,
    )
    .await
    {
        Ok(()) => {}
        Err(crate::admin::crud::AfterValidateError::BadRequest(errors))
        | Err(crate::admin::crud::AfterValidateError::Conflict(errors)) => anyhow::bail!(
            "late API-spec create compensation would leave an invalid transaction-log schema graph: {}",
            errors.join("; ")
        ),
        Err(crate::admin::crud::AfterValidateError::Db(error)) => return Err(error),
        Err(crate::admin::crud::AfterValidateError::Response(_)) => {
            anyhow::bail!("late API-spec create compensation validation returned an HTTP response")
        }
    }
    if !late_api_spec_create_compensation_safe(db.as_ref(), &bundle, &spec).await? {
        anyhow::bail!(
            "late API-spec create compensation found intervening resources attached to its proxy"
        );
    }
    if !db.delete_api_spec(&spec.namespace, &spec.id).await? {
        anyhow::bail!("late API-spec create compensation found no matching API spec");
    }
    Ok(ApiSpecLateWriteRecovery::NotRetained)
}

async fn late_api_spec_create_compensation_safe(
    db: &dyn DatabaseBackend,
    bundle: &ExtractedBundle,
    spec: &ApiSpec,
) -> Result<bool, anyhow::Error> {
    if !stored_api_spec_bundle_matches(db, bundle, spec).await? {
        return Ok(false);
    }
    let Some(current_proxy) = db
        .get_proxy_for_write(&spec.namespace, &bundle.proxy.id)
        .await?
    else {
        return Ok(false);
    };
    let expected_associations = bundle
        .proxy
        .plugins
        .iter()
        .map(|association| association.plugin_config_id.as_str())
        .collect::<HashSet<_>>();
    if current_proxy.plugins.len() != expected_associations.len()
        || current_proxy.plugins.iter().any(|association| {
            !expected_associations.contains(association.plugin_config_id.as_str())
        })
    {
        return Ok(false);
    }

    let expected_plugin_ids = bundle
        .plugins
        .iter()
        .map(|plugin| plugin.id.as_str())
        .collect::<HashSet<_>>();
    let mut offset = 0_i64;
    const PAGE_SIZE: i64 = 1_000;
    loop {
        let page = db
            .list_plugin_configs_paginated(&spec.namespace, PAGE_SIZE, offset)
            .await?;
        let items_len = page.items.len() as i64;
        if page.items.iter().any(|plugin| {
            plugin.proxy_id.as_deref() == Some(bundle.proxy.id.as_str())
                && !expected_plugin_ids.contains(plugin.id.as_str())
        }) {
            return Ok(false);
        }
        if items_len == 0 || offset + items_len >= page.total {
            return Ok(true);
        }
        offset += items_len;
    }
}

async fn compensate_late_api_spec_replace(
    db: Arc<dyn DatabaseBackend>,
    written_bundle: ExtractedBundle,
    written_spec: ApiSpec,
    previous_bundle: ExtractedBundle,
    previous_spec: ApiSpec,
    state: &AdminState,
) -> Result<ApiSpecLateWriteRecovery, anyhow::Error> {
    if crate::admin::crud::current_transaction_log_schema_graph_is_valid(
        db.as_ref(),
        state,
        &written_spec.namespace,
    )
    .await?
    {
        return if stored_api_spec_bundle_matches(db.as_ref(), &written_bundle, &written_spec)
            .await?
        {
            Ok(ApiSpecLateWriteRecovery::Retained)
        } else {
            Ok(ApiSpecLateWriteRecovery::NotRetained)
        };
    }
    match crate::admin::crud::validate_transaction_log_schema_api_spec_replacement_candidate(
        db.as_ref(),
        state,
        &written_spec.namespace,
        &written_spec,
        &previous_bundle.plugins,
    )
    .await
    {
        Ok(()) => {}
        Err(crate::admin::crud::AfterValidateError::BadRequest(errors))
        | Err(crate::admin::crud::AfterValidateError::Conflict(errors)) => anyhow::bail!(
            "late API-spec replacement compensation could not produce a valid transaction-log schema graph: {}",
            errors.join("; ")
        ),
        Err(crate::admin::crud::AfterValidateError::Db(error)) => return Err(error),
        Err(crate::admin::crud::AfterValidateError::Response(_)) => anyhow::bail!(
            "late API-spec replacement compensation validation returned an HTTP response"
        ),
    }
    if !stored_api_spec_bundle_matches(db.as_ref(), &written_bundle, &written_spec).await? {
        anyhow::bail!("late API-spec replacement no longer matches the written bundle");
    }
    db.replace_api_spec_bundle(&previous_bundle, &previous_spec)
        .await?;
    Ok(ApiSpecLateWriteRecovery::NotRetained)
}

async fn compensate_late_api_spec_delete(
    db: Arc<dyn DatabaseBackend>,
    previous_bundle: ExtractedBundle,
    previous_spec: ApiSpec,
    additional_upstreams: Vec<Upstream>,
    additional_plugins: Vec<crate::config::types::PluginConfig>,
    state: &AdminState,
) -> Result<ApiSpecLateWriteRecovery, anyhow::Error> {
    if crate::admin::crud::current_transaction_log_schema_graph_is_valid(
        db.as_ref(),
        state,
        &previous_spec.namespace,
    )
    .await?
    {
        let remains_deleted = db
            .get_api_spec(&previous_spec.namespace, &previous_spec.id)
            .await?
            .is_none()
            && db
                .get_proxy_for_write(&previous_spec.namespace, &previous_spec.proxy_id)
                .await?
                .is_none();
        return Ok(if remains_deleted {
            ApiSpecLateWriteRecovery::Retained
        } else {
            ApiSpecLateWriteRecovery::NotRetained
        });
    }
    if db
        .get_api_spec(&previous_spec.namespace, &previous_spec.id)
        .await?
        .is_some()
        || db
            .get_proxy_for_write(&previous_spec.namespace, &previous_spec.proxy_id)
            .await?
            .is_some()
    {
        return Ok(ApiSpecLateWriteRecovery::NotRetained);
    }
    let mut restored_plugins = previous_bundle.plugins.clone();
    restored_plugins.extend(additional_plugins.iter().cloned());
    match crate::admin::crud::validate_transaction_log_schema_candidates(
        db.as_ref(),
        state,
        &previous_spec.namespace,
        &restored_plugins,
        None,
    )
    .await
    {
        Ok(()) => {}
        Err(crate::admin::crud::AfterValidateError::BadRequest(errors))
        | Err(crate::admin::crud::AfterValidateError::Conflict(errors)) => anyhow::bail!(
            "late API-spec delete compensation could not restore a valid transaction-log schema graph: {}",
            errors.join("; ")
        ),
        Err(crate::admin::crud::AfterValidateError::Db(error)) => return Err(error),
        Err(crate::admin::crud::AfterValidateError::Response(_)) => {
            anyhow::bail!("late API-spec delete compensation validation returned an HTTP response")
        }
    }
    let validation_http_client = crate::admin::plugin_validation_http_client(state);
    db.restore_api_spec_bundle(
        &previous_bundle,
        &previous_spec,
        &additional_upstreams,
        &additional_plugins,
        &validation_http_client,
    )
    .await?;
    Ok(ApiSpecLateWriteRecovery::NotRetained)
}

fn is_row_missing_error_message(lower: &str) -> bool {
    lower.contains("row not found")
        || lower.contains("record not found")
        || lower.contains("document not found")
        || lower.contains("no rows returned")
        || lower.contains("no row returned")
}

// ---------------------------------------------------------------------------
// Helper: convert ApiSpecError → HTTP Response
// ---------------------------------------------------------------------------

fn error_response(err: ApiSpecError) -> Response<Full<Bytes>> {
    match err {
        ApiSpecError::PayloadTooLarge(max_mib) => json_resp(
            StatusCode::PAYLOAD_TOO_LARGE,
            &json!({"error": format!("Request body too large (max {} MiB)", max_mib)}),
        ),
        ApiSpecError::BodyTimedOut => json_resp(
            StatusCode::REQUEST_TIMEOUT,
            &json!({"error": "Request body read timed out"}),
        ),
        ApiSpecError::BodyCollect => json_resp(
            StatusCode::BAD_REQUEST,
            &json!({"error": "Failed to read request body"}),
        ),
        ApiSpecError::BadRequest(msg) => json_resp(StatusCode::BAD_REQUEST, &json!({"error": msg})),
        ApiSpecError::Extract(e) => {
            let code = extract_error_code(&e);
            // Parse-time errors (syntactically invalid or structurally missing
            // required fields) → 400 Bad Request.
            // Semantic-violation errors (valid structure but forbidden by
            // Ferrum policy) → 422 Unprocessable Entity, matching how the
            // ValidationFailures path behaves.
            let status = extract_error_status(&e);
            json_resp(
                status,
                &json!({
                    "error": "Spec parse failed",
                    "code": code,
                    "details": e.to_string()
                }),
            )
        }
        ApiSpecError::ValidationFailures {
            spec_version,
            failures,
        } => json_resp(
            StatusCode::UNPROCESSABLE_ENTITY,
            &json!({
                "error": "Spec validation failed",
                "spec_version": spec_version,
                "failures": failures
            }),
        ),
        ApiSpecError::NotFound => json_resp(
            StatusCode::NOT_FOUND,
            &json!({"error": "API spec not found"}),
        ),
        ApiSpecError::Conflict(_detail) => {
            crate::admin::warn_persistence_failure_redacted("api_spec_conflict");
            json_resp(
                StatusCode::CONFLICT,
                &json!({
                    "error": "Resource conflict — the operation collides with an existing row (likely a duplicate id, name, or unique constraint)"
                }),
            )
        }
        ApiSpecError::MongoDocTooLarge => json_resp(
            StatusCode::PAYLOAD_TOO_LARGE,
            &json!({"error": "Spec document exceeds MongoDB document size limit"}),
        ),
        ApiSpecError::Unprocessable(_detail) => {
            crate::admin::warn_persistence_failure_redacted("api_spec_unprocessable");
            json_resp(
                StatusCode::UNPROCESSABLE_ENTITY,
                &json!({
                    "error": "The submitted spec references a resource that does not exist or violates referential integrity"
                }),
            )
        }
        ApiSpecError::PluginComposition(errors) => json_resp(
            StatusCode::UNPROCESSABLE_ENTITY,
            &json!({
                "error": "Spec validation failed",
                "failures": [{
                    "resource_type": "plugin_composition",
                    "errors": errors,
                }]
            }),
        ),
        ApiSpecError::NoDatabase => json_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            &json!({"error": "No database configured"}),
        ),
        ApiSpecError::AdmissionUnavailable(_detail) => {
            crate::admin::warn_persistence_failure_redacted("api_spec_admission_unavailable");
            crate::admin::mtls_dns_admission_unavailable_response()
        }
        ApiSpecError::Internal(_msg) => {
            crate::admin::error_persistence_failure_redacted("api_spec_internal");
            json_resp(
                StatusCode::INTERNAL_SERVER_ERROR,
                &json!({"error": "Internal server error"}),
            )
        }
    }
}

/// Short discriminant string for `ExtractError` variants.
fn extract_error_code(e: &ExtractError) -> &'static str {
    match e {
        ExtractError::InvalidJson(_) => "InvalidJson",
        ExtractError::InvalidYaml(_) => "InvalidYaml",
        ExtractError::UnknownVersion => "UnknownVersion",
        ExtractError::MissingProxyExtension => "MissingProxyExtension",
        ExtractError::MalformedExtension { .. } => "MalformedExtension",
        ExtractError::ConsumerExtensionNotAllowed => "ConsumerExtensionNotAllowed",
        ExtractError::PluginInvalidScope { .. } => "PluginInvalidScope",
        ExtractError::PluginProxyIdMismatch { .. } => "PluginProxyIdMismatch",
        ExtractError::PluginContainsCredentials { .. } => "PluginContainsCredentials",
        ExtractError::ProxyUpstreamIdMismatch { .. } => "ProxyUpstreamIdMismatch",
        ExtractError::InvalidTagName { .. } => "InvalidTagName",
        ExtractError::UnsupportedExternalRef { .. } => "UnsupportedExternalRef",
        ExtractError::SchemaReference(_) => "SchemaReference",
        ExtractError::SchemaTooDeep { .. } => "SchemaTooDeep",
    }
}

/// HTTP status code for an `ExtractError`.
///
/// Parse-time / structural errors → 400 Bad Request (the document is malformed
/// or missing required fields at the syntax level).
///
/// Semantic-violation errors → 422 Unprocessable Entity (the document is
/// syntactically valid but violates Ferrum policy rules, just like
/// `ValidationFailures` which already returns 422).
fn extract_error_status(e: &ExtractError) -> StatusCode {
    match e {
        // Parse-time / structural: 400
        ExtractError::InvalidJson(_)
        | ExtractError::InvalidYaml(_)
        | ExtractError::UnknownVersion
        | ExtractError::MissingProxyExtension
        | ExtractError::MalformedExtension { .. } => StatusCode::BAD_REQUEST,
        // Semantic violations: 422
        ExtractError::ConsumerExtensionNotAllowed
        | ExtractError::PluginInvalidScope { .. }
        | ExtractError::PluginProxyIdMismatch { .. }
        | ExtractError::PluginContainsCredentials { .. }
        | ExtractError::ProxyUpstreamIdMismatch { .. }
        | ExtractError::InvalidTagName { .. }
        | ExtractError::UnsupportedExternalRef { .. }
        | ExtractError::SchemaReference(_)
        | ExtractError::SchemaTooDeep { .. } => StatusCode::UNPROCESSABLE_ENTITY,
    }
}

// ---------------------------------------------------------------------------
// Helper: parse Content-Type → SpecFormat
// ---------------------------------------------------------------------------

/// Parse the `Content-Type` header into a `SpecFormat` hint.
///
/// Accepts:
///   - `application/json`               → `Some(Json)`
///   - `application/yaml`               → `Some(Yaml)`
///   - `application/x-yaml`             → `Some(Yaml)`
///   - `text/yaml`                      → `Some(Yaml)`
///   - `text/x-yaml`                    → `Some(Yaml)`
///   - anything else / missing          → `None` (autodetect)
pub(super) fn parse_content_type(headers: &hyper::HeaderMap) -> Option<SpecFormat> {
    let ct = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Strip parameters (e.g. `application/json; charset=utf-8`)
    let mime = ct.split(';').next().unwrap_or("").trim();
    // RFC 7231 §3.1.1.1: media type tokens are case-insensitive.
    let mime_lower = mime.to_ascii_lowercase();
    match mime_lower.as_str() {
        "application/json" => Some(SpecFormat::Json),
        "application/yaml" | "application/x-yaml" | "text/yaml" | "text/x-yaml" => {
            Some(SpecFormat::Yaml)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Helper: Accept header negotiation for GET responses
// ---------------------------------------------------------------------------

/// Resolve the response format from an `Accept` header vs the stored format.
///
/// Returns the `SpecFormat` the caller should use to serialise the body.
///
/// Rules:
/// - Missing, `*/*`, or matching stored format → stored format
/// - `application/json` and stored is YAML     → Json (convert)
/// - `application/yaml` / `text/yaml` etc. and stored is JSON → Yaml (convert)
/// - Unknown accept types                       → stored format (best-effort)
///
/// Quality weight for a media range, parsed from `;q=N.NNN`.
/// Returns a value in `[0, 1000]` (1000 = q=1.0, default).
///
/// Module-level so both `negotiate_accept` and `negotiate_accept_or_406`
/// share the same parser (avoids duplication).
fn parse_accept_quality(params: &str) -> u32 {
    for param in params.split(';') {
        let p = param.trim();
        // Parse up to 3 decimal places; clamp to [0, 1000].
        if let Some(rest) = p.strip_prefix("q=").or_else(|| p.strip_prefix("Q="))
            && let Ok(f) = rest.parse::<f64>()
        {
            return (f * 1000.0).round().clamp(0.0, 1000.0) as u32;
        }
    }
    1000 // default q=1.0
}

/// Uses a small media-range parser: splits on `,`, strips `q=` quality
/// parameters, trims whitespace, and compares exact tokens.  Wildcards
/// (`*/*`, `application/*`) accept the stored format.  Highest-quality
/// match wins; ties resolve to the first listed entry.
pub(super) fn negotiate_accept(headers: &hyper::HeaderMap, stored: SpecFormat) -> SpecFormat {
    let accept = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if accept.is_empty() {
        return stored;
    }

    let mut best_json: Option<u32> = None;
    let mut best_yaml: Option<u32> = None;
    let mut best_wildcard: Option<u32> = None;
    let mut best_stored: Option<u32> = None;

    for entry in accept.split(',') {
        // Split type/subtype from parameters.
        let mut parts = entry.splitn(2, ';');
        let media_type_raw = parts.next().unwrap_or("").trim();
        let params = parts.next().unwrap_or("");
        let q = parse_accept_quality(params);

        // RFC 7231 §3.1.1.1: media type tokens (type/subtype) are
        // case-insensitive. Normalize before matching so that headers like
        // `Accept: Application/JSON` are recognized.
        let media_type = media_type_raw.to_ascii_lowercase();

        match media_type.as_str() {
            "*/*" | "application/*" if best_wildcard.is_none_or(|prev| q > prev) => {
                best_wildcard = Some(q);
            }
            "application/json" if best_json.is_none_or(|prev| q > prev) => {
                best_json = Some(q);
            }
            "application/yaml" | "application/x-yaml" | "text/yaml" | "text/x-yaml"
                if best_yaml.is_none_or(|prev| q > prev) =>
            {
                best_yaml = Some(q);
            }
            m if m
                == match stored {
                    SpecFormat::Json => "application/json",
                    SpecFormat::Yaml => "application/yaml",
                }
                && best_stored.is_none_or(|prev| q > prev) =>
            {
                best_stored = Some(q);
            }
            _ => {} // unknown media type — ignored
        }
    }

    // Compute effective per-format quality, honoring RFC 7231 §5.3.2:
    //   - An explicit `q=0` for a media range means the client refuses that
    //     representation; the wildcard fallback does NOT override it.
    //   - An absent media range falls back to the wildcard quality if any.
    //   - The exact-stored bucket is treated like an explicit listing of the
    //     stored format.
    let wildcard_q = best_wildcard.unwrap_or(0);

    // For each format: explicit value (incl. q=0) wins; otherwise inherit wildcard.
    let json_explicit = best_json.or(if stored == SpecFormat::Json {
        best_stored
    } else {
        None
    });
    let yaml_explicit = best_yaml.or(if stored == SpecFormat::Yaml {
        best_stored
    } else {
        None
    });

    let json_q = json_explicit.unwrap_or(wildcard_q);
    let yaml_q = yaml_explicit.unwrap_or(wildcard_q);

    // Did the client mention any of OUR buckets at all? (json/yaml/wildcard
    // /exact-stored). If not, we default to stored as before — RFC permits
    // serving any representation when no Accept rules match.
    let saw_relevant = best_json.is_some()
        || best_yaml.is_some()
        || best_wildcard.is_some()
        || best_stored.is_some();
    if !saw_relevant {
        return stored;
    }

    // If the client mentioned our buckets but every effective quality is 0,
    // they have explicitly rejected every representation we can serve. Signal
    // this by returning the stored format — but the caller is expected to
    // detect "all q=0" and translate to 406 Not Acceptable. Today the caller
    // only wires 406 on conversion failure; an explicit 406-on-q=0 path lives
    // in the public wrapper below.
    //
    // Pick the highest non-zero effective quality. Ties go to stored.
    if json_q == 0 && yaml_q == 0 {
        // Neither format is acceptable. The public wrapper interprets this
        // by returning None instead.
        return stored; // sentinel; the wrapper detects this case via accept_acceptable.
    }

    if json_q > yaml_q {
        SpecFormat::Json
    } else if yaml_q > json_q {
        SpecFormat::Yaml
    } else {
        // Equal qualities — prefer stored.
        stored
    }
}

/// Returns `None` when the client's `Accept` header explicitly rejects every
/// representation the server can serve (all relevant buckets at `q=0`). The
/// caller should respond with 406 Not Acceptable in that case.
///
/// Returns `Some(format)` otherwise — either the negotiated format, or the
/// stored format as a default when no relevant `Accept` entries were sent.
pub(super) fn negotiate_accept_or_406(
    headers: &hyper::HeaderMap,
    stored: SpecFormat,
) -> Option<SpecFormat> {
    let accept = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    if accept.is_empty() {
        return Some(stored);
    }

    // Re-parse here to detect the "all explicit q=0" case without
    // duplicating the arithmetic in `negotiate_accept`. Cheap (single
    // pass over a short string).
    let mut saw_relevant = false;
    let mut json_explicit: Option<u32> = None;
    let mut yaml_explicit: Option<u32> = None;
    let mut wildcard_q: Option<u32> = None;

    for entry in accept.split(',') {
        let mut parts = entry.splitn(2, ';');
        let mt = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let q = parse_accept_quality(parts.next().unwrap_or(""));
        match mt.as_str() {
            "*/*" | "application/*" => {
                saw_relevant = true;
                wildcard_q = Some(wildcard_q.map_or(q, |p| p.max(q)));
            }
            "application/json" => {
                saw_relevant = true;
                json_explicit = Some(json_explicit.map_or(q, |p| p.max(q)));
            }
            "application/yaml" | "application/x-yaml" | "text/yaml" | "text/x-yaml" => {
                saw_relevant = true;
                yaml_explicit = Some(yaml_explicit.map_or(q, |p| p.max(q)));
            }
            _ => {} // unknown — ignored for relevance accounting
        }
    }

    if !saw_relevant {
        // No relevant Accept entries (e.g. `Accept: text/plain`). Use the
        // stored format.
        return Some(stored);
    }

    // Effective q per format: explicit wins (including explicit q=0), else
    // fall back to wildcard.
    let wq = wildcard_q.unwrap_or(0);
    let json_q = json_explicit.unwrap_or(wq);
    let yaml_q = yaml_explicit.unwrap_or(wq);

    if json_q == 0 && yaml_q == 0 {
        // Every representation the server can serve has been explicitly
        // rejected. RFC 7231: respond with 406 Not Acceptable.
        return None;
    }

    Some(negotiate_accept(headers, stored))
}

#[cfg(test)]
mod negotiate_accept_tests {
    use super::*;

    fn headers_with_accept(accept: &str) -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        h.insert(
            "accept",
            hyper::header::HeaderValue::from_str(accept).unwrap(),
        );
        h
    }

    #[test]
    fn negotiate_accept_exact_json() {
        let h = headers_with_accept("application/json");
        assert_eq!(
            negotiate_accept(&h, SpecFormat::Yaml),
            SpecFormat::Json,
            "application/json must select JSON even when stored is YAML"
        );
    }

    #[test]
    fn negotiate_accept_exact_yaml() {
        let h = headers_with_accept("application/yaml");
        assert_eq!(
            negotiate_accept(&h, SpecFormat::Json),
            SpecFormat::Yaml,
            "application/yaml must select YAML even when stored is JSON"
        );
    }

    #[test]
    fn negotiate_accept_does_not_match_jsonpath_plus_json() {
        // "application/jsonpath+json" contains "application/json" as a
        // substring; the old `contains()` check would have matched it.
        let h = headers_with_accept("application/jsonpath+json");
        // Unknown media type → fall back to stored format.
        assert_eq!(
            negotiate_accept(&h, SpecFormat::Yaml),
            SpecFormat::Yaml,
            "application/jsonpath+json must NOT trigger JSON negotiation"
        );
    }

    #[test]
    fn negotiate_accept_wildcard() {
        let h = headers_with_accept("*/*");
        assert_eq!(
            negotiate_accept(&h, SpecFormat::Yaml),
            SpecFormat::Yaml,
            "*/* must return stored format"
        );
        assert_eq!(
            negotiate_accept(&h, SpecFormat::Json),
            SpecFormat::Json,
            "*/* must return stored format"
        );
    }

    #[test]
    fn negotiate_accept_quality_ordering() {
        // YAML at q=0.9, JSON at q=1.0 — JSON wins.
        let h = headers_with_accept("application/yaml;q=0.9, application/json;q=1.0");
        assert_eq!(
            negotiate_accept(&h, SpecFormat::Yaml),
            SpecFormat::Json,
            "highest-quality type must win"
        );
        // JSON at q=0.5, YAML at q=0.9 — YAML wins.
        let h2 = headers_with_accept("application/json;q=0.5, application/yaml;q=0.9");
        assert_eq!(
            negotiate_accept(&h2, SpecFormat::Json),
            SpecFormat::Yaml,
            "highest-quality type must win"
        );
    }

    /// RFC 7231 §3.1.1.1 says media type tokens are case-insensitive.
    /// Standards-compliant clients may send mixed-case tokens; we must
    /// normalize before matching.
    #[test]
    fn negotiate_accept_is_case_insensitive() {
        // Mixed-case JSON
        let h = headers_with_accept("Application/JSON");
        assert_eq!(negotiate_accept(&h, SpecFormat::Yaml), SpecFormat::Json);
        // Upper-case YAML variant
        let h = headers_with_accept("APPLICATION/X-YAML");
        assert_eq!(negotiate_accept(&h, SpecFormat::Json), SpecFormat::Yaml);
        // Mixed-case wildcard
        let h = headers_with_accept("Application/*");
        assert_eq!(negotiate_accept(&h, SpecFormat::Yaml), SpecFormat::Yaml);
        // Mixed-case quality parameter still parses
        let h = headers_with_accept("application/yaml;Q=0.5, Application/JSON;q=1.0");
        assert_eq!(
            negotiate_accept(&h, SpecFormat::Yaml),
            SpecFormat::Json,
            "case-insensitive parsing must coexist with quality ordering"
        );
    }

    #[test]
    fn negotiate_accept_missing_or_empty_returns_stored_format() {
        let empty = hyper::HeaderMap::new();
        assert_eq!(
            negotiate_accept(&empty, SpecFormat::Json),
            SpecFormat::Json,
            "missing Accept must return stored format"
        );
        let h = headers_with_accept("");
        assert_eq!(
            negotiate_accept(&h, SpecFormat::Yaml),
            SpecFormat::Yaml,
            "empty Accept must return stored format"
        );
    }

    /// `Accept: application/json;q=0` explicitly refuses JSON. With no other
    /// acceptable format mentioned, RFC 7231 says respond 406 — encoded by
    /// `negotiate_accept_or_406` returning `None`.
    #[test]
    fn negotiate_accept_or_406_explicit_q0_returns_none() {
        let h = headers_with_accept("application/json;q=0");
        assert_eq!(
            negotiate_accept_or_406(&h, SpecFormat::Json),
            None,
            "explicit q=0 on stored format with no fallback must yield None (→ 406)"
        );
        // `Accept: */*;q=0` rejects every representation.
        let h = headers_with_accept("*/*;q=0");
        assert_eq!(
            negotiate_accept_or_406(&h, SpecFormat::Yaml),
            None,
            "wildcard q=0 must yield None (→ 406)"
        );
    }

    /// q=0 on one format must NOT poison the other format's wildcard fallback.
    #[test]
    fn negotiate_accept_or_406_q0_one_format_serves_the_other() {
        let h = headers_with_accept("application/json;q=0, application/yaml;q=1");
        assert_eq!(
            negotiate_accept_or_406(&h, SpecFormat::Json),
            Some(SpecFormat::Yaml),
            "explicit q=0 on JSON must not block YAML"
        );
    }

    /// Empty / missing Accept and unknown-only Accept fall back to stored —
    /// this is RFC-permitted default behavior, not a 406 case.
    #[test]
    fn negotiate_accept_or_406_default_to_stored_when_no_relevant_entries() {
        let empty = hyper::HeaderMap::new();
        assert_eq!(
            negotiate_accept_or_406(&empty, SpecFormat::Yaml),
            Some(SpecFormat::Yaml),
            "missing Accept must default to stored"
        );
        let h = headers_with_accept("text/plain");
        assert_eq!(
            negotiate_accept_or_406(&h, SpecFormat::Json),
            Some(SpecFormat::Json),
            "Accept with only unrelated types must default to stored"
        );
    }
}

/// Content-Type string for a `SpecFormat`.
fn content_type_for_format(fmt: SpecFormat) -> &'static str {
    match fmt {
        SpecFormat::Json => "application/json",
        SpecFormat::Yaml => "application/yaml",
    }
}

/// Convert spec bytes between formats.
///
/// Returns `Err` if the conversion fails (malformed source document).
fn convert_format(body: &[u8], from: SpecFormat, to: SpecFormat) -> Result<Vec<u8>, String> {
    if from == to {
        return Ok(body.to_vec());
    }
    match (from, to) {
        (SpecFormat::Yaml, SpecFormat::Json) => {
            let val: serde_yaml::Value = serde_yaml::from_slice(body)
                .map_err(|e| format!("YAML parse error during conversion: {e}"))?;
            let jv: serde_json::Value = serde_json::to_value(val)
                .map_err(|e| format!("YAML→JSON conversion error: {e}"))?;
            let mut budget = MAX_YAML_EXPANDED_NODES;
            if !count_value_nodes(&jv, &mut budget) {
                return Err(
                    "YAML alias expansion exceeds node limit during conversion; \
                     retrieve the stored YAML representation instead"
                        .to_string(),
                );
            }
            serde_json::to_vec_pretty(&jv).map_err(|e| format!("JSON serialization error: {e}"))
        }
        (SpecFormat::Json, SpecFormat::Yaml) => {
            let jv: serde_json::Value = serde_json::from_slice(body)
                .map_err(|e| format!("JSON parse error during conversion: {e}"))?;
            serde_yaml::to_string(&jv)
                .map(|s| s.into_bytes())
                .map_err(|e| format!("YAML serialization error: {e}"))
        }
        _ => Err(format!(
            "unsupported format conversion {:?} → {:?}",
            from, to
        )),
    }
}

// ---------------------------------------------------------------------------
// Helper: collect body with a size limit
// ---------------------------------------------------------------------------

async fn collect_body(
    req: Request<Incoming>,
    max_mib: usize,
    idle_timeout_seconds: u64,
) -> Result<Vec<u8>, ApiSpecError> {
    let max_bytes = max_mib.saturating_mul(1024).saturating_mul(1024);
    match crate::admin::body::collect_admin_body(req.into_body(), max_bytes, idle_timeout_seconds)
        .await
    {
        Ok(bytes) => Ok(bytes),
        Err(crate::admin::body::AdminBodyError::TooLarge) => {
            Err(ApiSpecError::PayloadTooLarge(max_mib))
        }
        Err(crate::admin::body::AdminBodyError::TimedOut) => Err(ApiSpecError::BodyTimedOut),
        Err(crate::admin::body::AdminBodyError::Read(e)) => {
            tracing::warn!(error = %e, "failed to read api spec request body");
            Err(ApiSpecError::BodyCollect)
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: require DB
// ---------------------------------------------------------------------------

fn require_db(state: &AdminState) -> Result<&Arc<dyn DatabaseBackend>, ApiSpecError> {
    state.db.as_ref().ok_or(ApiSpecError::NoDatabase)
}

// ---------------------------------------------------------------------------
// ID assignment helpers (Fix 1 — PUT idempotency)
// ---------------------------------------------------------------------------

/// Assign IDs to bundle resources for the POST path.
///
/// For each resource (proxy, upstream, plugins) with an empty `id`, mints a
/// new UUID. Re-links cross-references so `plugin.proxy_id` and
/// `proxy.upstream_id` always reference the final IDs. Rebuilds the proxy
/// `plugins` association list to reference the final plugin IDs.
///
/// Also stamps server-side `created_at`/`updated_at` timestamps so any
/// operator-supplied timestamps in the spec document are ignored — the
/// polling cycle's incremental delta path uses `updated_at > since`, and
/// stale embedded timestamps would cause real config changes to be skipped.
fn assign_ids_for_post(bundle: &mut ExtractedBundle) {
    // Proxy
    if bundle.proxy.id.is_empty() {
        bundle.proxy.id = Uuid::new_v4().to_string();
    }

    // Upstream
    if let Some(ref mut u) = bundle.upstream
        && u.id.is_empty()
    {
        u.id = Uuid::new_v4().to_string();
    }

    // Plugins — assign IDs then re-link proxy_id
    for pc in &mut bundle.plugins {
        if pc.id.is_empty() {
            pc.id = Uuid::new_v4().to_string();
        }
        pc.proxy_id = Some(bundle.proxy.id.clone());
    }

    // Re-link proxy.upstream_id
    if let Some(ref u) = bundle.upstream
        && bundle.proxy.upstream_id.as_deref().unwrap_or("").is_empty()
    {
        bundle.proxy.upstream_id = Some(u.id.clone());
    }

    // Stamp server-side timestamps (Fix 1). Mirrors handle_write's convention:
    //   Create → set_created_at(now) + set_updated_at(now).
    // This overwrites any operator-embedded timestamps from the spec document.
    let now = Utc::now();
    bundle.proxy.created_at = now;
    bundle.proxy.updated_at = now;
    if let Some(ref mut u) = bundle.upstream {
        u.created_at = now;
        u.updated_at = now;
    }
    for pc in &mut bundle.plugins {
        pc.created_at = now;
        pc.updated_at = now;
    }

    // Rebuild proxy.plugins association list with final plugin IDs.
    // Preserve any operator-written associations pointing to pre-existing
    // plugins (non-empty IDs that are NOT in bundle.plugins are left as-is).
    let spec_plugin_ids: Vec<String> = bundle.plugins.iter().map(|p| p.id.clone()).collect();
    // Remove stale associations that used the now-replaced empty IDs, then
    // add the final ones. The simplest safe approach: keep associations whose
    // plugin_config_id is non-empty and NOT an empty-string leftover, then
    // merge in the spec-extracted final IDs.
    let mut assocs: Vec<PluginAssociation> = bundle
        .proxy
        .plugins
        .drain(..)
        .filter(|a| {
            // Keep operator-written associations to pre-existing plugins
            // (non-empty IDs that are not in the spec-extracted list).
            !a.plugin_config_id.is_empty() && !spec_plugin_ids.contains(&a.plugin_config_id)
        })
        .collect();
    for id in &spec_plugin_ids {
        if !assocs.iter().any(|a| &a.plugin_config_id == id) {
            assocs.push(PluginAssociation {
                plugin_config_id: id.clone(),
            });
        }
    }
    bundle.proxy.plugins = assocs;
}

/// Assign IDs to bundle resources for the PUT path, reusing existing stored
/// IDs where the spec leaves IDs empty so re-submitting the same ID-less spec
/// is idempotent.
///
/// Matching strategy:
/// - `proxy.id`: always use `existing_proxy_id` (the same-proxy-id rule
///   enforces this anyway; if the spec sets a non-matching proxy.id
///   explicitly, the immutability check catches it later).
/// - `upstream.id`: if empty, reuse the existing upstream tagged with this
///   api_spec_id if present, else mint UUID.
/// - `plugin.id`: if empty, match by canonical `(plugin_name, config_json,
///   priority_override)` tuple against existing spec-owned plugins (Fix 5).
///   If two extracted plugins share the same plugin_name with DIFFERENT
///   configs, explicit IDs are required — returns a structured error.
///   If they share the same name AND identical canonical config, falls back
///   to FIFO ordering (deterministic index pairing). If no match found, mints
///   a new UUID.
/// - For non-empty extracted IDs, leave as-is — operator opted in.
///
/// Also stamps server-side timestamps (Fix 1): `updated_at = now` always;
/// `created_at` is preserved from the stored row on PUT, or set to `now` for
/// genuinely new resources introduced by this PUT.
///
/// After ID assignment, re-links: `proxy.upstream_id = upstream.id` (if
/// present); `plugin.proxy_id = proxy.id`; rebuilds `proxy.plugins`
/// association list to reference the final plugin IDs.
async fn assign_ids_for_put(
    bundle: &mut ExtractedBundle,
    db: &Arc<dyn DatabaseBackend>,
    namespace: &str,
    existing_spec: &ApiSpec,
    existing_spec_upstream: Option<&Upstream>,
    spec_version: &str,
) -> Result<(), ApiSpecError> {
    // If proxy.id is empty (operator did not supply one), fill it in from
    // the existing spec so the resource hash + immutability check work correctly.
    // If the operator supplied a non-empty proxy.id, leave it; the immutability
    // check downstream will reject it if it differs from existing_spec.proxy_id.
    if bundle.proxy.id.is_empty() {
        bundle.proxy.id = existing_spec.proxy_id.clone();
    }

    // Load the existing proxy to get upstream_id and created_at.
    let existing_proxy = match db
        .get_proxy_for_write(namespace, &existing_spec.proxy_id)
        .await
    {
        Ok(Some(p)) => Some(p),
        Ok(None) => None,
        Err(e) => return Err(classify_db_error(e)),
    };

    // Upstream ID: reuse the existing spec-owned upstream if empty. Do not use
    // the current proxy.upstream_id here; direct admin CRUD can drift that
    // pointer to a hand-managed upstream while preserving proxy.api_spec_id.
    if let Some(ref mut u) = bundle.upstream
        && u.id.is_empty()
    {
        let reuse_id = existing_spec_upstream
            .map(|u| u.id.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        u.id = reuse_id.unwrap_or_else(|| Uuid::new_v4().to_string());
    }

    // Load existing spec-owned plugins for canonical-tuple matching (Fix 5).
    let mut existing_plugins = match db
        .list_spec_owned_plugin_configs(namespace, &existing_spec.id)
        .await
    {
        Ok(v) => v,
        Err(e) => return Err(classify_db_error(e)),
    };
    if let Some(existing_proxy) = existing_proxy.as_ref() {
        let assoc_order: std::collections::HashMap<String, usize> = existing_proxy
            .plugins
            .iter()
            .enumerate()
            .map(|(idx, assoc)| (assoc.plugin_config_id.clone(), idx))
            .collect();
        existing_plugins.sort_by(|a, b| {
            assoc_order
                .get(&a.id)
                .copied()
                .unwrap_or(usize::MAX)
                .cmp(&assoc_order.get(&b.id).copied().unwrap_or(usize::MAX))
                .then_with(|| a.created_at.cmp(&b.created_at))
                .then_with(|| a.id.cmp(&b.id))
        });
    }

    // Build a map from canonical key → FIFO queue of existing plugins.
    // Canonical key = (plugin_name, sorted-keys config JSON, priority_override).
    let mut canonical_to_existing: std::collections::HashMap<
        (String, String, Option<u16>),
        std::collections::VecDeque<&crate::config::types::PluginConfig>,
    > = std::collections::HashMap::new();
    for ep in &existing_plugins {
        let key = plugin_canonical_key(ep)?;
        canonical_to_existing.entry(key).or_default().push_back(ep);
    }

    // Snapshot proxy_id before the mutable plugin loop to avoid split borrows.
    let proxy_id_snap = bundle.proxy.id.clone();

    // Assign plugin IDs in two passes (Fix 5 canonical matching, refined to
    // tolerate one unmatched duplicate per name — see PR review at HEAD
    // cf7ebc9).
    //
    // Pass 1: try to canonically match each empty-id plugin to a stored
    // spec-owned plugin. Buffer the assignments. Track which names have
    // multiple UNMATCHED entries — those are the genuinely ambiguous cases.
    //
    // Pass 2: walk the buffered assignments; for unmatched entries, mint a
    // UUID when the name has only one unmatched entry (an unambiguous "new
    // instance" addition), or reject when the same name has multiple
    // unmatched entries with different configs (the original Fix 5 case —
    // operator must use explicit IDs to disambiguate).
    let mut assigned_ids: Vec<Option<String>> = Vec::with_capacity(bundle.plugins.len());
    let mut unmatched_configs_per_name: std::collections::HashMap<
        String,
        std::collections::HashSet<String>,
    > = std::collections::HashMap::new();

    for pc in &bundle.plugins {
        if !pc.id.is_empty() {
            assigned_ids.push(Some(pc.id.clone()));
            continue;
        }
        let key = plugin_canonical_key(pc)?;
        if let Some(q) = canonical_to_existing.get_mut(&key)
            && let Some(matched) = q.pop_front()
        {
            assigned_ids.push(Some(matched.id.clone()));
            continue;
        }
        // Unmatched — record the canonical config for ambiguity detection.
        assigned_ids.push(None);
        unmatched_configs_per_name
            .entry(pc.plugin_name.clone())
            .or_default()
            .insert(key.1.clone());
    }

    for (pc, slot) in bundle.plugins.iter_mut().zip(assigned_ids.iter()) {
        pc.proxy_id = Some(proxy_id_snap.clone());
        match slot {
            Some(id) => {
                pc.id = id.clone();
            }
            None => {
                // Reject only when multiple unmatched entries for the same
                // name have DIFFERENT canonical configs — those are genuinely
                // ambiguous. Multiple unmatched entries with identical configs
                // (e.g. adding two instances of the same plugin) are safe to
                // mint fresh UUIDs for since they are interchangeable.
                let distinct = unmatched_configs_per_name
                    .get(&pc.plugin_name)
                    .map_or(0, |s| s.len());
                if distinct > 1 {
                    return Err(ApiSpecError::ValidationFailures {
                        spec_version: spec_version.to_string(),
                        failures: vec![ValidationFailure {
                            resource_type: "plugin",
                            id: proxy_id_snap.clone(),
                            errors: vec![format!(
                                "duplicate plugin_name '{}' on PUT with no canonical match \
                                 requires explicit ids to disambiguate; set a non-empty 'id' \
                                 on each instance whose config differs from any stored entry",
                                pc.plugin_name
                            )],
                        }],
                    });
                }
                pc.id = Uuid::new_v4().to_string();
            }
        }
    }

    // Re-link proxy.upstream_id.
    if let Some(ref u) = bundle.upstream
        && bundle.proxy.upstream_id.as_deref().unwrap_or("").is_empty()
    {
        bundle.proxy.upstream_id = Some(u.id.clone());
    }

    // Stamp server-side timestamps (Fix 1). Mirrors handle_write's convention:
    //   Update → set_updated_at(now), preserve created_at from stored row.
    let now = Utc::now();

    // Proxy: preserve stored created_at, refresh updated_at.
    bundle.proxy.updated_at = now;
    bundle.proxy.created_at = existing_proxy.as_ref().map(|p| p.created_at).unwrap_or(now);

    // Upstream: preserve existing created_at if the same ID is being reused.
    if let Some(ref mut u) = bundle.upstream {
        u.updated_at = now;
        // If the upstream ID matches what was previously stored, preserve its
        // created_at. Otherwise (new upstream) use now.
        if let Some(stored_upstream) = existing_spec_upstream.filter(|stored| stored.id == u.id) {
            u.created_at = stored_upstream.created_at;
        } else {
            u.created_at = now;
        }
    }

    // Plugins: for each plugin, if we reused an existing stored ID, preserve
    // that plugin's created_at. For genuinely new plugins, use now.
    let existing_plugin_map: std::collections::HashMap<&str, &crate::config::types::PluginConfig> =
        existing_plugins
            .iter()
            .map(|ep| (ep.id.as_str(), ep))
            .collect();
    for pc in &mut bundle.plugins {
        pc.updated_at = now;
        pc.created_at = existing_plugin_map
            .get(pc.id.as_str())
            .map(|ep| ep.created_at)
            .unwrap_or(now);
    }

    // Rebuild proxy.plugins association list with final plugin IDs.
    let spec_plugin_ids: Vec<String> = bundle.plugins.iter().map(|p| p.id.clone()).collect();
    let mut assocs: Vec<PluginAssociation> = bundle
        .proxy
        .plugins
        .drain(..)
        .filter(|a| {
            !a.plugin_config_id.is_empty() && !spec_plugin_ids.contains(&a.plugin_config_id)
        })
        .collect();
    for id in &spec_plugin_ids {
        if !assocs.iter().any(|a| &a.plugin_config_id == id) {
            assocs.push(PluginAssociation {
                plugin_config_id: id.clone(),
            });
        }
    }
    bundle.proxy.plugins = assocs;

    Ok(())
}

async fn load_single_spec_owned_upstream(
    db: &Arc<dyn DatabaseBackend>,
    namespace: &str,
    spec_id: &str,
) -> Result<Option<Upstream>, ApiSpecError> {
    let upstreams = db
        .list_spec_owned_upstreams(namespace, spec_id)
        .await
        .map_err(classify_db_error)?;
    match upstreams.len() {
        0 => Ok(None),
        1 => Ok(upstreams.into_iter().next()),
        n => Err(ApiSpecError::Internal(format!(
            "api_spec '{}' owns {} upstreams; expected at most one",
            spec_id, n
        ))),
    }
}

/// Maximum recursion depth for [`sort_json_keys`].
///
/// Matches [`MAX_FORBIDDEN_KEY_SCAN_DEPTH`] in `extractor.rs` (32).  Plugin
/// configs nested deeper than this are rejected rather than allowing unbounded
/// stack growth.  A depth-32 config is already far beyond anything a real plugin
/// would use.
const MAX_SORT_JSON_DEPTH: usize = 32;

/// Compute the canonical matching key for a plugin during PUT id-assignment.
///
/// The key is `(plugin_name, sorted-keys config JSON, priority_override)`.
/// Sorting JSON object keys via a `BTreeMap` round-trip ensures two configs
/// with the same key-value pairs but different insertion order compare equal,
/// which is necessary for idempotent re-submission of specs produced by
/// different tooling.
///
/// Returns `Err` if the config is nested more than [`MAX_SORT_JSON_DEPTH`]
/// levels or if JSON serialisation fails (neither should happen in practice;
/// both are treated as internal errors by the caller so the PUT returns 500
/// rather than silently assigning wrong IDs).
fn plugin_canonical_key(
    pc: &crate::config::types::PluginConfig,
) -> Result<(String, String, Option<u16>), ApiSpecError> {
    let canonical_config = sort_json_keys(&pc.config, MAX_SORT_JSON_DEPTH).map_err(|e| {
        ApiSpecError::Internal(format!(
            "plugin '{}': failed to compute canonical key: {}",
            pc.plugin_name, e
        ))
    })?;
    let config_str = serde_json::to_string(&canonical_config).map_err(|e| {
        ApiSpecError::Internal(format!(
            "plugin '{}': failed to serialise canonical config: {}",
            pc.plugin_name, e
        ))
    })?;
    Ok((pc.plugin_name.clone(), config_str, pc.priority_override))
}

/// Recursively sort all JSON object keys so that canonical comparison is
/// key-order-independent. Arrays are left in their original order (order
/// matters for arrays). Uses a `BTreeMap` round-trip for objects.
///
/// `depth_remaining` is decremented on each recursive call. Returns `Err` when
/// it reaches zero rather than continuing to recurse (stack-overflow defence).
fn sort_json_keys(
    v: &serde_json::Value,
    depth_remaining: usize,
) -> Result<serde_json::Value, &'static str> {
    if depth_remaining == 0 {
        return Err("config nested too deeply (>32 levels) for canonical hash");
    }
    match v {
        serde_json::Value::Object(map) => {
            let mut sorted = serde_json::Map::with_capacity(map.len());
            for (k, val) in map.iter().collect::<std::collections::BTreeMap<_, _>>() {
                sorted.insert(k.clone(), sort_json_keys(val, depth_remaining - 1)?);
            }
            Ok(serde_json::Value::Object(sorted))
        }
        serde_json::Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                out.push(sort_json_keys(item, depth_remaining - 1)?);
            }
            Ok(serde_json::Value::Array(out))
        }
        other => Ok(other.clone()),
    }
}

// ---------------------------------------------------------------------------
// Shared validate logic (POST and PUT share the validation pipeline)
// ---------------------------------------------------------------------------

struct ValidatedBundle {
    bundle: ExtractedBundle,
    metadata: crate::admin::api_specs::SpecMetadata,
}

/// Context for the PUT path: existing resource IDs and the stored proxy row.
///
/// Passed as a single value to [`validate_bundle`] so the function stays under
/// the 7-argument clippy limit while keeping all PUT-specific fields together.
struct PutContext<'a> {
    /// Stored API spec whose owned resources are being replaced.
    spec: &'a ApiSpec,
    /// ID of the proxy being replaced (excluded from uniqueness checks).
    proxy_id: &'a str,
    /// ID of the upstream currently owned by the spec (excluded from name checks).
    upstream_id: Option<&'a str>,
    /// Stored proxy row; used to detect port / transport changes for the OS probe.
    proxy: Option<&'a crate::config::types::Proxy>,
}

/// Validate an already-extracted and ID-assigned bundle.
///
/// `put_ctx` — `Some` on the PUT path; carries the existing resource IDs so
/// uniqueness checks exclude the resource being replaced, and the stored proxy
/// row so the OS port-availability probe fires only when needed. `None` on POST.
async fn validate_bundle(
    mut bundle: ExtractedBundle,
    metadata: crate::admin::api_specs::SpecMetadata,
    namespace: &str,
    db: &dyn DatabaseBackend,
    state: &AdminState,
    put_ctx: Option<PutContext<'_>>,
) -> Result<ValidatedBundle, ApiSpecError> {
    let existing_proxy_id: Option<&str> = put_ctx.as_ref().map(|c| c.proxy_id);
    let existing_upstream_id: Option<&str> = put_ctx.as_ref().and_then(|c| c.upstream_id);
    let existing_proxy: Option<&crate::config::types::Proxy> =
        put_ctx.as_ref().and_then(|c| c.proxy);
    // ID assignment (minting UUIDs for empty IDs) is the caller's responsibility
    // (assign_ids_for_post / assign_ids_for_put) and happens BEFORE this
    // function is called. By the time we arrive here, all resource IDs are
    // non-empty. Malformed non-empty ids surface as ExtractError::MalformedExtension
    // → 400, consistent with other parse errors.

    // --- Normalize + validate bundle resources ---

    use crate::admin::crud::ValidationCtx;
    let vctx = ValidationCtx::from_state(state);
    let cached_config = state.cached_gateway_config();
    let mesh_model = cached_config
        .as_ref()
        .and_then(|config| config.mesh.as_deref());
    let mut failures: Vec<ValidationFailure> = Vec::new();

    // Upstream
    if let Some(ref mut upstream) = bundle.upstream {
        upstream.normalize_fields();
        // Spec import is an operator-provided admin write, so reject mesh-projected
        // fields too (the rejection is scoped to operator paths; the mesh
        // slice-apply path does not run it).
        let mut upstream_errors = Vec::new();
        if upstream.api_spec_id.is_some() {
            upstream_errors.push(
                "api_spec_id is server-managed and must be omitted from x-ferrum-upstream"
                    .to_string(),
            );
        }
        if let Err(e) = upstream.validate_fields() {
            upstream_errors.extend(e);
        }
        if let Err(e) = upstream.validate_operator_provided_fields() {
            upstream_errors.extend(e);
        }
        // Screen literal-IP targets against the egress policy, same as direct
        // upstream admin writes and the file/db loaders.
        if let Err(e) = upstream.validate_backend_egress_ips(&state.backend_allow_ips) {
            upstream_errors.extend(e);
        }
        if !upstream_errors.is_empty() {
            failures.push(ValidationFailure {
                resource_type: "upstream",
                id: upstream.id.clone(),
                errors: upstream_errors,
            });
        }
    }

    // Proxy
    {
        bundle.proxy.normalize_fields();
        let proxy = &bundle.proxy;

        let mut proxy_errors: Vec<String> = Vec::new();

        if proxy.api_spec_id.is_some() {
            proxy_errors.push(
                "api_spec_id is server-managed and must be omitted from x-ferrum-proxy".to_string(),
            );
        }

        // validate_fields covers scheme, port, listen_path regex, etc.
        if let Err(e) = proxy.validate_fields() {
            proxy_errors.extend(e);
        }
        // Screen literal-IP backend_host / dns_override against the egress
        // policy, same as direct proxy admin writes and the file/db loaders.
        if let Err(e) = proxy.validate_backend_egress_ips(&state.backend_allow_ips) {
            proxy_errors.extend(e);
        }
        // Host entry validation
        for host in &proxy.hosts {
            if let Err(msg) = crate::config::types::validate_host_entry(host) {
                proxy_errors.push(format!("Invalid proxy hosts: {msg}"));
            }
        }
        // Stream proxy must have listen_port
        if proxy.dispatch_kind.is_stream() {
            match proxy.listen_port {
                None => proxy_errors.push(format!(
                    "Stream proxy (scheme {}) must have a listen_port",
                    proxy.scheme_display()
                )),
                Some(0) => proxy_errors.push("listen_port 0 must be >= 1".to_string()),
                Some(_) => {}
            }
        } else if proxy.listen_port.is_some() {
            proxy_errors.push(format!(
                "HTTP proxy (scheme {}) must not set listen_port",
                proxy.scheme_display()
            ));
        }

        if !proxy_errors.is_empty() {
            failures.push(ValidationFailure {
                resource_type: "proxy",
                id: proxy.id.clone(),
                errors: proxy_errors,
            });
        }
    }

    // Plugins
    let known_plugins = crate::plugins::available_plugins();
    for plugin in &bundle.plugins {
        let mut plugin_errors: Vec<String> = Vec::new();

        if plugin.api_spec_id.is_some() {
            plugin_errors.push(
                "api_spec_id is server-managed and must be omitted from x-ferrum-plugins"
                    .to_string(),
            );
        }

        // Generic PluginConfig field constraints (Fix 3): priority_override
        // range, config JSON size, nesting depth.  Direct admin runs
        // validate_fields() on every PluginConfig before persistence; we
        // must do the same here.
        if let Err(errs) = plugin.validate_fields() {
            plugin_errors.extend(errs);
        }

        // Plugin names remain validated even while disabled. Construction and
        // plugin-specific config validation are deferred until enabled, which
        // lets operators stage configs whose runtime prerequisites are not yet
        // provisioned without admitting unknown plugin types.
        if !known_plugins.contains(&plugin.plugin_name.as_str()) {
            plugin_errors.push(format!(
                "Unknown plugin name '{}'. Available plugins: {:?}",
                plugin.plugin_name, known_plugins
            ));
        } else if plugin.enabled {
            let validation =
                if crate::plugins::transaction_log_schema::participates_in_config_graph(plugin) {
                    // Full construction must run only after the prospective
                    // namespace's schema definitions have been staged below.
                    // Keep policy-only admission active in this preliminary pass.
                    crate::plugins::validate_plugin_config_policy_only(
                        &plugin.plugin_name,
                        &plugin.config,
                        &state.backend_allow_ips,
                    )
                } else {
                    crate::plugins::validate_plugin_config_with_policy(
                        &plugin.plugin_name,
                        &plugin.config,
                        &state.backend_allow_ips,
                    )
                };
            if let Err(error) = validation {
                plugin_errors.push(error);
            }
        }

        if !plugin_errors.is_empty() {
            failures.push(ValidationFailure {
                resource_type: "plugin",
                id: plugin.id.clone(),
                errors: plugin_errors,
            });
        }
    }

    // Duplicate plugin IDs after handler-side ID assignment. The extractor
    // rejects duplicate non-empty IDs in the submitted spec, but PUT can still
    // produce duplicates when one empty-id plugin reuses an existing stored ID
    // and another submitted plugin explicitly names that same ID.
    {
        let mut seen_plugin_ids: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut dupe_plugin_ids: Vec<String> = Vec::new();
        for plugin in &bundle.plugins {
            if !plugin.id.is_empty()
                && !seen_plugin_ids.insert(plugin.id.as_str())
                && !dupe_plugin_ids.iter().any(|id| id == &plugin.id)
            {
                dupe_plugin_ids.push(plugin.id.clone());
            }
        }
        if !dupe_plugin_ids.is_empty() {
            failures.push(ValidationFailure {
                resource_type: "plugin",
                id: bundle.proxy.id.clone(),
                errors: dupe_plugin_ids
                    .iter()
                    .map(|id| format!("duplicate plugin id '{id}' after API spec ID assignment"))
                    .collect(),
            });
        }
    }

    // Duplicate proxy plugin associations (Fix 4): detect operator-written
    // duplicate plugin_config_id entries in bundle.proxy.plugins.  SQL's
    // proxy_plugins(proxy_id, plugin_config_id) PK would conflict on insert;
    // MongoDB would persist duplicates and runtime validate_plugin_references
    // would reject.
    {
        let mut seen_assoc_ids: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut dupe_assoc_ids: Vec<String> = Vec::new();
        for assoc in &bundle.proxy.plugins {
            if !seen_assoc_ids.insert(assoc.plugin_config_id.as_str()) {
                dupe_assoc_ids.push(assoc.plugin_config_id.clone());
            }
        }
        if !dupe_assoc_ids.is_empty() {
            failures.push(ValidationFailure {
                resource_type: "proxy_plugin_association",
                id: bundle.proxy.id.clone(),
                errors: dupe_assoc_ids
                    .iter()
                    .map(|id| format!("duplicate plugin_config_id '{id}' in proxy.plugins"))
                    .collect(),
            });
        }
    }

    // Proxy plugin associations (Fix 2) — validate any operator-written
    // associations in x-ferrum-proxy.plugins that reference pre-existing
    // plugins (spec-extracted plugins are in bundle.plugins and are always
    // OK; associations pointing to non-existent or wrong-proxy plugins are
    // rejected here rather than silently admitted and only caught at
    // load_full_config time).
    {
        // Filter to associations NOT covered by bundle.plugins (operator-written only).
        let new_plugin_ids: std::collections::HashSet<&str> =
            bundle.plugins.iter().map(|p| p.id.as_str()).collect();
        let extra_associations: Vec<&PluginAssociation> = bundle
            .proxy
            .plugins
            .iter()
            .filter(|a| !new_plugin_ids.contains(a.plugin_config_id.as_str()))
            .collect();

        if !extra_associations.is_empty() {
            let proxy_id = bundle.proxy.id.clone();
            let mut assoc_errors: Vec<String> = Vec::new();

            for assoc in &extra_associations {
                let pid = &assoc.plugin_config_id;
                match db.get_plugin_config(namespace, pid).await {
                    Ok(Some(existing)) => {
                        use crate::config::types::PluginScope;
                        match existing.scope {
                            PluginScope::Global => {
                                // Mirrors the system-wide invariant enforced by
                                // GatewayConfig::validate_plugin_references and SQL
                                // validate_proxy_plugin_associations: proxy
                                // associations may only reference proxy-scoped or
                                // proxy_group-scoped plugin configs. Global plugins
                                // apply implicitly via the plugin_cache and must
                                // remain unassociated.
                                assoc_errors.push(format!(
                                    "plugin_config_id '{}' has scope=global; global plugins must remain unassociated",
                                    pid
                                ));
                            }
                            PluginScope::ProxyGroup => {
                                // Any proxy may reference a ProxyGroup plugin.
                            }
                            PluginScope::Proxy => {
                                if existing.proxy_id.as_deref() != Some(proxy_id.as_str()) {
                                    assoc_errors.push(format!(
                                        "plugin_config_id '{}' belongs to proxy '{}', not '{}'",
                                        pid,
                                        existing.proxy_id.as_deref().unwrap_or("<none>"),
                                        proxy_id
                                    ));
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        assoc_errors.push(format!("plugin_config_id '{}' does not exist", pid));
                    }
                    Err(e) => return Err(classify_db_error(e)),
                }
            }

            if !assoc_errors.is_empty() {
                failures.push(ValidationFailure {
                    resource_type: "proxy_plugin_association",
                    id: proxy_id,
                    errors: assoc_errors,
                });
            }
        }
    }

    // DB cross-checks (only when no structural failures found — avoids spurious FK errors)
    if failures.is_empty() {
        let proxy = &bundle.proxy;

        // Mirrors Proxy::after_validate in crud.rs: when the proxy references an
        // upstream by ID, verify the upstream actually exists.  If the bundle
        // includes its own upstream (x-ferrum-upstream) whose ID matches, we
        // accept it without a DB round-trip (it's about to be inserted).
        // Otherwise load the upstream row and reject missing, cross-namespace,
        // or spec-owned upstreams. Referencing a spec-owned upstream without
        // including it in this bundle is unsafe: PUT/DELETE lifecycle cleanup
        // owns those rows by api_spec_id and can remove them.
        if let Some(ref upstream_id) = proxy.upstream_id {
            let bundled_id_matches = bundle
                .upstream
                .as_ref()
                .map(|u| u.id.as_str() == upstream_id.as_str())
                .unwrap_or(false);
            if bundled_id_matches {
                if let Some(subset_name) = proxy.upstream_subset.as_deref() {
                    let subset_exists = bundle
                        .upstream
                        .as_ref()
                        .and_then(|u| u.subsets.as_ref())
                        .is_some_and(|subsets| subsets.iter().any(|s| s.name == subset_name));
                    if !subset_exists {
                        failures.push(ValidationFailure {
                            resource_type: "proxy",
                            id: proxy.id.clone(),
                            errors: vec![format!(
                                "upstream_subset '{}' is not defined on upstream_id '{}'",
                                subset_name, upstream_id
                            )],
                        });
                    }
                }
            } else {
                // Namespace-predicated lookup: an upstream in another
                // namespace reports as missing (cross-namespace references
                // are equally forbidden either way).
                match db.get_upstream(namespace, upstream_id).await {
                    Ok(Some(existing)) if existing.api_spec_id.is_some() => {
                        failures.push(ValidationFailure {
                            resource_type: "proxy",
                            id: proxy.id.clone(),
                            errors: vec![format!(
                                "upstream_id '{}' is owned by api_spec '{}' and cannot be referenced as an external upstream; include x-ferrum-upstream with this id in the spec instead",
                                upstream_id,
                                existing.api_spec_id.as_deref().unwrap_or("<unknown>")
                            )],
                        });
                    }
                    Ok(Some(existing)) => {
                        if let Some(subset_name) = proxy.upstream_subset.as_deref() {
                            let subset_exists = existing.subsets.as_ref().is_some_and(|subsets| {
                                subsets.iter().any(|s| s.name == subset_name)
                            });
                            if !subset_exists {
                                failures.push(ValidationFailure {
                                    resource_type: "proxy",
                                    id: proxy.id.clone(),
                                    errors: vec![format!(
                                        "upstream_subset '{}' is not defined on upstream_id '{}'",
                                        subset_name, upstream_id
                                    )],
                                });
                            }
                        }
                    }
                    Ok(None) => failures.push(ValidationFailure {
                        resource_type: "proxy",
                        id: proxy.id.clone(),
                        errors: vec![format!(
                            "upstream_id '{upstream_id}' does not exist in namespace '{namespace}'"
                        )],
                    }),
                    Err(e) => return Err(classify_db_error(e)),
                }
            }

            // Mirrors Proxy::after_validate in crud.rs: a retry-enabled proxy
            // whose selected default-upstream targets require a mesh transport
            // (`mesh.hbone` / `mesh.mtls`) 502s at runtime because retry forces
            // that transport off (issue #1669). Reject it at import rather than
            // persist a config the next load rejects. The upstream is the bundled
            // one (when its id matches) or the existing same-namespace DB row.
            let resolved_upstream = if bundled_id_matches {
                bundle.upstream.clone()
            } else {
                match db.get_upstream(namespace, upstream_id).await {
                    Ok(Some(existing)) if existing.api_spec_id.is_none() => Some(existing),
                    Ok(_) => None,
                    Err(e) => return Err(classify_db_error(e)),
                }
            };
            if let Some(upstream) = resolved_upstream {
                // The bundled/looked-up upstream carries `port_overrides`, but the
                // imported proxy arrives without its `#[serde(skip)]`
                // `dispatch_port_overrides` resolved — derive them so a
                // `maxRetries = 0` cap on the mesh port is honored here exactly as
                // the runtime applies it.
                if let Some(conflict) =
                    crate::config::types::first_effective_mesh_transport_conflict_with_mesh(
                        &crate::config::types::proxy_with_resolved_port_caps(proxy, &upstream),
                        &upstream,
                        proxy.upstream_subset.as_deref(),
                        proxy.retry.as_ref(),
                        proxy.allowed_methods.as_deref(),
                        mesh_model,
                    )
                {
                    failures.push(ValidationFailure {
                        resource_type: "proxy",
                        id: proxy.id.clone(),
                        errors: vec![crate::config::types::mesh_transport_retry_conflict_message(
                            &proxy.id,
                            upstream_id,
                            &conflict,
                        )],
                    });
                }
            }
        }

        // Spec-extracted plugins (`x-ferrum-plugins`) are associated with the
        // imported proxy and may include a `mesh_route_dispatch` rule that routes
        // matched traffic to a mesh-tagged upstream — independent of whether the
        // proxy's DEFAULT upstream exists or is plain. Mirror the CRUD proxy path:
        // reject when an override destination still has an effective retry over a
        // mesh transport.
        validate_bundle_route_override_conflicts(
            db,
            namespace,
            proxy,
            &bundle,
            mesh_model,
            &mut failures,
        )
        .await?;

        if proxy.dispatch_kind.is_stream() {
            // Stream-family: validate port uniqueness, reserved-port conflict, and
            // OS-level port availability.
            // Mirrors Proxy::check_uniqueness + Proxy::after_validate in crud.rs.
            if let Some(port) = proxy.listen_port {
                // Port uniqueness (across all stream proxies in this namespace).
                match db
                    .check_listen_port_unique(namespace, port, existing_proxy_id)
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => failures.push(ValidationFailure {
                        resource_type: "proxy",
                        id: proxy.id.clone(),
                        errors: vec![format!(
                            "listen_port {port} is already in use by another proxy"
                        )],
                    }),
                    Err(e) => return Err(classify_db_error(e)),
                }

                // Reserved gateway ports check (skip in CP mode — CP can't know each
                // DP's reserved ports; matches the Proxy::after_validate guard).
                if vctx.mode != "cp" && vctx.reserved_ports.contains(&port) {
                    failures.push(ValidationFailure {
                        resource_type: "proxy",
                        id: proxy.id.clone(),
                        errors: vec![format!(
                            "listen_port {port} conflicts with a gateway reserved port \
                             (proxy/admin/gRPC listener)"
                        )],
                    });
                }

                // --- Fix 2: OS-level port availability probe ---
                // Mirrors the Proxy::after_validate check in crud.rs.
                // Skip in CP mode — CP can't know each DP's OS bind state.
                // Skip on PUT when neither the port nor the transport changed.
                if vctx.mode != "cp" && failures.is_empty() {
                    let port_changed = existing_proxy.and_then(|p| p.listen_port) != Some(port);
                    let transport_changed = existing_proxy
                        .map(|p| p.dispatch_kind.is_udp() != proxy.dispatch_kind.is_udp())
                        .unwrap_or(false);
                    let should_probe =
                        existing_proxy.is_none() || port_changed || transport_changed;
                    if should_probe
                        && let Err(error) = crate::admin::crud::check_port_available(
                            port,
                            vctx.stream_bind_address,
                            proxy.dispatch_kind.is_udp(),
                        )
                        .await
                    {
                        failures.push(ValidationFailure {
                            resource_type: "proxy",
                            id: proxy.id.clone(),
                            errors: vec![format!(
                                "listen_port {port} is not available on the host: {error}"
                            )],
                        });
                    }
                }
            }
        } else {
            // HTTP-family: validate listen_path + hosts uniqueness.
            // Exclude self when replacing (PUT path passes existing proxy id).
            match db
                .check_listen_path_unique(
                    namespace,
                    proxy.listen_path.as_deref(),
                    &proxy.hosts,
                    existing_proxy_id,
                )
                .await
            {
                Ok(true) => {}
                Ok(false) => failures.push(ValidationFailure {
                    resource_type: "proxy",
                    id: proxy.id.clone(),
                    errors: vec![
                        "A proxy with overlapping hosts and listen_path already exists".to_string(),
                    ],
                }),
                Err(e) => return Err(classify_db_error(e)),
            }
        }

        if let Some(name) = proxy.name.as_deref() {
            match db
                .check_proxy_name_unique(namespace, name, existing_proxy_id)
                .await
            {
                Ok(true) => {}
                Ok(false) => failures.push(ValidationFailure {
                    resource_type: "proxy",
                    id: proxy.id.clone(),
                    errors: vec![format!("Proxy name '{}' already exists", name)],
                }),
                Err(e) => return Err(classify_db_error(e)),
            }
        }

        if let Some(ref upstream) = bundle.upstream
            && let Some(ref name) = upstream.name
        {
            // On PUT, exclude the spec's current upstream so a spec that
            // keeps the same upstream name doesn't collide with itself.
            match db
                .check_upstream_name_unique(namespace, name, existing_upstream_id)
                .await
            {
                Ok(true) => {}
                Ok(false) => failures.push(ValidationFailure {
                    resource_type: "upstream",
                    id: upstream.id.clone(),
                    errors: vec![format!("An upstream with name '{}' already exists", name)],
                }),
                Err(e) => return Err(classify_db_error(e)),
            }
        }
    }

    if failures.is_empty() {
        let validation_result = if let Some(put_ctx) = put_ctx.as_ref() {
            crate::admin::crud::validate_plugin_graph_api_spec_replacement_candidate(
                db,
                state,
                namespace,
                put_ctx.spec,
                &bundle.proxy,
                &bundle.plugins,
            )
            .await
        } else {
            crate::admin::crud::validate_plugin_graph_candidates(
                db,
                state,
                namespace,
                std::slice::from_ref(&bundle.proxy),
                &bundle.plugins,
                None,
            )
            .await
        };
        match validation_result {
            Ok(()) => {}
            Err(crate::admin::crud::AfterValidateError::BadRequest(errors)) => {
                failures.push(ValidationFailure {
                    resource_type: "plugin_composition",
                    id: bundle.proxy.id.clone(),
                    errors,
                });
            }
            Err(crate::admin::crud::AfterValidateError::Conflict(errors)) => {
                return Err(ApiSpecError::Conflict(errors.join("; ")));
            }
            Err(crate::admin::crud::AfterValidateError::Db(error)) => {
                return Err(classify_db_error(error));
            }
            Err(crate::admin::crud::AfterValidateError::Response(_)) => {
                return Err(ApiSpecError::Internal(
                    "Plugin-graph candidate validation returned an unexpected response".to_string(),
                ));
            }
        }
    }

    if failures.is_empty() {
        let validation_result = if let Some(put_ctx) = put_ctx.as_ref() {
            crate::admin::crud::validate_transaction_log_schema_api_spec_replacement_candidate(
                db,
                state,
                namespace,
                put_ctx.spec,
                &bundle.plugins,
            )
            .await
        } else if bundle
            .plugins
            .iter()
            .any(crate::plugins::transaction_log_schema::is_enabled_config_graph_participant)
        {
            crate::admin::crud::validate_transaction_log_schema_candidates(
                db,
                state,
                namespace,
                &bundle.plugins,
                None,
            )
            .await
        } else {
            Ok(())
        };
        match validation_result {
            Ok(()) => {}
            Err(
                crate::admin::crud::AfterValidateError::BadRequest(errors)
                | crate::admin::crud::AfterValidateError::Conflict(errors),
            ) => {
                failures.push(ValidationFailure {
                    resource_type: "plugin_graph",
                    id: bundle.proxy.id.clone(),
                    errors,
                });
            }
            Err(crate::admin::crud::AfterValidateError::Db(error)) => {
                return Err(classify_db_error(error));
            }
            Err(crate::admin::crud::AfterValidateError::Response(_)) => {
                return Err(ApiSpecError::Internal(
                    "Transaction-log schema candidate validation returned an unexpected response"
                        .to_string(),
                ));
            }
        }
    }

    if !failures.is_empty() {
        return Err(ApiSpecError::ValidationFailures {
            spec_version: metadata.version.clone(),
            failures,
        });
    }

    Ok(ValidatedBundle { bundle, metadata })
}

/// Reject a retry-enabled imported proxy whose `mesh_route_dispatch` rules route
/// matched traffic to a mesh-tagged (`mesh.hbone` / `mesh.mtls`) upstream — the
/// API-spec equivalent of the route-override conflict check in `Proxy::after_validate`.
///
/// Spec-extracted plugins (`x-ferrum-plugins`) are associated with the imported
/// proxy via `bundle.proxy.plugins`, so a bundled `mesh_route_dispatch` whose rule
/// overrides the upstream still 502s at runtime (issue #1669) just like a
/// CRUD-written one. The candidate plugin set mirrors the runtime plugin cache:
/// the bundle's own proxy-scoped/proxy_group mesh_route_dispatch instances (only
/// those the proxy actually attaches) plus enabled DB globals — except a bundled
/// local instance shadows DB globals of the same name, so those are excluded.
/// Override-destination upstreams resolve from the bundle first, then the DB.
async fn validate_bundle_route_override_conflicts(
    db: &dyn DatabaseBackend,
    namespace: &str,
    proxy: &crate::config::types::Proxy,
    bundle: &crate::admin::api_specs::extractor::ExtractedBundle,
    mesh_model: Option<&crate::modes::mesh::config::MeshConfig>,
    failures: &mut Vec<ValidationFailure>,
) -> Result<(), ApiSpecError> {
    use crate::config::types::PluginScope;
    use crate::plugins::mesh_route_dispatch::MeshRouteDispatchConfig;

    // Plugin config ids the proxy actually attaches (runtime only instantiates
    // attached instances; an inert bundled instance never dispatches).
    let attached_ids: std::collections::HashSet<&str> = proxy
        .plugins
        .iter()
        .map(|a| a.plugin_config_id.as_str())
        .collect();

    // mesh_route_dispatch instances this proxy attaches, resolved from the bundle
    // first then the DB (an operator-written association may reference a
    // pre-existing DB plugin). A local instance shadows DB globals of the same
    // name (PluginCache removes them).
    let mut candidates: Vec<crate::config::types::PluginConfig> = Vec::new();
    let mut shadows_global = false;
    let bundle_plugin_ids: std::collections::HashSet<&str> =
        bundle.plugins.iter().map(|p| p.id.as_str()).collect();
    for pc in &bundle.plugins {
        if pc.enabled
            && pc.plugin_name == "mesh_route_dispatch"
            && attached_ids.contains(pc.id.as_str())
        {
            shadows_global = true;
            candidates.push(pc.clone());
        }
    }
    for id in &attached_ids {
        if bundle_plugin_ids.contains(id) {
            continue;
        }
        if let Some(pc) = db
            .get_plugin_config(namespace, id)
            .await
            .map_err(classify_db_error)?
            && pc.enabled
            && pc.plugin_name == "mesh_route_dispatch"
        {
            shadows_global = true;
            candidates.push(pc);
        }
    }

    // DB globals run on this proxy unless a local instance shadows them.
    let db_globals: Vec<crate::config::types::PluginConfig> = if shadows_global {
        Vec::new()
    } else {
        let mut globals = Vec::new();
        let mut offset = 0_i64;
        const PAGE_SIZE: i64 = 1_000;
        loop {
            let page = db
                .list_plugin_configs_paginated(namespace, PAGE_SIZE, offset)
                .await
                .map_err(classify_db_error)?;
            let items_len = page.items.len() as i64;
            for plugin in page.items {
                if plugin.scope == PluginScope::Global
                    && plugin.enabled
                    && plugin.plugin_name == "mesh_route_dispatch"
                {
                    globals.push(plugin);
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
        globals
    };

    let default_uid = proxy.upstream_id.as_deref().unwrap_or("");
    for pc in candidates.iter().chain(db_globals.iter()) {
        let Ok(dispatch) = MeshRouteDispatchConfig::from_value(&pc.config) else {
            continue;
        };
        for rule in &dispatch.rules {
            // Redirect rules answer the request before any upstream override, so
            // they never dispatch to their destination upstream.
            if rule.redirect.is_some() {
                continue;
            }
            let Some(override_uid) = rule.destination.upstream_id.as_deref() else {
                continue;
            };
            let rule_changes_retry = rule.retry.is_some() || rule.retry_disabled;
            // A same-upstream rule that leaves retry untouched is covered by the
            // default-upstream check.
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
            // Runtime preserves `proxy.upstream_subset` only for a same-upstream
            // rule; a different-upstream override drops it.
            let selected_subset = if override_uid == default_uid {
                proxy.upstream_subset.as_deref()
            } else {
                None
            };
            // Resolve the override destination upstream: bundle first, then DB.
            let resolved = match bundle.upstream.as_ref() {
                Some(u) if u.id == override_uid => Some(u.clone()),
                _ => match db.get_upstream(namespace, override_uid).await {
                    Ok(u) => u,
                    Err(e) => return Err(classify_db_error(e)),
                },
            };
            if let Some(upstream) = resolved
                && let Some(conflict) =
                    crate::config::types::first_effective_mesh_transport_conflict_with_mesh(
                        &crate::config::types::proxy_with_resolved_port_caps(proxy, &upstream),
                        &upstream,
                        selected_subset,
                        effective_retry.as_ref(),
                        proxy.allowed_methods.as_deref(),
                        mesh_model,
                    )
            {
                failures.push(ValidationFailure {
                    resource_type: "proxy",
                    id: proxy.id.clone(),
                    errors: vec![crate::config::types::mesh_transport_retry_conflict_message(
                        &proxy.id,
                        override_uid,
                        &conflict,
                    )],
                });
            }
        }
    }
    Ok(())
}

/// Build an `ApiSpec` row from body bytes, metadata, and bundle.
fn build_spec_row(
    id: String,
    proxy_id: String,
    namespace: String,
    body: &[u8],
    metadata: &crate::admin::api_specs::SpecMetadata,
    bundle: &crate::admin::api_specs::ExtractedBundle,
) -> Result<ApiSpec, ApiSpecError> {
    let spec_content = spec_codec::compress_gzip(body)
        .map_err(|e| ApiSpecError::Internal(format!("gzip compress failed: {e}")))?;
    let content_hash = spec_codec::sha256_hex(body);
    let resource_hash = hash_resource_bundle(bundle)
        .map_err(|e| ApiSpecError::Internal(format!("resource hash failed: {e}")))?;
    let now = Utc::now();
    Ok(ApiSpec {
        id,
        namespace,
        proxy_id,
        spec_version: metadata.version.clone(),
        spec_format: metadata.format,
        spec_content,
        content_encoding: "gzip".to_string(),
        uncompressed_size: body.len() as u64,
        content_hash,
        title: metadata.title.clone(),
        info_version: metadata.info_version.clone(),
        description: metadata.description.clone(),
        contact_name: metadata.contact_name.clone(),
        contact_email: metadata.contact_email.clone(),
        license_name: metadata.license_name.clone(),
        license_identifier: metadata.license_identifier.clone(),
        tags: metadata.tags.clone(),
        server_urls: metadata.server_urls.clone(),
        operation_count: metadata.operation_count,
        resource_hash,
        created_at: now,
        updated_at: now,
    })
}

// ---------------------------------------------------------------------------
// Helper: build spec-fetch response with ETag + content negotiation
// ---------------------------------------------------------------------------

/// `max_decompress_bytes` is the upper bound on decompressed output bytes.
/// Guards against corrupt or adversarially inflated DB rows.  Callers should
/// pass `2 * admin_spec_max_body_size_mib * 1024 * 1024`.
fn spec_content_response(
    spec: &ApiSpec,
    request_headers: &hyper::HeaderMap,
    max_decompress_bytes: usize,
) -> Response<Full<Bytes>> {
    // Content negotiation FIRST — the ETag must be representation-specific so
    // a cached YAML ETag does not produce a false 304 when the client requests
    // JSON (or vice-versa).
    let target_fmt = match negotiate_accept_or_406(request_headers, spec.spec_format) {
        Some(fmt) => fmt,
        None => {
            return json_resp(
                StatusCode::NOT_ACCEPTABLE,
                &json!({
                    "error": "No representation acceptable per Accept header (all formats explicitly q=0)"
                }),
            );
        }
    };

    let fmt_suffix = match target_fmt {
        SpecFormat::Json => "json",
        SpecFormat::Yaml => "yaml",
    };
    let etag = format!("\"{}-{}\"", spec.content_hash, fmt_suffix);

    // If-None-Match check (RFC 9110 §13.1.2: comma-separated list, W/ prefix)
    let etag_matches = request_headers
        .get("if-none-match")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|inm| {
            inm == "*"
                || inm.split(',').any(|entry| {
                    let tag = entry.trim().strip_prefix("W/").unwrap_or(entry.trim());
                    tag == etag
                })
        });
    if etag_matches {
        return Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header("ETag", &etag)
            .header("Cache-Control", "no-store")
            .header("Vary", "Accept")
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
    }

    // Decompress with an output cap.  A corrupted or bomb-ratio row from the
    // DB would otherwise expand to GB on every admin GET. Deferred until after
    // the 304 check so cache hits skip decompression entirely.
    let raw = match spec_codec::decompress_gzip_capped(&spec.spec_content, max_decompress_bytes) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(
                "decompress_gzip_capped failed for spec {} (cap={} bytes): {}",
                spec.id,
                max_decompress_bytes,
                e
            );
            return json_resp(
                StatusCode::INTERNAL_SERVER_ERROR,
                &json!({"error": "spec content corrupt or oversized"}),
            );
        }
    };

    let (body_bytes, ct) = if target_fmt == spec.spec_format {
        (raw, content_type_for_format(spec.spec_format))
    } else {
        match convert_format(&raw, spec.spec_format, target_fmt) {
            Ok(converted) => (converted, content_type_for_format(target_fmt)),
            Err(e) => {
                tracing::error!(
                    "format conversion ({:?} → {:?}) failed for spec {}: {}",
                    spec.spec_format,
                    target_fmt,
                    spec.id,
                    e
                );
                let stored_fmt_str = content_type_for_format(spec.spec_format);
                let accepted_fmt_str = content_type_for_format(target_fmt);
                return json_resp(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &json!({
                        "error": format!(
                            "Cannot convert stored {} to requested {}; \
                             the stored document may be malformed — \
                             try retrieving in the original format ({}) instead",
                            stored_fmt_str, accepted_fmt_str, stored_fmt_str
                        )
                    }),
                );
            }
        }
    };

    let len = body_bytes.len();
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", ct)
        .header("Content-Length", len.to_string())
        .header("ETag", &etag)
        .header("Cache-Control", "no-store")
        .header("Vary", "Accept")
        .header("X-Content-Type-Options", "nosniff")
        .body(Full::new(Bytes::from(body_bytes)))
        .unwrap_or_else(|_| {
            let mut resp = Response::new(Full::new(Bytes::from_static(
                b"{\"error\":\"Internal server error\"}",
            )));
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            resp
        })
}

// ---------------------------------------------------------------------------
// Helper: parse list filter from query string (Wave 5)
// ---------------------------------------------------------------------------

/// Build the stable API-spec pagination error without exposing parser internals.
fn invalid_pagination(field: &str, error: crate::admin::PaginationValueError) -> ApiSpecError {
    ApiSpecError::BadRequest(format!("{field} {}", error.reason()))
}

/// Parse `GET /api-specs` query parameters into an [`ApiSpecListFilter`].
///
/// Unknown parameters are silently ignored. Returns `Err` (400) for invalid
/// `sort_by` values (rejected to prevent accidental SQL-like injection), for
/// SQL `LIKE` wildcards in text filters, and for malformed `limit`/`offset`.
///
/// This endpoint keeps a stricter pagination scheme than the shared
/// [`crate::admin::PaginationParams`] used elsewhere — default 50, maximum 200,
/// and a `u32` offset — but shares its rejection contract: malformed values are
/// never silently coerced into a default.
fn parse_list_filter(uri: &hyper::Uri) -> Result<ApiSpecListFilter, ApiSpecError> {
    const DEFAULT_LIMIT: u32 = 50;
    const MAX_LIMIT: u32 = 200;

    let mut filter = ApiSpecListFilter {
        limit: DEFAULT_LIMIT,
        ..Default::default()
    };

    let Some(query) = uri.query() else {
        return Ok(filter);
    };

    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let raw_key = parts.next().unwrap_or("");
        let raw_val = parts.next().unwrap_or("");
        // URL-decode both names and values, NAME FIRST. Decoding only values
        // lets encoded pagination names bypass this endpoint's narrower `u32`
        // offset bound (e.g. `?%6fffset=` aliasing `offset`), so names are
        // decoded too. A *name* that does not decode to valid UTF-8 cannot
        // alias any recognized ASCII filter name, so it is an unknown parameter
        // and is ignored like every other unknown key.
        let Ok(key) = percent_decode(raw_key) else {
            continue;
        };

        // Whether the name is recognized is decided BEFORE its value is
        // decoded, and the value of an ignored name is never decoded at all.
        // Otherwise a parameter that is ignored anyway (`?%80=%80`, or any
        // third-party `?unknown=%80`) would still fail the request on its
        // value. Invalid UTF-8 in the value of a *recognized* name stays a
        // strict 400: decoding it is what stops percent-encoded bytes from
        // bypassing the character-validation checks below (e.g. the
        // `title_contains` LIKE-wildcard rejection).
        //
        // Keep this list in sync with the recognized arms of the match below;
        // a name missing here is silently ignored.
        if !matches!(
            key.as_str(),
            "limit"
                | "offset"
                | "proxy_id"
                | "spec_version"
                | "title_contains"
                | "updated_since"
                | "has_tag"
                | "sort_by"
                | "order"
        ) {
            continue;
        }
        let val = percent_decode(raw_val)?;

        match key.as_str() {
            // `/api-specs` keeps its own stricter bounds (default 50, max 200)
            // and its `{items, next_offset}` envelope, but malformed input is
            // rejected with 400 exactly as `parse_pagination` does for every
            // other list route — never silently coerced to a default.
            "limit" => {
                let parsed = crate::admin::parse_unsigned_pagination_value(&val)
                    .map_err(|error| invalid_pagination("limit", error))?;
                // `0` keeps the documented "server default" meaning; values
                // above the maximum are capped.
                filter.limit = if parsed == 0 {
                    DEFAULT_LIMIT
                } else {
                    u32::try_from(parsed.min(u64::from(MAX_LIMIT))).map_err(|_| {
                        invalid_pagination("limit", crate::admin::PaginationValueError::Overflow)
                    })?
                };
            }
            "offset" => {
                let parsed = crate::admin::parse_unsigned_pagination_value(&val)
                    .map_err(|error| invalid_pagination("offset", error))?;
                filter.offset = u32::try_from(parsed).map_err(|_| {
                    invalid_pagination("offset", crate::admin::PaginationValueError::Overflow)
                })?;
            }
            "proxy_id" if !val.is_empty() => {
                filter.proxy_id = Some(val);
            }
            "spec_version" if !val.is_empty() => {
                // Same LIKE wildcard defence as title_contains — the SQL
                // list_api_specs builds `spec_version LIKE ?` with a suffix
                // wildcard and no ESCAPE clause.
                for ch in ['%', '_', '\\'] {
                    if val.contains(ch) {
                        return Err(ApiSpecError::BadRequest(format!(
                            "spec_version must not contain SQL LIKE wildcard or escape \
                             characters ('{}' is forbidden); use plain text only",
                            ch
                        )));
                    }
                }
                filter.spec_version_prefix = Some(val);
            }
            "title_contains" if !val.is_empty() => {
                // SAFETY-CRITICAL CROSS-FILE INVARIANT:
                // The SQL list_api_specs implementation in src/config/db_loader.rs
                // builds `LOWER(title) LIKE ?` with a `%…%` wrapper and NO ESCAPE
                // clause.  Characters that are LIKE wildcards (`%`, `_`) or the
                // escape character (`\`) would turn into wildcards or escape tokens,
                // producing false positives (e.g. `_` matches any single character).
                // We reject those characters here rather than escaping them so the
                // invariant is easy to audit: "the LIKE pattern is safe because input
                // can never contain wildcards".  Update db_loader.rs if you change
                // this check.
                for ch in ['%', '_', '\\'] {
                    if val.contains(ch) {
                        return Err(ApiSpecError::BadRequest(format!(
                            "title_contains must not contain SQL LIKE wildcard or escape \
                             characters ('{}' is forbidden); use plain text only",
                            ch
                        )));
                    }
                }
                filter.title_contains = Some(val);
            }
            "updated_since" if !val.is_empty() => {
                // Accept ISO-8601 / RFC-3339 format.
                let dt = chrono::DateTime::parse_from_rfc3339(&val).map_err(|_| {
                    ApiSpecError::BadRequest(format!(
                        "invalid updated_since value '{}'; expected RFC3339 timestamp",
                        val
                    ))
                })?;
                filter.updated_since = Some(dt.to_utc());
            }
            "has_tag" if !val.is_empty() => {
                // SAFETY-CRITICAL CROSS-FILE INVARIANT (mirrors the ingest-time
                // rejection in src/admin/api_specs/extractor.rs and the
                // SAFETY-CRITICAL comment near the SQL `has_tag` LIKE branch in
                // src/config/db_loader.rs::list_api_specs):
                //
                // The SQL `has_tag` filter embeds the user-supplied tag into a
                // bare `LIKE` pattern with no `ESCAPE` clause. We reject the
                // tag NAMES at extraction time so the stored data is wildcard-
                // free, but we ALSO have to validate the QUERY parameter here
                // — otherwise a client sending `?has_tag=%25` (URL-decoded `%`)
                // or `?has_tag=_` would inject a SQL LIKE wildcard at query
                // time and turn the advertised exact-membership filter into a
                // multi-row pattern match.
                //
                // Apply the identical character whitelist used by
                // `ExtractError::InvalidTagName`.
                if let Some(c) = val.chars().find(|c| matches!(c, '"' | '%' | '_' | '\\')) {
                    return Err(ApiSpecError::BadRequest(format!(
                        "has_tag value contains forbidden character '{}'; tag names \
                         cannot contain '\"', '%', '_', or '\\\\'",
                        c
                    )));
                }
                filter.has_tag = Some(val);
            }
            "sort_by" if !val.is_empty() => {
                filter.sort_by = match val.as_str() {
                    "updated_at" => ApiSpecSortBy::UpdatedAt,
                    "title" => ApiSpecSortBy::Title,
                    "operation_count" => ApiSpecSortBy::OperationCount,
                    "created_at" => ApiSpecSortBy::CreatedAt,
                    other => {
                        return Err(ApiSpecError::BadRequest(format!(
                            "invalid sort_by value '{}'; allowed: updated_at, title, operation_count, created_at",
                            other
                        )));
                    }
                };
            }
            "order" if !val.is_empty() => {
                filter.order = match val.as_str() {
                    "asc" => SortOrder::Asc,
                    "desc" => SortOrder::Desc,
                    other => {
                        return Err(ApiSpecError::BadRequest(format!(
                            "invalid order value '{}'; allowed: asc, desc",
                            other
                        )));
                    }
                };
            }
            _ => {}
        }
    }

    Ok(filter)
}

fn max_spec_decompress_bytes(max_mib: usize) -> usize {
    max_mib
        .saturating_mul(2)
        .saturating_mul(1024)
        .saturating_mul(1024)
}

/// Simple percent-decode for query parameter values.
///
/// Only decodes `%XX` sequences; `+` is NOT decoded as space (RFC 3986 query
/// semantics).
///
/// Returns `Err` if the decoded byte sequence is not valid UTF-8.  Callers
/// should surface this as a 400 response — invalid percent-encoding could
/// otherwise bypass character-validation checks (e.g. `title_contains` wildcard
/// rejection) by encoding the forbidden bytes.
fn percent_decode(s: &str) -> Result<String, ApiSpecError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (
                char::from(bytes[i + 1]).to_digit(16),
                char::from(bytes[i + 2]).to_digit(16),
            )
        {
            out.push((h * 16 + l) as u8);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).map_err(|_| {
        ApiSpecError::BadRequest(
            "invalid percent-encoding in query parameter: byte sequence is not valid UTF-8"
                .to_string(),
        )
    })
}

fn json_resp(status: StatusCode, body: &Value) -> Response<Full<Bytes>> {
    super::super::json_response(status, body)
}

// ---------------------------------------------------------------------------
// POST /api-specs
// ---------------------------------------------------------------------------

pub async fn handle_post_api_spec(
    req: Request<Incoming>,
    state: &AdminState,
    actor: &AuditActor,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    let db = match require_db(state) {
        Ok(db) => db,
        Err(e) => return Ok(error_response(e)),
    };

    let declared_format = parse_content_type(req.headers());
    let max_mib = state.admin_spec_max_body_size_mib;

    let body = match collect_body(req, max_mib, state.admin_body_read_timeout_seconds).await {
        Ok(b) => b,
        Err(e) => return Ok(error_response(e)),
    };

    // Extract resources from the spec body.
    let (mut bundle, metadata) = match extract(&body, declared_format, namespace) {
        Ok(v) => v,
        Err(e) => return Ok(error_response(ApiSpecError::Extract(e))),
    };

    // Assign IDs for POST: mint UUIDs for every empty ID, re-link references.
    assign_ids_for_post(&mut bundle);

    // Keep the authoritative namespace snapshot used by plugin-graph admission
    // stable through bundle persistence. This is shared with direct CRUD,
    // batch, restore, and API-spec PUT/DELETE mutations.
    let _namespace_config_admission_guard =
        match crate::admin::crud::lock_namespace_config_admission(db.clone(), namespace).await {
            Ok(guard) => guard,
            Err(_error) => {
                crate::admin::warn_persistence_failure_redacted(
                    "api_spec_namespace_admission_acquire",
                );
                return Ok(error_response(ApiSpecError::AdmissionUnavailable(
                    "namespace config admission unavailable".to_string(),
                )));
            }
        };

    // Validate: field checks + DB cross-checks (listen_path uniqueness, etc.)
    let ValidatedBundle { bundle, metadata } = match validate_bundle(
        bundle,
        metadata,
        namespace,
        db.as_ref(),
        state,
        None, // POST: no existing resource context
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return Ok(error_response(e)),
    };

    let spec_id = Uuid::new_v4().to_string();
    let proxy_id = bundle.proxy.id.clone();

    let spec = match build_spec_row(
        spec_id.clone(),
        proxy_id.clone(),
        namespace.to_string(),
        &body,
        &metadata,
        &bundle,
    ) {
        Ok(s) => s,
        Err(e) => return Ok(error_response(e)),
    };

    let settlement_db = db.clone();
    let persistence_db = db.clone();
    let compensation_db = db.clone();
    let settlement_namespace = namespace.to_string();
    let persistence_bundle = bundle.clone();
    let persistence_spec = spec.clone();
    let compensation_bundle = bundle.clone();
    let compensation_spec = spec.clone();
    let settlement_state = state.clone();
    let audit_db = db.clone();
    let audit_enabled = state.admin_audit_enabled;
    let audit_actor = actor.clone();
    let audit_spec = spec.clone();
    let persistence = tokio::spawn(async move {
        let result = run_api_spec_persistence_while_held(
            settlement_db,
            &settlement_namespace,
            _namespace_config_admission_guard,
            persistence_db.submit_api_spec_bundle(&persistence_bundle, &persistence_spec),
            compensate_late_api_spec_create(
                compensation_db,
                compensation_bundle,
                compensation_spec,
                &settlement_state,
            ),
            true,
        )
        .await;
        if result.is_ok() {
            let event = audit::AuditEvent::new(
                &audit_actor,
                "create",
                "api_spec",
                &audit_spec.id,
                &audit_spec.namespace,
                audit::create_diff(json!({
                    "id": audit_spec.id,
                    "proxy_id": audit_spec.proxy_id,
                    "content_hash": audit_spec.content_hash,
                    "spec_version": audit_spec.spec_version,
                })),
            );
            if let Err(error) = audit::record(audit_enabled, audit_db, event) {
                log_audit_enqueue_failure(&error);
            }
        }
        result
    })
    .await
    .unwrap_or_else(|error| {
        Err(ApiSpecError::Internal(format!(
            "API-spec create persistence task failed: {error}"
        )))
    });
    if let Err(error) = persistence {
        return Ok(error_response(error));
    }

    let resp_body = json!({
        "id": spec_id,
        "proxy_id": proxy_id,
        "content_hash": spec.content_hash,
        "spec_version": spec.spec_version,
    });

    // Build the body + standard headers via the shared `json_resp` helper, then
    // inject the `Location` header. This keeps body-serialisation and header
    // policy consistent with every other JSON response in this module.
    let mut resp = json_resp(StatusCode::CREATED, &resp_body);
    if let Ok(hv) = hyper::header::HeaderValue::from_str(&format!("/api-specs/{}", spec_id)) {
        resp.headers_mut().insert("Location", hv);
    }
    Ok(resp)
}

// ---------------------------------------------------------------------------
// PUT /api-specs/{id}
// ---------------------------------------------------------------------------

pub async fn handle_put_api_spec(
    req: Request<Incoming>,
    state: &AdminState,
    actor: &AuditActor,
    namespace: &str,
    id: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    let db = match require_db(state) {
        Ok(db) => db,
        Err(e) => return Ok(error_response(e)),
    };

    // Preserve the endpoint's early not-found behavior before collecting a
    // potentially large body. The spec is re-read under the namespace
    // admission guard below before any prospective validation uses it.
    match db.get_api_spec(namespace, id).await {
        Ok(Some(_)) => {}
        Ok(None) => return Ok(error_response(ApiSpecError::NotFound)),
        Err(e) => return Ok(error_response(classify_db_error(e))),
    }

    let declared_format = parse_content_type(req.headers());
    let max_mib = state.admin_spec_max_body_size_mib;

    let body = match collect_body(req, max_mib, state.admin_body_read_timeout_seconds).await {
        Ok(b) => b,
        Err(e) => return Ok(error_response(e)),
    };

    // Extract resources from the spec body.
    let (mut bundle, metadata) = match extract(&body, declared_format, namespace) {
        Ok(v) => v,
        Err(e) => return Ok(error_response(ApiSpecError::Extract(e))),
    };

    // Serialize every graph-relevant read below through replacement
    // persistence. Re-read the spec after acquiring the guard so a concurrent
    // API-spec delete cannot leave validation based on a stale owner row.
    let _namespace_config_admission_guard =
        match crate::admin::crud::lock_namespace_config_admission(db.clone(), namespace).await {
            Ok(guard) => guard,
            Err(_error) => {
                crate::admin::warn_persistence_failure_redacted(
                    "api_spec_namespace_admission_acquire",
                );
                return Ok(error_response(ApiSpecError::AdmissionUnavailable(
                    "namespace config admission unavailable".to_string(),
                )));
            }
        };
    let existing_spec = match db.get_api_spec(namespace, id).await {
        Ok(Some(spec)) => spec,
        Ok(None) => return Ok(error_response(ApiSpecError::NotFound)),
        Err(e) => return Ok(error_response(classify_db_error(e))),
    };

    let existing_spec_upstream =
        match load_single_spec_owned_upstream(db, namespace, &existing_spec.id).await {
            Ok(upstream) => upstream,
            Err(e) => return Ok(error_response(e)),
        };
    let existing_spec_plugins = match db
        .list_spec_owned_plugin_configs(namespace, &existing_spec.id)
        .await
    {
        Ok(plugins) => plugins,
        Err(error) => return Ok(error_response(classify_db_error(error))),
    };

    // Assign IDs for PUT: reuse existing stored IDs for empty-id resources so
    // re-submitting the same ID-less spec is idempotent (Fix 1). This must
    // happen BEFORE the proxy-id immutability check and hash comparison.
    if let Err(e) = assign_ids_for_put(
        &mut bundle,
        db,
        namespace,
        &existing_spec,
        existing_spec_upstream.as_ref(),
        &metadata.version,
    )
    .await
    {
        return Ok(error_response(e));
    }

    // Enforce that the new spec targets the same proxy as the existing spec.
    // PUT cannot change which proxy a spec belongs to.
    if bundle.proxy.id != existing_spec.proxy_id {
        return Ok(error_response(ApiSpecError::ValidationFailures {
            spec_version: metadata.version.clone(),
            failures: vec![ValidationFailure {
                resource_type: "proxy",
                id: bundle.proxy.id.clone(),
                errors: vec![format!(
                    "PUT cannot change proxy_id; existing spec is for proxy '{}'",
                    existing_spec.proxy_id
                )],
            }],
        }));
    }

    // Fetch the existing proxy row once so we can:
    //   1. Exclude the spec's own upstream from the name-uniqueness check
    //      (PUT with unchanged name must not self-collide).
    //   2. Detect listen_port / transport changes for the port-probe
    //      skip-on-unchanged logic (Fix 2).
    // Use the *stored* upstream_id — NOT the bundle's post-assignment
    // upstream.id, which can be operator-changed.
    let existing_proxy_row: Option<crate::config::types::Proxy> = match db
        .get_proxy_for_write(namespace, &existing_spec.proxy_id)
        .await
    {
        Ok(p) => p,
        Err(e) => return Ok(error_response(classify_db_error(e))),
    };
    let previous_bundle = match existing_proxy_row.as_ref() {
        Some(proxy) => ExtractedBundle {
            proxy: proxy.clone(),
            upstream: existing_spec_upstream.clone(),
            plugins: existing_spec_plugins,
        },
        None => {
            return Ok(error_response(ApiSpecError::Internal(format!(
                "API spec '{}' references missing proxy '{}'",
                existing_spec.id, existing_spec.proxy_id
            ))));
        }
    };
    let existing_upstream_id: Option<&str> = existing_spec_upstream.as_ref().map(|u| u.id.as_str());

    let ValidatedBundle { bundle, metadata } = match validate_bundle(
        bundle,
        metadata,
        namespace,
        db.as_ref(),
        state,
        Some(PutContext {
            spec: &existing_spec,
            proxy_id: &existing_spec.proxy_id,
            upstream_id: existing_upstream_id,
            proxy: existing_proxy_row.as_ref(),
        }),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return Ok(error_response(e)),
    };

    let proxy_id = bundle.proxy.id.clone();

    let mut spec = match build_spec_row(
        id.to_string(),
        proxy_id.clone(),
        namespace.to_string(),
        &body,
        &metadata,
        &bundle,
    ) {
        Ok(s) => s,
        Err(e) => return Ok(error_response(e)),
    };
    // Preserve original created_at
    spec.created_at = existing_spec.created_at;

    let settlement_db = db.clone();
    let persistence_db = db.clone();
    let compensation_db = db.clone();
    let settlement_namespace = namespace.to_string();
    let persistence_bundle = bundle.clone();
    let persistence_spec = spec.clone();
    let compensation_bundle = bundle.clone();
    let compensation_spec = spec.clone();
    let compensation_previous_spec = existing_spec.clone();
    let settlement_state = state.clone();
    let audit_db = db.clone();
    let audit_enabled = state.admin_audit_enabled;
    let audit_actor = actor.clone();
    let audit_spec = spec.clone();
    let audit_previous_spec = existing_spec.clone();
    let persistence = tokio::spawn(async move {
        let result = run_api_spec_persistence_while_held(
            settlement_db,
            &settlement_namespace,
            _namespace_config_admission_guard,
            persistence_db.replace_api_spec_bundle(&persistence_bundle, &persistence_spec),
            compensate_late_api_spec_replace(
                compensation_db,
                compensation_bundle,
                compensation_spec,
                previous_bundle,
                compensation_previous_spec,
                &settlement_state,
            ),
            true,
        )
        .await;
        if result.is_ok() {
            let event = audit::AuditEvent::new(
                &audit_actor,
                "update",
                "api_spec",
                &audit_spec.id,
                &audit_spec.namespace,
                audit::update_diff(
                    json!({
                        "id": audit_previous_spec.id,
                        "proxy_id": audit_previous_spec.proxy_id,
                        "content_hash": audit_previous_spec.content_hash,
                        "spec_version": audit_previous_spec.spec_version,
                    }),
                    json!({
                        "id": audit_spec.id,
                        "proxy_id": audit_spec.proxy_id,
                        "content_hash": audit_spec.content_hash,
                        "spec_version": audit_spec.spec_version,
                    }),
                ),
            );
            if let Err(error) = audit::record(audit_enabled, audit_db, event) {
                log_audit_enqueue_failure(&error);
            }
        }
        result
    })
    .await
    .unwrap_or_else(|error| {
        Err(ApiSpecError::Internal(format!(
            "API-spec replace persistence task failed: {error}"
        )))
    });
    if let Err(error) = persistence {
        return Ok(error_response(error));
    }

    let resp_body = json!({
        "id": id,
        "proxy_id": proxy_id,
        "content_hash": spec.content_hash,
        "spec_version": spec.spec_version,
    });

    Ok(json_resp(StatusCode::OK, &resp_body))
}

// ---------------------------------------------------------------------------
// GET /api-specs/{id}
// ---------------------------------------------------------------------------

pub async fn handle_get_api_spec(
    req: Request<Incoming>,
    state: &AdminState,
    namespace: &str,
    id: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let db = match require_db(state) {
        Ok(db) => db,
        Err(e) => return Ok(error_response(e)),
    };

    let spec = match db.get_api_spec(namespace, id).await {
        Ok(Some(s)) => s,
        Ok(None) => return Ok(error_response(ApiSpecError::NotFound)),
        Err(e) => return Ok(error_response(classify_db_error(e))),
    };

    let max_decompress = max_spec_decompress_bytes(state.admin_spec_max_body_size_mib);
    Ok(spec_content_response(&spec, req.headers(), max_decompress))
}

// ---------------------------------------------------------------------------
// GET /api-specs/by-proxy/{proxy_id}
// ---------------------------------------------------------------------------

pub async fn handle_get_api_spec_by_proxy(
    req: Request<Incoming>,
    state: &AdminState,
    namespace: &str,
    proxy_id: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let db = match require_db(state) {
        Ok(db) => db,
        Err(e) => return Ok(error_response(e)),
    };

    let spec = match db.get_api_spec_by_proxy(namespace, proxy_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return Ok(error_response(ApiSpecError::NotFound)),
        Err(e) => return Ok(error_response(classify_db_error(e))),
    };

    let max_decompress = max_spec_decompress_bytes(state.admin_spec_max_body_size_mib);
    Ok(spec_content_response(&spec, req.headers(), max_decompress))
}

// ---------------------------------------------------------------------------
// GET /api-specs (list)
// ---------------------------------------------------------------------------

pub async fn handle_list_api_specs(
    req: Request<Incoming>,
    state: &AdminState,
    namespace: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let db = match require_db(state) {
        Ok(db) => db,
        Err(e) => return Ok(error_response(e)),
    };

    let filter = match parse_list_filter(req.uri()) {
        Ok(f) => f,
        Err(e) => return Ok(error_response(e)),
    };

    let paginated = match db.list_api_specs(namespace, &filter).await {
        Ok(p) => p,
        Err(e) => return Ok(error_response(classify_db_error(e))),
    };

    // Build summary items — intentionally OMIT spec_content (heavy blob) and
    // resource_hash (internal implementation detail, not for client display).
    let items: Vec<Value> = paginated
        .items
        .iter()
        .map(|s| {
            json!({
                "id": s.id,
                "proxy_id": s.proxy_id,
                "spec_version": s.spec_version,
                "spec_format": s.spec_format,
                "title": s.title,
                "info_version": s.info_version,
                "description": s.description,
                "contact_name": s.contact_name,
                "contact_email": s.contact_email,
                "license_name": s.license_name,
                "license_identifier": s.license_identifier,
                "tags": s.tags,
                "server_urls": s.server_urls,
                "operation_count": s.operation_count,
                "uncompressed_size": s.uncompressed_size,
                "content_hash": s.content_hash,
                "created_at": s.created_at,
                "updated_at": s.updated_at,
            })
        })
        .collect();

    let next_offset =
        crate::admin::advancing_u32_offset(filter.offset, items.len(), paginated.total);

    let body = json!({
        "items": items,
        "limit": filter.limit,
        "offset": filter.offset,
        "next_offset": next_offset,
        "total": paginated.total,
    });

    Ok(json_resp(StatusCode::OK, &body))
}

// ---------------------------------------------------------------------------
// DELETE /api-specs/{id}
// ---------------------------------------------------------------------------

pub async fn handle_delete_api_spec(
    state: &AdminState,
    actor: &AuditActor,
    namespace: &str,
    id: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Some(resp) = state.check_write_allowed() {
        return Ok(resp);
    }

    let db = match require_db(state) {
        Ok(db) => db,
        Err(e) => return Ok(error_response(e)),
    };

    let _namespace_config_admission_guard =
        match crate::admin::crud::lock_namespace_config_admission(db.clone(), namespace).await {
            Ok(guard) => guard,
            Err(_error) => {
                crate::admin::warn_persistence_failure_redacted(
                    "api_spec_namespace_admission_acquire",
                );
                return Ok(error_response(ApiSpecError::AdmissionUnavailable(
                    "namespace config admission unavailable".to_string(),
                )));
            }
        };

    let existing = match db.get_api_spec(namespace, id).await {
        Ok(Some(spec)) => spec,
        Ok(None) => return Ok(error_response(ApiSpecError::NotFound)),
        Err(e) => return Ok(error_response(classify_db_error(e))),
    };
    let existing_proxy = match db.get_proxy_for_write(namespace, &existing.proxy_id).await {
        Ok(Some(proxy)) => proxy,
        Ok(None) => {
            return Ok(error_response(ApiSpecError::Internal(format!(
                "API spec '{}' references missing proxy '{}'",
                existing.id, existing.proxy_id
            ))));
        }
        Err(error) => return Ok(error_response(classify_db_error(error))),
    };
    let existing_upstream = match load_single_spec_owned_upstream(db, namespace, id).await {
        Ok(upstream) => upstream,
        Err(error) => return Ok(error_response(error)),
    };
    let additional_upstreams = match existing_proxy.upstream_id.as_deref().filter(|upstream_id| {
        existing_upstream
            .as_ref()
            .map(|upstream| upstream.id.as_str())
            != Some(*upstream_id)
    }) {
        Some(upstream_id) => match db.get_upstream(namespace, upstream_id).await {
            Ok(Some(upstream)) if upstream.api_spec_id.is_none() => vec![upstream],
            Ok(Some(upstream)) => {
                let error = format!(
                    "API spec '{}' cannot snapshot current upstream '{}': it is owned by API spec '{}'",
                    existing.id,
                    upstream.id,
                    upstream.api_spec_id.as_deref().unwrap_or("<unknown>")
                );
                return Ok(error_response(restore_snapshot_validation_failure(
                    &existing,
                    upstream.id,
                    error,
                )));
            }
            Ok(None) => {
                return Ok(error_response(ApiSpecError::ValidationFailures {
                    spec_version: existing.spec_version.clone(),
                    failures: vec![ValidationFailure {
                        resource_type: "upstream_graph",
                        id: existing.proxy_id.clone(),
                        errors: vec![format!("proxy references missing upstream '{upstream_id}'")],
                    }],
                }));
            }
            Err(error) => return Ok(error_response(classify_db_error(error))),
        },
        None => Vec::new(),
    };
    let existing_plugins = match db.list_spec_owned_plugin_configs(namespace, id).await {
        Ok(plugins) => plugins,
        Err(error) => return Ok(error_response(classify_db_error(error))),
    };
    let deletion_snapshot = match db.load_namespace_snapshot(namespace).await {
        Ok(snapshot) => snapshot,
        Err(error) => return Ok(error_response(classify_db_error(error))),
    };
    let owned_plugin_ids: HashSet<&str> = existing_plugins
        .iter()
        .map(|plugin| plugin.id.as_str())
        .collect();
    let proxy_plugin_ids: HashSet<&str> = existing_proxy
        .plugins
        .iter()
        .map(|association| association.plugin_config_id.as_str())
        .collect();
    let other_proxy_plugin_ids: HashSet<&str> = deletion_snapshot
        .proxies
        .iter()
        .filter(|proxy| proxy.id != existing.proxy_id)
        .flat_map(|proxy| proxy.plugins.iter())
        .map(|association| association.plugin_config_id.as_str())
        .collect();
    for plugin in deletion_snapshot.plugin_configs.iter().filter(|plugin| {
        owned_plugin_ids.contains(plugin.id.as_str())
            || plugin.proxy_id.as_deref() == Some(existing.proxy_id.as_str())
    }) {
        let Some(other_proxy) = deletion_snapshot
            .proxies
            .iter()
            .filter(|proxy| proxy.id != existing.proxy_id)
            .find(|proxy| {
                proxy
                    .plugins
                    .iter()
                    .any(|association| association.plugin_config_id == plugin.id)
            })
        else {
            continue;
        };
        let error = format!(
            "API spec '{}' cannot delete proxy '{}': cascade plugin '{}' is also associated with proxy '{}', whose association is not part of the restore snapshot",
            existing.id, existing.proxy_id, plugin.id, other_proxy.id
        );
        return Ok(error_response(restore_snapshot_validation_failure(
            &existing,
            plugin.id.clone(),
            error,
        )));
    }
    let additional_plugin_ids = deletion_snapshot
        .plugin_configs
        .iter()
        .filter(|plugin| !owned_plugin_ids.contains(plugin.id.as_str()))
        .filter(|plugin| {
            plugin.proxy_id.as_deref() == Some(existing.proxy_id.as_str())
                || (plugin.scope == PluginScope::ProxyGroup
                    && proxy_plugin_ids.contains(plugin.id.as_str())
                    && !other_proxy_plugin_ids.contains(plugin.id.as_str()))
        })
        .map(|plugin| plugin.id.clone())
        .collect::<Vec<_>>();
    let additional_plugin_id_set: HashSet<&str> =
        additional_plugin_ids.iter().map(String::as_str).collect();
    let mut additional_plugins = Vec::with_capacity(additional_plugin_ids.len());
    for plugin_id in &additional_plugin_ids {
        match db.get_plugin_config(namespace, plugin_id).await {
            Ok(Some(plugin)) if plugin.api_spec_id.is_none() => additional_plugins.push(plugin),
            Ok(Some(plugin)) => {
                let error = format!(
                    "API spec '{}' cannot delete proxy '{}': plugin '{}' is owned by API spec '{}'",
                    existing.id,
                    existing.proxy_id,
                    plugin.id,
                    plugin.api_spec_id.as_deref().unwrap_or("<unknown>")
                );
                return Ok(error_response(restore_snapshot_validation_failure(
                    &existing, plugin.id, error,
                )));
            }
            Ok(None) => {
                return Ok(error_response(ApiSpecError::Internal(format!(
                    "API spec '{}' delete snapshot lost plugin '{}' before persistence",
                    existing.id, plugin_id
                ))));
            }
            Err(error) => return Ok(error_response(classify_db_error(error))),
        }
    }
    for association in &existing_proxy.plugins {
        let plugin_id = association.plugin_config_id.as_str();
        if owned_plugin_ids.contains(plugin_id) || additional_plugin_id_set.contains(plugin_id) {
            continue;
        }
        match db.get_plugin_config(namespace, plugin_id).await {
            Ok(Some(plugin)) if plugin.api_spec_id.is_none() => {
                if let Err(error) =
                    validate_api_spec_proxy_plugin_association(&plugin, &existing.proxy_id)
                {
                    return Ok(error_response(restore_snapshot_validation_failure(
                        &existing,
                        plugin.id,
                        error.to_string(),
                    )));
                }
            }
            Ok(Some(plugin)) => {
                let error = format!(
                    "API spec '{}' cannot delete proxy '{}': associated plugin '{}' is owned by API spec '{}'",
                    existing.id,
                    existing.proxy_id,
                    plugin.id,
                    plugin.api_spec_id.as_deref().unwrap_or("<unknown>")
                );
                return Ok(error_response(restore_snapshot_validation_failure(
                    &existing, plugin.id, error,
                )));
            }
            Ok(None) => {
                return Ok(error_response(ApiSpecError::ValidationFailures {
                    spec_version: existing.spec_version.clone(),
                    failures: vec![ValidationFailure {
                        resource_type: "plugin_graph",
                        id: existing.proxy_id.clone(),
                        errors: vec![format!(
                            "proxy association references missing plugin '{plugin_id}'"
                        )],
                    }],
                }));
            }
            Err(error) => return Ok(error_response(classify_db_error(error))),
        }
    }
    let previous_bundle = ExtractedBundle {
        proxy: existing_proxy,
        upstream: existing_upstream,
        plugins: existing_plugins,
    };
    if let Err(error) = validate_api_spec_restore_inputs(
        &previous_bundle,
        &existing,
        &additional_upstreams,
        &additional_plugins,
        true,
    ) {
        return Ok(error_response(ApiSpecError::ValidationFailures {
            spec_version: existing.spec_version.clone(),
            failures: vec![ValidationFailure {
                resource_type: "restore_snapshot",
                id: existing.proxy_id.clone(),
                errors: vec![error.to_string()],
            }],
        }));
    }

    match crate::admin::crud::validate_plugin_graph_proxy_deletion_candidate(
        db.as_ref(),
        state,
        namespace,
        &existing.proxy_id,
    )
    .await
    {
        Ok(()) => {}
        Err(
            crate::admin::crud::AfterValidateError::BadRequest(errors)
            | crate::admin::crud::AfterValidateError::Conflict(errors),
        ) => {
            return Ok(error_response(ApiSpecError::ValidationFailures {
                spec_version: existing.spec_version.clone(),
                failures: vec![ValidationFailure {
                    resource_type: "plugin_composition",
                    id: existing.proxy_id.clone(),
                    errors,
                }],
            }));
        }
        Err(crate::admin::crud::AfterValidateError::Db(error)) => {
            return Ok(error_response(classify_db_error(error)));
        }
        Err(crate::admin::crud::AfterValidateError::Response(response)) => {
            return Ok(*response);
        }
    }

    match crate::admin::crud::validate_transaction_log_schema_api_spec_deletion_candidate(
        db.as_ref(),
        state,
        namespace,
        &existing,
    )
    .await
    {
        Ok(()) => {}
        Err(
            crate::admin::crud::AfterValidateError::BadRequest(errors)
            | crate::admin::crud::AfterValidateError::Conflict(errors),
        ) => {
            return Ok(error_response(ApiSpecError::ValidationFailures {
                spec_version: existing.spec_version.clone(),
                failures: vec![ValidationFailure {
                    resource_type: "plugin_graph",
                    id: existing.proxy_id.clone(),
                    errors,
                }],
            }));
        }
        Err(crate::admin::crud::AfterValidateError::Db(error)) => {
            return Ok(error_response(classify_db_error(error)));
        }
        Err(crate::admin::crud::AfterValidateError::Response(response)) => {
            return Ok(*response);
        }
    }

    let settlement_db = db.clone();
    let persistence_db = db.clone();
    let compensation_db = db.clone();
    let settlement_namespace = namespace.to_string();
    let persistence_id = id.to_string();
    let compensation_spec = existing.clone();
    let settlement_state = state.clone();
    let audit_db = db.clone();
    let audit_enabled = state.admin_audit_enabled;
    let audit_actor = actor.clone();
    let audit_spec = existing.clone();
    let persistence = match tokio::spawn(async move {
        let result = run_api_spec_persistence_while_held(
            settlement_db,
            &settlement_namespace,
            _namespace_config_admission_guard,
            persistence_db.delete_api_spec(&settlement_namespace, &persistence_id),
            compensate_late_api_spec_delete(
                compensation_db,
                previous_bundle,
                compensation_spec,
                additional_upstreams,
                additional_plugins,
                &settlement_state,
            ),
            true,
        )
        .await;
        if matches!(&result, Ok(true)) {
            let event = audit::AuditEvent::new(
                &audit_actor,
                "delete",
                "api_spec",
                &audit_spec.id,
                &audit_spec.namespace,
                audit::delete_diff(json!({
                    "id": audit_spec.id,
                    "proxy_id": audit_spec.proxy_id,
                    "content_hash": audit_spec.content_hash,
                    "spec_version": audit_spec.spec_version,
                })),
            );
            if let Err(error) = audit::record(audit_enabled, audit_db, event) {
                log_audit_enqueue_failure(&error);
            }
        }
        result
    })
    .await
    .unwrap_or_else(|error| {
        Err(ApiSpecError::Internal(format!(
            "API-spec delete persistence task failed: {error}"
        )))
    }) {
        Ok(result) => result,
        Err(error) => return Ok(error_response(error)),
    };
    if persistence {
        Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("Cache-Control", "no-store")
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))))
    } else {
        Ok(error_response(ApiSpecError::NotFound))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::HeaderMap;

    // -----------------------------------------------------------------------
    // Content-Type → SpecFormat parsing
    // -----------------------------------------------------------------------

    fn headers_with_ct(ct: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("content-type", ct.parse().unwrap());
        h
    }

    #[test]
    fn parse_content_type_json() {
        let h = headers_with_ct("application/json");
        assert_eq!(parse_content_type(&h), Some(SpecFormat::Json));
    }

    #[test]
    fn parse_content_type_json_with_charset() {
        let h = headers_with_ct("application/json; charset=utf-8");
        assert_eq!(parse_content_type(&h), Some(SpecFormat::Json));
    }

    #[test]
    fn parse_content_type_yaml_variants() {
        for ct in &[
            "application/yaml",
            "application/x-yaml",
            "text/yaml",
            "text/x-yaml",
        ] {
            let h = headers_with_ct(ct);
            assert_eq!(
                parse_content_type(&h),
                Some(SpecFormat::Yaml),
                "ct={ct} should map to Yaml"
            );
        }
    }

    #[test]
    fn parse_content_type_case_insensitive_json() {
        let h = headers_with_ct("Application/JSON");
        assert_eq!(
            parse_content_type(&h),
            Some(SpecFormat::Json),
            "Content-Type matching must be case-insensitive per RFC 7231"
        );
    }

    #[test]
    fn parse_content_type_case_insensitive_yaml() {
        let h = headers_with_ct("APPLICATION/YAML");
        assert_eq!(
            parse_content_type(&h),
            Some(SpecFormat::Yaml),
            "Content-Type matching must be case-insensitive per RFC 7231"
        );
    }

    #[test]
    fn parse_content_type_case_insensitive_text_yaml() {
        let h = headers_with_ct("Text/X-Yaml");
        assert_eq!(
            parse_content_type(&h),
            Some(SpecFormat::Yaml),
            "Content-Type matching must be case-insensitive per RFC 7231"
        );
    }

    #[test]
    fn parse_content_type_unknown_returns_none() {
        let h = headers_with_ct("text/plain");
        assert_eq!(parse_content_type(&h), None);
    }

    #[test]
    fn parse_content_type_missing_returns_none() {
        let h = HeaderMap::new();
        assert_eq!(parse_content_type(&h), None);
    }

    // -----------------------------------------------------------------------
    // Accept header negotiation
    // -----------------------------------------------------------------------

    fn headers_with_accept(accept: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("accept", accept.parse().unwrap());
        h
    }

    #[test]
    fn negotiate_accept_wildcard_returns_stored() {
        let h = headers_with_accept("*/*");
        assert_eq!(negotiate_accept(&h, SpecFormat::Yaml), SpecFormat::Yaml);
        assert_eq!(negotiate_accept(&h, SpecFormat::Json), SpecFormat::Json);
    }

    #[test]
    fn negotiate_accept_missing_returns_stored() {
        let h = HeaderMap::new();
        assert_eq!(negotiate_accept(&h, SpecFormat::Yaml), SpecFormat::Yaml);
    }

    #[test]
    fn negotiate_accept_json_with_yaml_stored_requests_json() {
        // Client wants JSON, stored is YAML → must convert
        let h = headers_with_accept("application/json");
        assert_eq!(negotiate_accept(&h, SpecFormat::Yaml), SpecFormat::Json);
    }

    #[test]
    fn negotiate_accept_yaml_with_json_stored_requests_yaml() {
        let h = headers_with_accept("application/yaml");
        assert_eq!(negotiate_accept(&h, SpecFormat::Json), SpecFormat::Yaml);
    }

    #[test]
    fn negotiate_accept_json_with_json_stored_is_identity() {
        let h = headers_with_accept("application/json");
        assert_eq!(negotiate_accept(&h, SpecFormat::Json), SpecFormat::Json);
    }

    // -----------------------------------------------------------------------
    // Format conversion
    // -----------------------------------------------------------------------

    #[test]
    fn convert_yaml_to_json_roundtrip() {
        let yaml = b"openapi: '3.0.3'\ninfo:\n  title: Test\n  version: '1.0'\n";
        let json_bytes = convert_format(yaml, SpecFormat::Yaml, SpecFormat::Json).unwrap();
        let val: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(val["openapi"].as_str(), Some("3.0.3"));
        assert_eq!(val["info"]["title"].as_str(), Some("Test"));
    }

    #[test]
    fn convert_json_to_yaml_roundtrip() {
        let json = br#"{"openapi":"3.0.3","info":{"title":"Test","version":"1.0"}}"#;
        let yaml_bytes = convert_format(json, SpecFormat::Json, SpecFormat::Yaml).unwrap();
        let val: serde_yaml::Value = serde_yaml::from_slice(&yaml_bytes).unwrap();
        let title = val["info"]["title"].as_str().unwrap_or("");
        assert_eq!(title, "Test");
    }

    #[test]
    fn convert_same_format_is_identity() {
        let input = b"hello world";
        assert_eq!(
            convert_format(input, SpecFormat::Json, SpecFormat::Json).unwrap(),
            input
        );
    }

    #[test]
    fn max_spec_decompress_bytes_saturates() {
        assert_eq!(max_spec_decompress_bytes(25), 50 * 1024 * 1024);
        assert_eq!(max_spec_decompress_bytes(usize::MAX), usize::MAX);
    }

    // -----------------------------------------------------------------------
    // Error → HTTP status mapping
    // -----------------------------------------------------------------------

    #[test]
    fn payload_too_large_maps_to_413() {
        let resp = error_response(ApiSpecError::PayloadTooLarge(25));
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn body_timed_out_maps_to_408() {
        let resp = error_response(ApiSpecError::BodyTimedOut);
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
    }

    /// Body-collection failures must surface a generic 400 with no leaked
    /// transport details — the underlying error is logged via `tracing::warn`
    /// instead. Regression guard against an earlier shape that forwarded the
    /// raw hyper error string into the response body.
    #[tokio::test]
    async fn body_collect_error_returns_generic_400() {
        let resp = error_response(ApiSpecError::BodyCollect);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = resp.into_body().collect().await.unwrap();
        let body = String::from_utf8(body.to_bytes().to_vec()).unwrap();
        assert!(body.contains("Failed to read request body"));
    }

    #[test]
    fn extract_error_maps_to_400() {
        let resp = error_response(ApiSpecError::Extract(ExtractError::MissingProxyExtension));
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn validation_failures_maps_to_422() {
        let resp = error_response(ApiSpecError::ValidationFailures {
            spec_version: "3.1.0".to_string(),
            failures: vec![],
        });
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn not_found_maps_to_404() {
        let resp = error_response(ApiSpecError::NotFound);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn conflict_maps_to_409() {
        let resp = error_response(ApiSpecError::Conflict("dup".to_string()));
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn mongo_doc_too_large_maps_to_413() {
        let resp = error_response(ApiSpecError::MongoDocTooLarge);
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn no_database_maps_to_503() {
        let resp = error_response(ApiSpecError::NoDatabase);
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn internal_maps_to_500() {
        let resp = error_response(ApiSpecError::Internal("boom".to_string()));
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // -----------------------------------------------------------------------
    // DB error string classification
    // -----------------------------------------------------------------------

    #[test]
    fn classify_unique_constraint_as_conflict() {
        assert!(matches!(
            classify_db_error_str("UNIQUE constraint failed: proxies.id"),
            ApiSpecError::Conflict(_)
        ));
    }

    #[test]
    fn classify_duplicate_key_as_conflict() {
        assert!(matches!(
            classify_db_error_str("duplicate key value violates unique constraint"),
            ApiSpecError::Conflict(_)
        ));
    }

    #[test]
    fn classify_proxy_route_conflict_as_conflict() {
        assert!(matches!(
            classify_db_error_str(PROXY_ROUTE_CONFLICT_ERROR),
            ApiSpecError::Conflict(_)
        ));
    }

    #[test]
    fn classify_mongo_doc_limit() {
        assert!(matches!(
            classify_db_error_str("MongoDB document limit exceeded for collection"),
            ApiSpecError::MongoDocTooLarge
        ));
    }

    #[test]
    fn classify_not_found_row_missing() {
        assert!(matches!(
            classify_db_error_str("RowNotFound: no rows returned"),
            ApiSpecError::NotFound
        ));
    }

    #[test]
    fn classify_typed_sqlx_row_not_found() {
        assert!(matches!(
            classify_db_error(anyhow::Error::new(sqlx::Error::RowNotFound)),
            ApiSpecError::NotFound
        ));
    }

    #[test]
    fn classify_schema_does_not_exist_as_internal() {
        assert!(matches!(
            classify_db_error_str(
                r#"error returned from database: relation "api_specs" does not exist"#
            ),
            ApiSpecError::Internal(_)
        ));
    }

    #[test]
    fn classify_column_does_not_exist_as_internal() {
        assert!(matches!(
            classify_db_error_str(
                r#"error returned from database: column "resource_hash" does not exist"#
            ),
            ApiSpecError::Internal(_)
        ));
    }

    #[test]
    fn classify_generic_error_as_internal() {
        assert!(matches!(
            classify_db_error_str("connection reset by peer"),
            ApiSpecError::Internal(_)
        ));
    }

    // -----------------------------------------------------------------------
    // List param parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_list_filter_defaults() {
        let uri: hyper::Uri = "/api-specs".parse().unwrap();
        let f = parse_list_filter(&uri).expect("parse failed");
        assert_eq!(f.limit, 50);
        assert_eq!(f.offset, 0);
    }

    #[test]
    fn parse_list_filter_custom() {
        let uri: hyper::Uri = "/api-specs?limit=10&offset=20".parse().unwrap();
        let f = parse_list_filter(&uri).expect("parse failed");
        assert_eq!(f.limit, 10);
        assert_eq!(f.offset, 20);
    }

    #[test]
    fn parse_list_filter_clamps_max() {
        let uri: hyper::Uri = "/api-specs?limit=9999".parse().unwrap();
        let f = parse_list_filter(&uri).expect("parse failed");
        assert_eq!(f.limit, 200);
    }

    #[test]
    fn parse_list_filter_invalid_updated_since_returns_400() {
        let uri: hyper::Uri = "/api-specs?updated_since=not-a-date".parse().unwrap();
        let err = parse_list_filter(&uri).unwrap_err();
        assert!(
            matches!(err, ApiSpecError::BadRequest(_)),
            "invalid updated_since must return 400; got: {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Item 5 — sort_json_keys depth limit
    // -----------------------------------------------------------------------

    #[test]
    fn test_sort_json_keys_depth_limit() {
        // Build a 50-level-deep nested object.  sort_json_keys caps at
        // MAX_SORT_JSON_DEPTH (32), so the call must return Err.
        let mut inner = serde_json::json!({"leaf": "value"});
        for _ in 0..50 {
            inner = serde_json::json!({"nested": inner});
        }
        let result = sort_json_keys(&inner, MAX_SORT_JSON_DEPTH);
        assert!(
            result.is_err(),
            "sort_json_keys must reject configs nested deeper than MAX_SORT_JSON_DEPTH ({})",
            MAX_SORT_JSON_DEPTH
        );
    }

    // -----------------------------------------------------------------------
    // Item 8 — title_contains wildcard rejection
    // -----------------------------------------------------------------------

    #[test]
    fn list_with_title_contains_wildcard_returns_400_percent() {
        let uri: hyper::Uri = "/api-specs?title_contains=foo%25bar".parse().unwrap();
        let err = parse_list_filter(&uri).unwrap_err();
        assert!(
            matches!(err, ApiSpecError::BadRequest(_)),
            "percent-sign in title_contains must return 400; got: {err:?}"
        );
    }

    #[test]
    fn list_with_title_contains_wildcard_returns_400_underscore() {
        // `_` is a SQL single-char wildcard; literal underscore must be rejected.
        let uri: hyper::Uri = "/api-specs?title_contains=foo_bar".parse().unwrap();
        let err = parse_list_filter(&uri).unwrap_err();
        assert!(
            matches!(err, ApiSpecError::BadRequest(_)),
            "underscore in title_contains must return 400; got: {err:?}"
        );
    }

    #[test]
    fn list_with_title_contains_wildcard_returns_400_backslash() {
        // URL-encode the backslash (%5C) so the URI parses.
        let uri: hyper::Uri = "/api-specs?title_contains=foo%5Cbar".parse().unwrap();
        let err = parse_list_filter(&uri).unwrap_err();
        assert!(
            matches!(err, ApiSpecError::BadRequest(_)),
            "backslash in title_contains must return 400; got: {err:?}"
        );
    }

    #[test]
    fn list_with_title_contains_plain_text_is_allowed() {
        let uri: hyper::Uri = "/api-specs?title_contains=MyApi".parse().unwrap();
        let f = parse_list_filter(&uri).expect("plain text must be allowed");
        assert_eq!(
            f.title_contains.as_deref(),
            Some("MyApi"),
            "plain title_contains must be accepted unchanged"
        );
    }

    // -----------------------------------------------------------------------
    // Item 10 — percent_decode rejects invalid UTF-8
    // -----------------------------------------------------------------------

    #[test]
    fn list_with_invalid_percent_encoding_returns_400() {
        // %80 is an invalid UTF-8 lead byte (continuation byte without start byte).
        let uri: hyper::Uri = "/api-specs?title_contains=%80invalid".parse().unwrap();
        let err = parse_list_filter(&uri).unwrap_err();
        assert!(
            matches!(err, ApiSpecError::BadRequest(_)),
            "invalid percent-encoding must return 400; got: {err:?}"
        );
    }

    #[test]
    fn percent_decode_valid_ascii_sequence() {
        // %41 = 'A', %42 = 'B' — valid UTF-8, must decode correctly.
        assert_eq!(percent_decode("%41%42C").unwrap(), "ABC");
    }

    #[test]
    fn percent_decode_invalid_utf8_returns_err() {
        // %ED%A0%80 is a surrogate code point — invalid UTF-8.
        assert!(
            percent_decode("%ED%A0%80").is_err(),
            "invalid UTF-8 byte sequence must be rejected"
        );
    }
}
