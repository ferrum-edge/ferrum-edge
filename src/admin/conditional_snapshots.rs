//! Explicit, fail-closed verification and namespace replacement contracts.

use std::collections::{BTreeMap, HashSet};

use bytes::Bytes;
use chrono::Utc;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use serde_json::json;

use super::audit::{self, AuditActor};
use super::backup::{
    ApiSpecsBackupSection, BackupCounts, BackupPayload, ConditionalBackupMetadata, RestorePayload,
};
use super::crud::{self, AdminResource};
use super::preconditions::{self, IfMatch};
use super::{AdminState, BackupExportPayload, json_response};
use crate::config::db_backend::{
    AtomicBatchGraph, BatchConfigWriteMode, ConditionalNamespaceRestore,
    ConditionalNamespaceSnapshot, DatabaseBackend, NamespacePreconditionFailed,
    NamespaceSnapshotTooLarge, SnapshotDigest, is_namespace_snapshot_too_large,
};
use crate::config::types::{Consumer, PluginConfig, Proxy, Upstream, validate_resource_id};

pub(super) fn parse_backup_opt_in(query: Option<&str>) -> Result<bool, &'static str> {
    let mut found = None;
    for (key, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        if key == "conditional" {
            if found.is_some() || !matches!(value.as_ref(), "true" | "false") {
                return Err("conditional must occur once with value true or false");
            }
            found = Some(value == "true");
        }
    }
    Ok(found.unwrap_or(false))
}

/// MAC domain for namespace snapshot tags. `v2` digests stored spec content
/// instead of embedding it; `v1` tags issued before that change no longer
/// match and fail closed with `412`.
const NAMESPACE_SNAPSHOT_TAG_KIND: &str = "namespace_snapshot.v2";

fn namespace_tag(
    state: &AdminState,
    namespace: &str,
    digest: &SnapshotDigest,
) -> Result<String, anyhow::Error> {
    let key = state
        .jwt_manager
        .resource_etag_key()
        .ok_or_else(|| anyhow::anyhow!("Namespace ETag key unavailable"))?;
    Ok(preconditions::snapshot_etag(&key, NAMESPACE_SNAPSHOT_TAG_KIND, namespace, digest))
}

fn row_tags<R: AdminResource>(
    state: &AdminState,
    rows: &[R],
) -> Result<BTreeMap<String, String>, anyhow::Error> {
    rows.iter()
        .map(|row| {
            let tag = crud::current_etag(state, row)
                .ok_or_else(|| anyhow::anyhow!("Resource ETag unavailable"))?;
            Ok((row.id().to_string(), preconditions::quoted(&tag)))
        })
        .collect()
}

fn unavailable() -> Response<Full<Bytes>> {
    json_response(
        StatusCode::SERVICE_UNAVAILABLE,
        &json!({"error": "Authoritative conditional snapshot unavailable"}),
    )
}

/// `507`: the namespace is too large to fence; nothing was materialized or applied.
pub(super) fn snapshot_too_large() -> Response<Full<Bytes>> {
    json_response(
        StatusCode::INSUFFICIENT_STORAGE,
        &json!({"error": NamespaceSnapshotTooLarge.to_string()}),
    )
}

fn store_error(error: &anyhow::Error) -> Response<Full<Bytes>> {
    if is_namespace_snapshot_too_large(error) {
        return snapshot_too_large();
    }
    if let Some(unsupported) = crate::config::db_backend::atomic_batch_unsupported(error) {
        return super::atomic_batch_unsupported_response(unsupported);
    }
    if error
        .chain()
        .any(|cause| cause.is::<NamespacePreconditionFailed>())
    {
        return json_response(
            StatusCode::PRECONDITION_FAILED,
            &json!({"error": "Namespace changed; conditional restore was not applied"}),
        );
    }
    // No raw driver errors: they may contain stored credential material.
    super::warn_persistence_failure_redacted("conditional_namespace_operation");
    unavailable()
}

pub(super) async fn consumer_verification(
    state: &AdminState,
    actor: &AuditActor,
    id: &str,
    namespace: &str,
    request_ctx: &audit::AuditRequestContext,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Err(message) = validate_resource_id(id) {
        return Ok(json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": message}),
        ));
    }
    let Some(db) = &state.db else {
        return Ok(unavailable());
    };
    let consumer = match db.get_consumer(namespace, id).await {
        Ok(Some(consumer)) => consumer,
        Ok(None) => {
            return Ok(json_response(
                StatusCode::NOT_FOUND,
                &json!({"error": "Consumer not found"}),
            ));
        }
        Err(error) => return Ok(store_error(&error)),
    };
    let Some(tag) = crud::current_etag(state, &consumer) else {
        return Ok(unavailable());
    };
    let body = match serde_json::to_value(&consumer) {
        Ok(body) => body,
        Err(_) => return Ok(unavailable()),
    };
    let event = audit::AuditEvent::new(
        actor,
        "consumer_verification",
        "consumer",
        id,
        namespace,
        json!({"credential_complete": true}),
    )
    .with_request_context(request_ctx)
    .with_outcome(audit::outcome::SUCCESS);
    if audit::admit_security_sensitive_event(
        state.db.as_ref(),
        &event,
        state.admin_audit_fallback_dir.as_deref(),
    )
    .await
    .is_err()
    {
        return Ok(super::backup_audit_admit_failed_response());
    }
    let response = json_response(StatusCode::OK, &body);
    Ok(with_tag(response, &preconditions::quoted(&tag)))
}

fn with_tag(mut response: Response<Full<Bytes>>, tag: &str) -> Response<Full<Bytes>> {
    let Ok(value) = hyper::header::HeaderValue::from_str(tag) else {
        return unavailable();
    };
    response.headers_mut().insert(hyper::header::ETAG, value);
    response.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("no-store"),
    );
    response
}

fn serialize_snapshot(
    state: &AdminState,
    namespace: &str,
    snapshot: &ConditionalNamespaceSnapshot,
) -> Result<(Vec<u8>, String), anyhow::Error> {
    let config = &snapshot.config;
    let tag = namespace_tag(state, namespace, &snapshot.digest()?)?;
    let metadata = ConditionalBackupMetadata {
        namespace_etag: preconditions::quoted(&tag),
        row_etags: BTreeMap::from([
            ("proxies", row_tags::<Proxy>(state, &config.proxies)?),
            ("consumers", row_tags::<Consumer>(state, &config.consumers)?),
            ("upstreams", row_tags::<Upstream>(state, &config.upstreams)?),
            (
                "plugin_configs",
                row_tags::<PluginConfig>(state, &config.plugin_configs)?,
            ),
        ]),
    };
    let specs = ApiSpecsBackupSection::from_specs(&snapshot.api_specs);
    let backup = BackupPayload {
        version: &config.version,
        ferrum_version: crate::FERRUM_VERSION,
        exported_at: Utc::now().to_rfc3339(),
        source: "database",
        counts: BackupCounts {
            proxies: config.proxies.len(),
            consumers: config.consumers.len(),
            upstreams: config.upstreams.len(),
            plugin_configs: config.plugin_configs.len(),
            api_specs: snapshot.api_specs.len(),
            gateway_trust_bundles: config.gateway_trust_bundles.len(),
        },
        proxies: &config.proxies,
        consumers: &config.consumers,
        upstreams: &config.upstreams,
        plugin_configs: &config.plugin_configs,
        api_specs: Some(&specs),
        gateway_trust_bundles: Some(&config.gateway_trust_bundles),
        conditional: Some(&metadata),
    };
    Ok((serde_json::to_vec(&backup)?, metadata.namespace_etag))
}

pub(super) async fn backup(
    state: &AdminState,
    actor: &AuditActor,
    namespace: &str,
    request_ctx: &audit::AuditRequestContext,
    resource_filter: Option<&HashSet<&str>>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let result = async {
        if resource_filter.is_some() {
            return Err(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": "Conditional backup requires a full unfiltered namespace export"}),
            ));
        }
        let db = state.db.as_ref().ok_or_else(unavailable)?;
        let snapshot = db
            .load_conditional_namespace_snapshot(namespace)
            .await
            .map_err(|error| store_error(&error))?;
        let (body_bytes, tag) = serialize_snapshot(state, namespace, &snapshot).map_err(|error| {
            if is_namespace_snapshot_too_large(&error) {
                snapshot_too_large()
            } else {
                unavailable()
            }
        })?;
        let config = snapshot.config;
        let response = super::finalize_backup_export(
            state,
            actor,
            namespace,
            request_ctx,
            BackupExportPayload {
                resource_filter: None,
                source: "database",
                body_bytes,
                proxy_count: config.proxies.len(),
                consumer_count: config.consumers.len(),
                plugin_config_count: config.plugin_configs.len(),
                upstream_count: config.upstreams.len(),
                api_specs_count: snapshot.api_specs.len(),
                gateway_trust_bundles_count: config.gateway_trust_bundles.len(),
            },
        )
        .await;
        Ok((response, tag))
    }
    .await;
    match result {
        Ok((response, tag)) => Ok(if response.status().is_success() {
            with_tag(response, &tag)
        } else {
            response
        }),
        Err(response) => {
            let category = if response.status() == StatusCode::BAD_REQUEST {
                audit::failure_category::VALIDATION_FAILED
            } else {
                audit::failure_category::UNAVAILABLE
            };
            super::audit_backup_failure(
                state,
                actor,
                namespace,
                request_ctx,
                resource_filter,
                category,
                if response.status() == StatusCode::BAD_REQUEST {
                    audit::outcome::VALIDATION_FAILED
                } else {
                    audit::outcome::UNAVAILABLE
                },
            )
            .await;
            Ok(response)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn restore(
    state: &AdminState,
    actor: &AuditActor,
    db: &dyn DatabaseBackend,
    namespace: &str,
    payload: &RestorePayload,
    if_match: &IfMatch,
    mode: &BatchConfigWriteMode,
    admission: &mut crud::NamespaceConfigAdmissionGuard,
) -> Response<Full<Bytes>> {
    let snapshot = match db.load_conditional_namespace_snapshot(namespace).await {
        Ok(snapshot) => snapshot,
        Err(error) => return store_error(&error),
    };
    let expected = match snapshot.digest() {
        Ok(digest) => digest,
        Err(error) => return store_error(&error),
    };
    // Release the snapshot before the replacement transaction reads its own.
    drop(snapshot);
    let tag = match namespace_tag(state, namespace, &expected) {
        Ok(tag) => tag,
        Err(_) => return unavailable(),
    };
    if !if_match.matches(Some(&tag)) {
        return store_error(&anyhow::Error::new(NamespacePreconditionFailed));
    }
    let specs = match payload
        .api_specs
        .as_ref()
        .map(|section| section.to_api_specs())
        .transpose()
    {
        Ok(specs) => specs.unwrap_or_default(),
        Err(_) => return unavailable(),
    };
    if admission.hand_off_to_restore_transaction().await.is_err() {
        return unavailable();
    }
    let restore = ConditionalNamespaceRestore {
        graph: AtomicBatchGraph {
            namespace,
            consumers: &payload.consumers,
            upstreams: &payload.upstreams,
            proxies: &payload.proxies,
            plugin_configs: &payload.plugin_configs,
            admission_lease: Some(admission.lease_ref()),
        },
        expected,
        api_specs: &specs,
        gateway_trust_bundles: payload.gateway_trust_bundles.as_deref(),
    };
    if let Err(error) = db.restore_namespace_conditionally(&restore, mode).await {
        return store_error(&error);
    }
    let response = json!({"restored": {
        "proxies": payload.proxies.len(),
        "consumers": payload.consumers.len(),
        "plugin_configs": payload.plugin_configs.len(),
        "upstreams": payload.upstreams.len(),
        "api_specs": specs.len(),
        "gateway_trust_bundles": payload.gateway_trust_bundles.as_ref().map_or(0, Vec::len),
    }});
    let event = audit::AuditEvent::new(
        actor,
        "restore",
        "gateway_config",
        namespace,
        namespace,
        audit::update_diff(
            json!({"replaced_namespace": namespace}),
            response["restored"].clone(),
        ),
    );
    if let Some(db) = &state.db
        && let Err(error) = audit::record(state.admin_audit_enabled, db.clone(), event).await
    {
        super::log_audit_enqueue_failure(&error);
    }
    json_response(StatusCode::OK, &response)
}
