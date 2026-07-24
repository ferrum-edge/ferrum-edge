use bytes::Bytes;
use chrono::{DateTime, Utc};
use http_body_util::Full;
use hyper::{Response, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::collections::{HashSet, hash_map::DefaultHasher};
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, MutexGuard};
use uuid::Uuid;

use crate::admin::AdminState;
use crate::admin::audit::{self, AuditActor, AuditEvent};
use crate::admin::jwt_auth::AdminRole;
use crate::config::db_backend::{
    BatchConfigWriteMode, DatabaseBackend, MTLS_DNS_ADMISSION_UNAVAILABLE_MESSAGE,
    PROXY_ROUTE_CONFLICT_ERROR, PaginatedResult, is_mtls_dns_admission_unavailable,
    is_mtls_dns_identity_conflict, mark_mtls_dns_admission_unavailable, mtls_dns_identity_conflict,
    tcp_connection_throttle_attachment_conflict, validate_api_spec_proxy_plugin_association,
    validate_api_spec_restore_inputs,
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

enum LateResourceWrite<'a> {
    Create,
    Update { id: &'a str },
    Delete { id: &'a str },
}

pub(crate) enum InterveningWriteRecovery {
    Compensate,
    KeepCurrent,
}

pub(crate) struct ApiSpecDeleteSnapshot {
    spec: crate::config::types::ApiSpec,
    upstream: Option<Upstream>,
    plugins: Vec<PluginConfig>,
    additional_upstreams: Vec<Upstream>,
    additional_plugins: Vec<PluginConfig>,
}

#[derive(Debug)]
struct ApiSpecRestoreSnapshotValidation(String);

impl std::fmt::Display for ApiSpecRestoreSnapshotValidation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ApiSpecRestoreSnapshotValidation {}

fn api_spec_restore_snapshot_validation(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(ApiSpecRestoreSnapshotValidation(message.into()))
}

#[derive(Clone, Copy)]
struct LateDeleteSnapshots<'a> {
    config: &'a GatewayConfig,
    api_spec: Option<&'a ApiSpecDeleteSnapshot>,
}

struct LateResourceRecovery<'a, R> {
    written: Option<&'a R>,
    previous: Option<&'a R>,
    delete_snapshots: Option<LateDeleteSnapshots<'a>>,
}

struct OwnedLateDeleteRecovery<R> {
    previous: R,
    config: Option<GatewayConfig>,
    api_spec: Option<ApiSpecDeleteSnapshot>,
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

const NAMESPACE_CONFIG_ADMISSION_LOCK_SHARDS: usize = 64;
static NAMESPACE_CONFIG_ADMISSION_LOCKS: OnceLock<Vec<Mutex<()>>> = OnceLock::new();
const CONFIG_ADMISSION_LEASE_DURATION: Duration = Duration::from_secs(120);
const CONFIG_ADMISSION_LEASE_RENEW_INTERVAL: Duration = Duration::from_secs(30);
const CONFIG_ADMISSION_LEASE_RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// Serialize graph- and credential-sensitive admin mutations for a namespace
/// from candidate validation through persistence. A bounded process-global
/// lock set is the cheap first tier; the datastore lease below coordinates
/// writable gateway instances that share SQL or MongoDB persistence.
///
/// SQL transactions and MongoDB leases provide the authoritative cross-process
/// backstop. The additional ASCII-folded `san_dns` constraint is conditional on
/// effective plugin associations, so it cannot use an unconditional case-folded
/// unique index without rejecting valid case variants used by exact-match
/// policies. This lock avoids redundant same-process candidate work while the
/// backend serialization covers separate admin processes.
/// Every credential mutation takes this lock, even for non-mTLS types, because
/// those endpoints persist the complete `Consumer` and could otherwise replay
/// stale `mtls_auth` entries loaded before a concurrent mTLS mutation. Every
/// plugin-graph mutation (including API-spec bundles) uses the same lock so a
/// prospective transaction-log schema snapshot remains authoritative until
/// the corresponding write commits.
pub(crate) async fn lock_local_namespace_config_admission(
    namespace: &str,
) -> MutexGuard<'static, ()> {
    let locks = NAMESPACE_CONFIG_ADMISSION_LOCKS.get_or_init(|| {
        (0..NAMESPACE_CONFIG_ADMISSION_LOCK_SHARDS)
            .map(|_| Mutex::new(()))
            .collect()
    });
    let mut hasher = DefaultHasher::new();
    namespace.hash(&mut hasher);
    let shard = hasher.finish() as usize % NAMESPACE_CONFIG_ADMISSION_LOCK_SHARDS;
    locks[shard].lock().await
}

fn validate_candidate_plugin_graph(
    candidate: &GatewayConfig,
    http_client: &crate::plugins::PluginHttpClient,
) -> Result<(), AfterValidateError> {
    crate::plugin_cache::validate_plugin_composition_candidate(candidate, http_client)
        .map_err(|error| AfterValidateError::BadRequest(vec![error]))?;
    crate::plugin_cache::validate_tcp_connection_throttle_attachments(candidate)
        .map_err(AfterValidateError::BadRequest)
}

pub(crate) struct NamespaceConfigAdmissionGuard {
    local: Option<MutexGuard<'static, ()>>,
    db: Option<Arc<dyn DatabaseBackend>>,
    namespace: String,
    owner: String,
    generation: u64,
    stop_tx: Option<tokio::sync::watch::Sender<bool>>,
    renew_task: Option<tokio::task::JoinHandle<()>>,
    valid: Arc<AtomicBool>,
    lease_started_at: Instant,
    valid_until_millis: Arc<AtomicU64>,
    lease_state_rx: tokio::sync::watch::Receiver<u64>,
}

pub(crate) enum NamespaceConfigAdmissionCompletion<T> {
    Held(T),
    Lost { result: T, error: anyhow::Error },
}

impl NamespaceConfigAdmissionGuard {
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn immediately_succeeds_generation(&self, previous: u64) -> bool {
        previous.checked_add(1) == Some(self.generation)
    }

    pub(crate) fn ensure_held(&self) -> Result<(), anyhow::Error> {
        let elapsed_millis =
            u64::try_from(self.lease_started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        if self.valid.load(Ordering::Acquire)
            && elapsed_millis < self.valid_until_millis.load(Ordering::Acquire)
        {
            Ok(())
        } else {
            anyhow::bail!("namespace config admission lease was lost before persistence")
        }
    }

    /// Run a persistence operation that is not cancellation-safe to a concrete
    /// result while still observing the admission lease. If ownership is lost,
    /// the caller receives both the completed result and the lease error so it
    /// can verify or compensate under a newly acquired lease.
    pub(crate) async fn run_to_completion_while_held<F, T>(
        &self,
        future: F,
    ) -> Result<NamespaceConfigAdmissionCompletion<T>, anyhow::Error>
    where
        F: Future<Output = T>,
    {
        self.ensure_held()?;
        let mut lease_state_rx = self.lease_state_rx.clone();
        tokio::pin!(future);
        let persistence_started = AtomicBool::new(false);
        loop {
            let valid_until_millis = *lease_state_rx.borrow_and_update();
            let elapsed_millis =
                u64::try_from(self.lease_started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
            if valid_until_millis == 0 || elapsed_millis >= valid_until_millis {
                if !persistence_started.load(Ordering::Acquire) {
                    anyhow::bail!(
                        "namespace config admission lease was lost before persistence started"
                    );
                }
                let result = future.await;
                return Ok(NamespaceConfigAdmissionCompletion::Lost {
                    result,
                    error: anyhow::anyhow!(
                        "namespace config admission lease was lost during persistence"
                    ),
                });
            }
            let remaining = Duration::from_millis(valid_until_millis - elapsed_millis);
            tokio::select! {
                biased;
                changed = lease_state_rx.changed() => {
                    if changed.is_err() {
                        if !persistence_started.load(Ordering::Acquire) {
                            anyhow::bail!(
                                "namespace config admission lease monitor stopped before persistence started"
                            );
                        }
                        let result = future.await;
                        return Ok(NamespaceConfigAdmissionCompletion::Lost {
                            result,
                            error: anyhow::anyhow!(
                                "namespace config admission lease monitor stopped during persistence"
                            ),
                        });
                    }
                }
                _ = tokio::time::sleep(remaining) => {
                    if !persistence_started.load(Ordering::Acquire) {
                        anyhow::bail!(
                            "namespace config admission lease expired before persistence started"
                        );
                    }
                    let result = future.await;
                    return Ok(NamespaceConfigAdmissionCompletion::Lost {
                        result,
                        error: anyhow::anyhow!(
                            "namespace config admission lease expired during persistence"
                        ),
                    });
                }
                result = std::future::poll_fn(|context| {
                    persistence_started.store(true, Ordering::Release);
                    future.as_mut().poll(context)
                }) => {
                    return Ok(match self.ensure_held() {
                        Ok(()) => NamespaceConfigAdmissionCompletion::Held(result),
                        Err(error) => NamespaceConfigAdmissionCompletion::Lost { result, error },
                    });
                }
            }
        }
    }
}

impl Drop for NamespaceConfigAdmissionGuard {
    fn drop(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(true);
        }
        let Some(db) = self.db.take() else {
            return;
        };
        let namespace = std::mem::take(&mut self.namespace);
        let owner = std::mem::take(&mut self.owner);
        let renew_task = self.renew_task.take();
        let local = self.local.take();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                if let Some(task) = renew_task {
                    task.abort();
                    let _ = task.await;
                }
                match tokio::time::timeout(
                    CONFIG_ADMISSION_LEASE_RETRY_INTERVAL,
                    db.release_namespace_config_admission_lease(&namespace, &owner),
                )
                .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(_error)) => {
                        super::warn_persistence_failure_redacted(
                            "namespace_admission_lease_release",
                        );
                    }
                    Err(_) => {
                        tracing::warn!(
                            namespace = %namespace,
                            "Timed out releasing namespace config admission lease; expiry will recover it"
                        );
                    }
                }
                drop(local);
            });
        }
    }
}

async fn release_namespace_config_admission_claim(
    db: &dyn DatabaseBackend,
    namespace: &str,
    owner: &str,
    context: &'static str,
) {
    match tokio::time::timeout(
        CONFIG_ADMISSION_LEASE_RETRY_INTERVAL,
        db.release_namespace_config_admission_lease(namespace, owner),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(_error)) => {
            super::warn_persistence_failure_redacted("namespace_admission_claim_release");
        }
        Err(_) => tracing::warn!(
            %namespace,
            "Timed out releasing {context}; expiry will recover it"
        ),
    }
}

struct PendingNamespaceConfigAdmissionClaim {
    db: Arc<dyn DatabaseBackend>,
    namespace: String,
    owner: String,
    lease_started_at: Instant,
    generation: u64,
    armed: bool,
}

impl PendingNamespaceConfigAdmissionClaim {
    fn into_acquired(mut self) -> (Instant, u64) {
        self.armed = false;
        (self.lease_started_at, self.generation)
    }
}

impl Drop for PendingNamespaceConfigAdmissionClaim {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let db = self.db.clone();
        let namespace = self.namespace.clone();
        let owner = self.owner.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let _cleanup_task = runtime.spawn(async move {
                release_namespace_config_admission_claim(
                    db.as_ref(),
                    &namespace,
                    &owner,
                    "a cancelled namespace config admission acquisition",
                )
                .await;
            });
        }
    }
}

pub(crate) async fn lock_namespace_config_admission(
    db: Arc<dyn DatabaseBackend>,
    namespace: &str,
) -> Result<NamespaceConfigAdmissionGuard, anyhow::Error> {
    let local = lock_local_namespace_config_admission(namespace).await;
    let owner = Uuid::new_v4().to_string();
    let (lease_started_at, generation) = loop {
        let acquire_db = db.clone();
        let acquire_namespace = namespace.to_string();
        let acquire_owner = owner.clone();
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let _acquire_task = tokio::spawn(async move {
            let attempt_started_at = Instant::now();
            let result = acquire_db
                .try_acquire_namespace_config_admission_lease(&acquire_namespace, &acquire_owner)
                .await;

            // An error can be an ambiguous datastore outcome. Make one
            // owner-qualified release attempt before reporting it. If the
            // request disappeared while acquisition was in flight, an
            // acquired claim is likewise released instead of waiting for its
            // full lease expiry.
            if result.is_err() {
                release_namespace_config_admission_claim(
                    acquire_db.as_ref(),
                    &acquire_namespace,
                    &acquire_owner,
                    "an ambiguous namespace config admission acquisition",
                )
                .await;
            }

            let result = result.map(|generation| {
                generation.map(|generation| PendingNamespaceConfigAdmissionClaim {
                    db: acquire_db,
                    namespace: acquire_namespace,
                    owner: acquire_owner,
                    lease_started_at: attempt_started_at,
                    generation,
                    armed: true,
                })
            });
            // If the receiver disappeared before or after this send, the
            // undelivered/queued claim is dropped and starts cleanup.
            let _ = result_tx.send(result);
        });
        if let Some(claim) = result_rx.await.map_err(|_| {
            anyhow::anyhow!("namespace config admission acquisition task stopped unexpectedly")
        })?? {
            break claim.into_acquired();
        }
        tokio::time::sleep(CONFIG_ADMISSION_LEASE_RETRY_INTERVAL).await;
    };

    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let renew_db = db.clone();
    let renew_namespace = namespace.to_string();
    let renew_owner = owner.clone();
    let valid = Arc::new(AtomicBool::new(true));
    let renew_valid = valid.clone();
    let lease_duration_millis =
        u64::try_from(CONFIG_ADMISSION_LEASE_DURATION.as_millis()).unwrap_or(u64::MAX);
    let valid_until_millis = Arc::new(AtomicU64::new(lease_duration_millis));
    let renew_valid_until_millis = valid_until_millis.clone();
    let (lease_state_tx, lease_state_rx) = tokio::sync::watch::channel(lease_duration_millis);
    let renew_task = tokio::spawn(async move {
        let mut valid_until = lease_started_at + CONFIG_ADMISSION_LEASE_DURATION;
        loop {
            tokio::select! {
                changed = stop_rx.changed() => {
                    if changed.is_err() || *stop_rx.borrow() {
                        return;
                    }
                }
                _ = tokio::time::sleep(CONFIG_ADMISSION_LEASE_RENEW_INTERVAL) => {}
            }

            loop {
                let renewal_started_at = Instant::now();
                match renew_db
                    .renew_namespace_config_admission_lease(&renew_namespace, &renew_owner)
                    .await
                {
                    Ok(true) => {
                        valid_until = renewal_started_at + CONFIG_ADMISSION_LEASE_DURATION;
                        let elapsed_millis = u64::try_from(
                            renewal_started_at
                                .duration_since(lease_started_at)
                                .as_millis(),
                        )
                        .unwrap_or(u64::MAX);
                        renew_valid_until_millis.store(
                            elapsed_millis.saturating_add(lease_duration_millis),
                            Ordering::Release,
                        );
                        let _ = lease_state_tx
                            .send(elapsed_millis.saturating_add(lease_duration_millis));
                        break;
                    }
                    Ok(false) => {
                        renew_valid.store(false, Ordering::Release);
                        let _ = lease_state_tx.send(0);
                        tracing::error!(
                            namespace = %renew_namespace,
                            "Namespace config admission lease renewal lost ownership"
                        );
                        return;
                    }
                    Err(_error) => {
                        if Instant::now() + CONFIG_ADMISSION_LEASE_RETRY_INTERVAL >= valid_until {
                            renew_valid.store(false, Ordering::Release);
                            let _ = lease_state_tx.send(0);
                            super::error_persistence_failure_redacted(
                                "namespace_admission_lease_renewal_expired",
                            );
                            return;
                        }
                        super::debug_persistence_failure_redacted(
                            "namespace_admission_lease_renewal_retry",
                        );
                        tokio::select! {
                            changed = stop_rx.changed() => {
                                if changed.is_err() || *stop_rx.borrow() {
                                    return;
                                }
                            }
                            _ = tokio::time::sleep(CONFIG_ADMISSION_LEASE_RETRY_INTERVAL) => {}
                        }
                    }
                }
            }
        }
    });

    Ok(NamespaceConfigAdmissionGuard {
        local: Some(local),
        db: Some(db),
        namespace: namespace.to_string(),
        owner,
        generation,
        stop_tx: Some(stop_tx),
        renew_task: Some(renew_task),
        valid,
        lease_started_at,
        valid_until_millis,
        lease_state_rx,
    })
}

async fn run_db_write_while_held<T, F>(
    guard: Option<&NamespaceConfigAdmissionGuard>,
    future: F,
) -> Result<NamespaceConfigAdmissionCompletion<DbResult<T>>, anyhow::Error>
where
    F: Future<Output = DbResult<T>>,
{
    match guard {
        Some(guard) => guard.run_to_completion_while_held(future).await,
        None => Ok(NamespaceConfigAdmissionCompletion::Held(future.await)),
    }
}

async fn plugin_has_proxy_association(
    db: &dyn DatabaseBackend,
    namespace: &str,
    plugin_id: &str,
) -> DbResult<bool> {
    let mut offset = 0_i64;
    const PAGE_SIZE: i64 = 1_000;
    loop {
        let page = db
            .list_proxies_paginated(namespace, PAGE_SIZE, offset)
            .await?;
        let items_len = page.items.len() as i64;
        if page.items.iter().any(|proxy| {
            proxy
                .plugins
                .iter()
                .any(|association| association.plugin_config_id == plugin_id)
        }) {
            return Ok(true);
        }
        if items_len == 0 || offset + items_len >= page.total {
            return Ok(false);
        }
        offset += items_len;
    }
}

async fn proxy_has_scoped_plugin(
    db: &dyn DatabaseBackend,
    namespace: &str,
    proxy_id: &str,
) -> DbResult<bool> {
    let mut offset = 0_i64;
    const PAGE_SIZE: i64 = 1_000;
    loop {
        let page = db
            .list_plugin_configs_paginated(namespace, PAGE_SIZE, offset)
            .await?;
        let items_len = page.items.len() as i64;
        if page
            .items
            .iter()
            .any(|plugin| plugin.proxy_id.as_deref() == Some(proxy_id))
        {
            return Ok(true);
        }
        if items_len == 0 || offset + items_len >= page.total {
            return Ok(false);
        }
        offset += items_len;
    }
}

/// Reacquire namespace admission after a successful late write. With no
/// intervening claimant, the original validation remains authoritative. If a
/// writer did intervene, undo only the still-current late delta; a later
/// same-resource mutation supersedes the delta and is left intact.
async fn recover_late_resource_write<R: AdminResource>(
    db: Arc<dyn DatabaseBackend>,
    namespace: &str,
    lost_generation: u64,
    http_client: crate::plugins::PluginHttpClient,
    action: LateResourceWrite<'_>,
    recovery: LateResourceRecovery<'_, R>,
) -> Result<bool, anyhow::Error> {
    let recovery_guard = lock_namespace_config_admission(db.clone(), namespace).await?;
    if recovery_guard.immediately_succeeds_generation(lost_generation) {
        return Ok(true);
    }
    if matches!(
        &action,
        LateResourceWrite::Update { .. } | LateResourceWrite::Delete { .. }
    ) && matches!(
        R::intervening_write_recovery(
            db.as_ref(),
            namespace,
            recovery.previous,
            http_client.clone(),
        )
        .await?,
        InterveningWriteRecovery::KeepCurrent
    ) {
        return Ok(false);
    }

    let compensation = async {
        match action {
            LateResourceWrite::Create => {
                let written = recovery.written.ok_or_else(|| {
                    anyhow::anyhow!("late create recovery is missing the written resource")
                })?;
                if let Some(current) =
                    R::db_get_for_write(db.as_ref(), namespace, written.id()).await?
                    && R::late_create_compensation_safe(
                        db.as_ref(),
                        namespace,
                        &current,
                        written,
                        recovery.delete_snapshots.map(|snapshots| snapshots.config),
                        http_client,
                    )
                    .await?
                    && !R::db_delete(db.as_ref(), namespace, written.id()).await?
                {
                    anyhow::bail!("late create compensation found no matching resource");
                }
            }
            LateResourceWrite::Update { id } => {
                let written = recovery.written.ok_or_else(|| {
                    anyhow::anyhow!("late update recovery is missing the written resource")
                })?;
                let previous = recovery.previous.ok_or_else(|| {
                    anyhow::anyhow!("late update recovery is missing the prior resource")
                })?;
                if R::db_get_for_write(db.as_ref(), namespace, id)
                    .await?
                    .is_some_and(|current| current.updated_at() == written.updated_at())
                    && !R::db_update(db.as_ref(), previous).await?
                {
                    anyhow::bail!("late update compensation found no matching resource");
                }
            }
            LateResourceWrite::Delete { id } => {
                let previous = recovery.previous.ok_or_else(|| {
                    anyhow::anyhow!("late delete recovery is missing the prior resource")
                })?;
                if R::db_get_for_write(db.as_ref(), namespace, id)
                    .await?
                    .is_none()
                {
                    R::compensate_late_delete(
                        db.as_ref(),
                        namespace,
                        previous,
                        recovery.delete_snapshots.map(|snapshots| snapshots.config),
                        recovery
                            .delete_snapshots
                            .and_then(|snapshots| snapshots.api_spec),
                        http_client,
                    )
                    .await?;
                }
            }
        }
        Ok(())
    };
    match recovery_guard
        .run_to_completion_while_held(compensation)
        .await?
    {
        NamespaceConfigAdmissionCompletion::Held(result) => result?,
        NamespaceConfigAdmissionCompletion::Lost { result, error } => {
            result?;
            return Err(error);
        }
    }
    Ok(false)
}

struct OwnedWriteSettlementContext {
    db: Arc<dyn DatabaseBackend>,
    namespace: String,
    guard: Option<NamespaceConfigAdmissionGuard>,
    http_client: crate::plugins::PluginHttpClient,
    state: AdminState,
    actor: AuditActor,
}

async fn persist_create_to_settlement<R: AdminResource>(
    context: OwnedWriteSettlementContext,
    written: R,
) -> DbResult<()> {
    let OwnedWriteSettlementContext {
        db,
        namespace,
        mut guard,
        http_client,
        state,
        actor,
    } = context;
    let success_db = db.clone();
    let result = match run_db_write_while_held(guard.as_ref(), R::db_create(db.as_ref(), &written))
        .await
    {
        Ok(NamespaceConfigAdmissionCompletion::Held(result)) => result,
        Ok(NamespaceConfigAdmissionCompletion::Lost { result, error: _ }) => match result {
            Ok(()) => {
                let lost_generation = guard
                    .as_ref()
                    .map(NamespaceConfigAdmissionGuard::generation)
                    .unwrap_or_default();
                drop(guard.take());
                match recover_late_resource_write(
                    db,
                    &namespace,
                    lost_generation,
                    http_client,
                    LateResourceWrite::Create,
                    LateResourceRecovery {
                        written: Some(&written),
                        previous: None,
                        delete_snapshots: None,
                    },
                )
                .await
                {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(mark_mtls_dns_admission_unavailable(anyhow::anyhow!(
                        "namespace config admission was lost during create; the late write was compensated"
                    ))),
                    Err(_recovery_error) => {
                        Err(mark_mtls_dns_admission_unavailable(anyhow::anyhow!(
                            "namespace config admission was lost during create and recovery failed"
                        )))
                    }
                }
            }
            Err(persistence_error) => Err(persistence_error),
        },
        Err(error) => Err(error),
    };
    if result.is_ok() {
        finish_write_success(
            success_db,
            &state,
            &actor,
            &namespace,
            &written,
            None,
            WriteAction::Create,
        )
        .await;
    }
    result
}

async fn persist_update_to_settlement<R: AdminResource>(
    context: OwnedWriteSettlementContext,
    id: String,
    written: R,
    previous: R,
) -> DbResult<bool> {
    let OwnedWriteSettlementContext {
        db,
        namespace,
        mut guard,
        http_client,
        state,
        actor,
    } = context;
    let success_db = db.clone();
    let result = match run_db_write_while_held(guard.as_ref(), R::db_update(db.as_ref(), &written))
        .await
    {
        Ok(NamespaceConfigAdmissionCompletion::Held(result)) => result,
        Ok(NamespaceConfigAdmissionCompletion::Lost { result, error: _ }) => match result {
            Ok(false) => Ok(false),
            Ok(true) => {
                let lost_generation = guard
                    .as_ref()
                    .map(NamespaceConfigAdmissionGuard::generation)
                    .unwrap_or_default();
                drop(guard.take());
                match recover_late_resource_write(
                    db,
                    &namespace,
                    lost_generation,
                    http_client,
                    LateResourceWrite::Update { id: &id },
                    LateResourceRecovery {
                        written: Some(&written),
                        previous: Some(&previous),
                        delete_snapshots: None,
                    },
                )
                .await
                {
                    Ok(true) => Ok(true),
                    Ok(false) => Err(mark_mtls_dns_admission_unavailable(anyhow::anyhow!(
                        "namespace config admission was lost during update; the late write was compensated"
                    ))),
                    Err(_recovery_error) => {
                        Err(mark_mtls_dns_admission_unavailable(anyhow::anyhow!(
                            "namespace config admission was lost during update and recovery failed"
                        )))
                    }
                }
            }
            Err(persistence_error) => Err(persistence_error),
        },
        Err(error) => Err(error),
    };
    if matches!(&result, Ok(true)) {
        finish_write_success(
            success_db,
            &state,
            &actor,
            &namespace,
            &written,
            Some(&previous),
            WriteAction::Update { id: &id },
        )
        .await;
    }
    result
}

async fn persist_delete_to_settlement<R: AdminResource>(
    context: OwnedWriteSettlementContext,
    id: String,
    recovery: OwnedLateDeleteRecovery<R>,
) -> DbResult<bool> {
    let OwnedWriteSettlementContext {
        db,
        namespace,
        mut guard,
        http_client,
        state,
        actor,
    } = context;
    let success_db = db.clone();
    let result = match run_db_write_while_held(
        guard.as_ref(),
        R::db_delete(db.as_ref(), &namespace, &id),
    )
    .await
    {
        Ok(NamespaceConfigAdmissionCompletion::Held(result)) => result,
        Ok(NamespaceConfigAdmissionCompletion::Lost { result, error: _ }) => match result {
            Ok(false) => Ok(false),
            Ok(true) => {
                let lost_generation = guard
                    .as_ref()
                    .map(NamespaceConfigAdmissionGuard::generation)
                    .unwrap_or_default();
                drop(guard.take());
                match recover_late_resource_write(
                    db,
                    &namespace,
                    lost_generation,
                    http_client,
                    LateResourceWrite::Delete { id: &id },
                    LateResourceRecovery {
                        written: None,
                        previous: Some(&recovery.previous),
                        delete_snapshots: recovery.config.as_ref().map(|config| {
                            LateDeleteSnapshots {
                                config,
                                api_spec: recovery.api_spec.as_ref(),
                            }
                        }),
                    },
                )
                .await
                {
                    Ok(true) => Ok(true),
                    Ok(false) => Err(mark_mtls_dns_admission_unavailable(anyhow::anyhow!(
                        "namespace config admission was lost during delete; the late write was compensated"
                    ))),
                    Err(_recovery_error) => {
                        Err(mark_mtls_dns_admission_unavailable(anyhow::anyhow!(
                            "namespace config admission was lost during delete and recovery failed"
                        )))
                    }
                }
            }
            Err(persistence_error) => Err(persistence_error),
        },
        Err(error) => Err(error),
    };
    if matches!(&result, Ok(true)) {
        let event = AuditEvent::new(
            &actor,
            "delete",
            R::RESOURCE_NAME.replace(' ', "_"),
            &id,
            &namespace,
            audit::delete_diff(R::audit_body(&recovery.previous)),
        );
        if let Err(error) = audit::record(state.admin_audit_enabled, success_db, event) {
            super::log_audit_enqueue_failure(&error);
        }
    }
    result
}

async fn finish_write_success<R: AdminResource>(
    db: Arc<dyn DatabaseBackend>,
    state: &AdminState,
    actor: &AuditActor,
    namespace: &str,
    resource: &R,
    existing: Option<&R>,
    action: WriteAction<'_>,
) {
    if let Err(_error) =
        R::after_write(db.as_ref(), state, namespace, resource, existing, action).await
    {
        super::warn_persistence_failure_redacted("admin_resource_post_write_hook");
    }

    let (audit_action, diff) = match action {
        WriteAction::Create => ("create", audit::create_diff(R::audit_body(resource))),
        WriteAction::Update { .. } => {
            let before = existing.map(R::audit_body).unwrap_or_else(|| json!(null));
            (
                "update",
                audit::update_diff(before, R::audit_body(resource)),
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
    if let Err(error) = audit::record(state.admin_audit_enabled, db, event) {
        super::log_audit_enqueue_failure(&error);
    }
}

pub(super) async fn validate_transaction_log_schema_graph_on_blocking_pool(
    candidate: GatewayConfig,
    http_client: crate::plugins::PluginHttpClient,
) -> Result<(), AfterValidateError> {
    tokio::task::spawn_blocking(move || {
        crate::plugins::transaction_log_schema::validate_config_graph(
            &candidate,
            &http_client,
            true,
        )
    })
    .await
    .map_err(|error| {
        AfterValidateError::Db(anyhow::anyhow!(
            "transaction-log schema validation task failed: {error}"
        ))
    })?
    .map_err(AfterValidateError::BadRequest)
}

pub(crate) async fn current_transaction_log_schema_graph_is_valid(
    db: &dyn DatabaseBackend,
    state: &AdminState,
    namespace: &str,
) -> DbResult<bool> {
    let candidate = db.load_namespace_snapshot(namespace).await?;
    let http_client = super::plugin_validation_http_client(state);
    match validate_transaction_log_schema_graph_on_blocking_pool(candidate, http_client).await {
        Ok(()) => Ok(true),
        Err(AfterValidateError::BadRequest(_) | AfterValidateError::Conflict(_)) => Ok(false),
        Err(AfterValidateError::Db(error)) => Err(error),
        Err(AfterValidateError::Response(_)) => {
            anyhow::bail!("transaction-log schema graph validation returned an HTTP response")
        }
    }
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

/// Validate the exact post-mutation graph for cross-resource plugin contracts
/// before a Proxy or PluginConfig write is persisted.
pub(crate) async fn validate_plugin_graph_candidates(
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
    validate_candidate_plugin_graph(&candidate, &http_client)
}

/// Validate the exact graph produced by deleting a Proxy, including the
/// proxy-scoped plugin FK cascade and orphaned proxy-group cleanup performed by
/// both direct Proxy deletion and API-spec cascade deletion.
pub(crate) async fn validate_plugin_graph_proxy_deletion_candidate(
    db: &dyn DatabaseBackend,
    state: &AdminState,
    namespace: &str,
    removed_proxy_id: &str,
) -> Result<(), AfterValidateError> {
    let mut candidate = db
        .load_namespace_snapshot(namespace)
        .await
        .map_err(AfterValidateError::Db)?;
    candidate
        .proxies
        .retain(|proxy| proxy.id != removed_proxy_id);
    candidate
        .plugin_configs
        .retain(|plugin| plugin.proxy_id.as_deref() != Some(removed_proxy_id));

    let remaining_associations: HashSet<String> = candidate
        .proxies
        .iter()
        .flat_map(|proxy| proxy.plugins.iter())
        .map(|association| association.plugin_config_id.clone())
        .collect();
    candidate.plugin_configs.retain(|plugin| {
        plugin.scope != PluginScope::ProxyGroup || remaining_associations.contains(&plugin.id)
    });

    let http_client = super::plugin_validation_http_client(state);
    validate_candidate_plugin_graph(&candidate, &http_client)
}

/// A direct proxy delete can cascade resources that the runtime snapshot
/// deliberately exposes without API-spec ownership metadata. Re-read every
/// resource that compensation would classify as hand-owned before persistence,
/// while namespace admission is still held, so a foreign spec's resource can
/// never be restored with its ownership stripped.
async fn validate_direct_api_spec_proxy_delete_restore_ownership(
    db: &dyn DatabaseBackend,
    namespace: &str,
    proxy: &Proxy,
) -> Result<(), AfterValidateError> {
    let spec = db
        .get_api_spec_by_proxy(namespace, &proxy.id)
        .await
        .map_err(AfterValidateError::Db)?;
    let Some(spec) = spec else {
        if let Some(owner) = proxy.api_spec_id.as_deref() {
            return Err(AfterValidateError::BadRequest(vec![format!(
                "proxy '{}' is stamped to API spec '{}' but its owning API-spec metadata is missing",
                proxy.id, owner
            )]));
        }
        return Ok(());
    };
    if let Some(owner) = proxy.api_spec_id.as_deref()
        && owner != spec.id
    {
        return Err(AfterValidateError::BadRequest(vec![format!(
            "proxy '{}' is stamped to API spec '{}' but its owning metadata identifies API spec '{}'",
            proxy.id, owner, spec.id
        )]));
    }
    let snapshot = db
        .load_namespace_snapshot(namespace)
        .await
        .map_err(AfterValidateError::Db)?;
    let associated_ids = proxy
        .plugins
        .iter()
        .map(|association| association.plugin_config_id.as_str())
        .collect::<HashSet<_>>();
    let other_associated_ids = snapshot
        .proxies
        .iter()
        .filter(|candidate| candidate.id != proxy.id)
        .flat_map(|candidate| candidate.plugins.iter())
        .map(|association| association.plugin_config_id.as_str())
        .collect::<HashSet<_>>();

    for snapshot_plugin in snapshot.plugin_configs.iter().filter(|plugin| {
        plugin.proxy_id.as_deref() == Some(proxy.id.as_str())
            || (plugin.scope == PluginScope::ProxyGroup
                && associated_ids.contains(plugin.id.as_str())
                && !other_associated_ids.contains(plugin.id.as_str()))
    }) {
        let Some(plugin) = db
            .get_plugin_config(namespace, &snapshot_plugin.id)
            .await
            .map_err(AfterValidateError::Db)?
        else {
            return Err(AfterValidateError::BadRequest(vec![format!(
                "proxy '{}' cascade plugin '{}' disappeared before API-spec restore ownership validation",
                proxy.id, snapshot_plugin.id
            )]));
        };
        if let Some(owner) = plugin.api_spec_id.as_deref()
            && owner != spec.id
        {
            return Err(AfterValidateError::BadRequest(vec![format!(
                "proxy '{}' cascade plugin '{}' is owned by API spec '{}', not owning API spec '{}'",
                proxy.id, plugin.id, owner, spec.id
            )]));
        }
    }

    if let Some(upstream_id) = proxy.upstream_id.as_deref() {
        let Some(upstream) = db
            .get_upstream(namespace, upstream_id)
            .await
            .map_err(AfterValidateError::Db)?
        else {
            return Err(AfterValidateError::BadRequest(vec![format!(
                "proxy '{}' upstream '{}' disappeared before API-spec restore ownership validation",
                proxy.id, upstream_id
            )]));
        };
        if let Some(owner) = upstream.api_spec_id.as_deref()
            && owner != spec.id
        {
            return Err(AfterValidateError::BadRequest(vec![format!(
                "proxy '{}' upstream '{}' is owned by API spec '{}', not owning API spec '{}'",
                proxy.id, upstream.id, owner, spec.id
            )]));
        }
    }

    Ok(())
}

/// Validate the post-mutation named log-schema graph for one namespace.
///
/// The authoritative snapshot is overlaid exactly as plugin CRUD/batch
/// persistence will change it, then definitions and referrers are validated in
/// an isolated registry bracket. No live registry state participates.
pub(crate) async fn validate_transaction_log_schema_candidates(
    db: &dyn DatabaseBackend,
    state: &AdminState,
    namespace: &str,
    plugins: &[PluginConfig],
    removed_plugin_id: Option<&str>,
) -> Result<(), AfterValidateError> {
    let mut candidate = db
        .load_namespace_snapshot(namespace)
        .await
        .map_err(AfterValidateError::Db)?;

    if let Some(removed_plugin_id) = removed_plugin_id {
        candidate
            .plugin_configs
            .retain(|plugin| plugin.namespace != namespace || plugin.id != removed_plugin_id);
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
    validate_transaction_log_schema_graph_on_blocking_pool(candidate, http_client).await
}

/// Validate the exact post-PUT API-spec replacement candidate.
///
/// The persistence contract deletes plugin configs owned by the replaced spec,
/// removes associations declared only by the previous spec, preserves manual
/// associations, and then overlays the incoming proxy and plugins. Build that
/// same graph here so admission neither rejects a valid replacement because of
/// removed globals nor admits an invalid chain by dropping retained manual
/// associations.
pub(crate) async fn validate_plugin_graph_api_spec_replacement_candidate(
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
    validate_candidate_plugin_graph(&candidate, &http_client)
}

/// Validate the named log-schema graph produced by an exact API-spec PUT.
///
/// `replace_api_spec_bundle` deletes every plugin config owned by the old spec
/// before inserting the replacement bundle. Mirror that ownership boundary so
/// removed definitions/referrers cannot leak into validation and retained
/// manual plugins remain part of the authoritative prospective namespace.
pub(crate) async fn validate_transaction_log_schema_api_spec_replacement_candidate(
    db: &dyn DatabaseBackend,
    state: &AdminState,
    namespace: &str,
    existing_spec: &crate::config::types::ApiSpec,
    plugins: &[PluginConfig],
) -> Result<(), AfterValidateError> {
    let replaced_plugins = db
        .list_spec_owned_plugin_configs(namespace, &existing_spec.id)
        .await
        .map_err(AfterValidateError::Db)?;
    if !plugins
        .iter()
        .chain(replaced_plugins.iter())
        .any(crate::plugins::transaction_log_schema::is_enabled_config_graph_participant)
    {
        return Ok(());
    }

    let mut candidate = db
        .load_namespace_snapshot(namespace)
        .await
        .map_err(AfterValidateError::Db)?;
    let replaced_plugin_ids: HashSet<String> = replaced_plugins
        .into_iter()
        .map(|plugin| plugin.id)
        .collect();

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
    validate_transaction_log_schema_graph_on_blocking_pool(candidate, http_client).await
}

/// Validate the named log-schema graph produced by deleting an API spec.
///
/// API-spec deletion removes every plugin config owned by the spec, every
/// proxy-scoped config tied to the deleted proxy, and proxy-group configs that
/// become orphaned after that proxy's associations disappear. Mirror all three
/// cascades so retained manual referrers cannot be stranded while referrers
/// deleted by the same operation do not cause a false rejection.
pub(crate) async fn validate_transaction_log_schema_api_spec_deletion_candidate(
    db: &dyn DatabaseBackend,
    state: &AdminState,
    namespace: &str,
    existing_spec: &crate::config::types::ApiSpec,
) -> Result<(), AfterValidateError> {
    let spec_owned_plugins = db
        .list_spec_owned_plugin_configs(namespace, &existing_spec.id)
        .await
        .map_err(AfterValidateError::Db)?;
    let mut removed_plugin_ids: HashSet<String> = spec_owned_plugins
        .into_iter()
        .map(|plugin| plugin.id)
        .collect();
    let mut candidate = db
        .load_namespace_snapshot(namespace)
        .await
        .map_err(AfterValidateError::Db)?;

    candidate
        .proxies
        .retain(|proxy| proxy.namespace != namespace || proxy.id != existing_spec.proxy_id);
    removed_plugin_ids.extend(
        candidate
            .plugin_configs
            .iter()
            .filter(|plugin| {
                plugin.namespace == namespace
                    && plugin.proxy_id.as_deref() == Some(existing_spec.proxy_id.as_str())
            })
            .map(|plugin| plugin.id.clone()),
    );

    let retained_association_ids: HashSet<&str> = candidate
        .proxies
        .iter()
        .flat_map(|proxy| proxy.plugins.iter())
        .map(|association| association.plugin_config_id.as_str())
        .collect();
    removed_plugin_ids.extend(
        candidate
            .plugin_configs
            .iter()
            .filter(|plugin| {
                plugin.namespace == namespace
                    && plugin.scope == crate::config::types::PluginScope::ProxyGroup
                    && !retained_association_ids.contains(plugin.id.as_str())
            })
            .map(|plugin| plugin.id.clone()),
    );

    if !candidate.plugin_configs.iter().any(|plugin| {
        removed_plugin_ids.contains(&plugin.id)
            && crate::plugins::transaction_log_schema::is_enabled_config_graph_participant(plugin)
    }) {
        return Ok(());
    }

    candidate
        .plugin_configs
        .retain(|plugin| !removed_plugin_ids.contains(&plugin.id));
    let http_client = super::plugin_validation_http_client(state);
    validate_transaction_log_schema_graph_on_blocking_pool(candidate, http_client).await
}

/// Validate a wholesale namespace replacement without retaining resources that
/// the restore will delete. Runtime plugin chains are namespace-scoped, so the
/// normalized replacement is the complete authoritative candidate.
pub(crate) fn validate_plugin_graph_restore_candidate(
    state: &AdminState,
    replacement: &GatewayConfig,
) -> Result<(), AfterValidateError> {
    let http_client = super::plugin_validation_http_client(state);
    validate_candidate_plugin_graph(replacement, &http_client)
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
/// authoritative. `lock_namespace_config_admission` serializes same-process
/// prechecks; namespace-scoped SQL/Mongo uniqueness constraints are the
/// cross-process persistence backstop.
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

#[async_trait::async_trait]
pub(crate) trait AdminResource:
    Send + Sync + Serialize + DeserializeOwned + Clone + Sized + 'static
{
    const RESOURCE_NAME: &'static str;
    const RESOURCE_LABEL: &'static str;
    const VALIDATION_ERROR_LABEL: &'static str;
    const NOT_FOUND_MESSAGE: &'static str;
    const ID_CONFLICT_LABEL: &'static str = Self::RESOURCE_LABEL;
    const SERIALIZE_NAMESPACE_CONFIG_ADMISSION: bool = false;

    fn id(&self) -> &str;
    fn set_id(&mut self, id: String);
    fn namespace(&self) -> &str;
    fn set_namespace(&mut self, ns: String);
    fn set_created_at(&mut self, now: DateTime<Utc>);
    fn set_updated_at(&mut self, now: DateTime<Utc>);
    fn updated_at(&self) -> DateTime<Utc>;
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
        if let Some(conflict) = tcp_connection_throttle_attachment_conflict(error) {
            return Self::map_after_validate_errors(conflict.errors());
        }
        // Unique-constraint violations at persist time are conflicts, not
        // server faults: the admission prechecks are namespace-scoped and
        // raceable, so the DB constraint is the authoritative backstop (e.g.
        // reusing a proxy/upstream id that exists in another namespace, or a
        // concurrent create winning the race after the precheck passed).
        // Preserve the 409 disposition without surfacing driver-owned
        // constraint, key, schema, or duplicate-value text.
        if let Some(conflict) = mtls_dns_identity_conflict(error) {
            // Typed conflicts are classified anywhere in the chain, so render
            // the conflict itself: `error.to_string()` is the chain's outermost
            // message and would echo any driver/DSN/schema context a store
            // wrapped above it.
            return super::json_response(
                StatusCode::CONFLICT,
                &json!({ "error": conflict.to_string() }),
            );
        }
        if super::chain_has_unique_constraint_violation(error) {
            super::json_response(
                StatusCode::CONFLICT,
                &json!({ "error": super::RESOURCE_IDENTITY_CONFLICT_MESSAGE }),
            )
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
        } else if let Some(conflict) = tcp_connection_throttle_attachment_conflict(error) {
            Self::map_after_validate_errors(conflict.errors())
        } else if let Some(conflict) = mtls_dns_identity_conflict(error) {
            // Render the typed conflict rather than the chain's outermost
            // message; see `map_persist_db_error` above.
            super::json_response(
                StatusCode::CONFLICT,
                &json!({"error": conflict.to_string()}),
            )
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

    async fn compensate_late_delete(
        db: &dyn DatabaseBackend,
        _namespace: &str,
        previous: &Self,
        _previous_snapshot: Option<&GatewayConfig>,
        _previous_api_spec: Option<&ApiSpecDeleteSnapshot>,
        _http_client: crate::plugins::PluginHttpClient,
    ) -> DbResult<()> {
        Self::db_create(db, previous).await
    }

    async fn intervening_write_recovery(
        _db: &dyn DatabaseBackend,
        _namespace: &str,
        _previous: Option<&Self>,
        _http_client: crate::plugins::PluginHttpClient,
    ) -> DbResult<InterveningWriteRecovery> {
        Ok(InterveningWriteRecovery::Compensate)
    }

    async fn late_delete_api_spec_snapshot(
        _db: &dyn DatabaseBackend,
        _namespace: &str,
        _previous: &Self,
        _previous_snapshot: Option<&GatewayConfig>,
    ) -> DbResult<Option<ApiSpecDeleteSnapshot>> {
        Ok(None)
    }

    async fn late_create_compensation_safe(
        _db: &dyn DatabaseBackend,
        _namespace: &str,
        current: &Self,
        written: &Self,
        _previous_snapshot: Option<&GatewayConfig>,
        _http_client: crate::plugins::PluginHttpClient,
    ) -> DbResult<bool> {
        Ok(current.updated_at() == written.updated_at())
    }

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
                super::warn_persistence_failure_redacted("admin_resource_list_cached_fallback");
            }
        }
    }

    if let Some(config) = state.cached_gateway_config() {
        let items = R::cached_items(&config)
            .iter()
            .filter(|resource| resource.namespace() == namespace);
        let body = super::paginate_mapped_response(items, pagination, |resource| {
            R::response_body_for_role(resource, role)
        });
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
                super::warn_persistence_failure_redacted("admin_resource_get_cached_fallback");
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
    let mut namespace_config_admission_guard = if R::SERIALIZE_NAMESPACE_CONFIG_ADMISSION {
        match lock_namespace_config_admission(db_arc.clone(), namespace).await {
            Ok(guard) => Some(guard),
            Err(error) => return Ok(R::map_precheck_db_error(&error)),
        }
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
    let previous_snapshot = if R::SERIALIZE_NAMESPACE_CONFIG_ADMISSION {
        match db.load_namespace_snapshot(namespace).await {
            Ok(snapshot) => Some(snapshot),
            Err(error) => return Ok(R::map_precheck_db_error(&error)),
        }
    } else {
        None
    };
    let previous_api_spec = match R::late_delete_api_spec_snapshot(
        db,
        namespace,
        &existing,
        previous_snapshot.as_ref(),
    )
    .await
    {
        Ok(snapshot) => snapshot,
        Err(error) => return Ok(R::map_precheck_db_error(&error)),
    };

    let validation_ctx = ValidationCtx::from_state(state);
    if let Err(error) = R::before_delete(db, state, namespace, &existing, &validation_ctx).await {
        return Ok(map_after_validate_error::<R>(error));
    }

    let persistence = match tokio::spawn(persist_delete_to_settlement(
        OwnedWriteSettlementContext {
            db: db_arc.clone(),
            namespace: namespace.to_string(),
            guard: namespace_config_admission_guard.take(),
            http_client: super::plugin_validation_http_client(state),
            state: state.clone(),
            actor: actor.clone(),
        },
        id.to_string(),
        OwnedLateDeleteRecovery {
            previous: existing.clone(),
            config: previous_snapshot,
            api_spec: previous_api_spec,
        },
    ))
    .await
    {
        Ok(result) => result,
        Err(error) => Err(anyhow::anyhow!(
            "namespace delete persistence task failed: {error}"
        )),
    };
    match persistence {
        Ok(true) => Ok(super::empty_response(StatusCode::NO_CONTENT)),
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
    let unique_conflict =
        is_mtls_dns_identity_conflict(error) || super::chain_has_unique_constraint_violation(error);
    let message = consumer_persist_error_message(error);
    let status = if unique_conflict {
        StatusCode::CONFLICT
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    super::json_response(status, &json!({"error": message}))
}

/// Redact persistence-level diagnostics before they reach an admin response.
/// MongoDB duplicate-key errors can echo indexed credential-derived values;
/// callers need the conflict disposition, never credential or index metadata.
/// Every branch renders a constant or an internally constructed typed message,
/// and the fallback logs no error text at all, so neither the wire nor the
/// admin log carries driver-provided material.
pub(crate) fn consumer_persist_error_message(error: &anyhow::Error) -> String {
    if is_mtls_dns_admission_unavailable(error) {
        MTLS_DNS_ADMISSION_UNAVAILABLE_MESSAGE.to_string()
    } else if let Some(conflict) = mtls_dns_identity_conflict(error) {
        // Render the typed conflict, not the chain's outermost message: the
        // identities it names are internally constructed and not secrets, but
        // any driver context wrapped above it would be.
        conflict.to_string()
    } else if super::chain_has_unique_constraint_violation(error) {
        // Chain-aware: a MongoDB replica-set write wraps the inner E11000 in
        // transaction context, so matching only the outermost message would
        // drop a credential-index conflict into the branch below.
        "Consumer identity or credential conflicts with another Consumer in the namespace"
            .to_string()
    } else {
        super::redacted_persistence_error_message("consumer_persist", error).to_string()
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
        if resource.plugin_name == "serverless_function"
            && let Some(url) = config.get_mut("function_url")
        {
            *url = match url.as_str() {
                Some(raw) => {
                    json!(crate::plugins::serverless_function::redact_serverless_url(
                        raw
                    ))
                }
                None => json!(crate::plugins::utils::metadata_redaction::REDACTED_PLACEHOLDER),
            };
        }
        redact_sensitive_plugin_config_fields(config);
        if resource.plugin_name == "loki_logging" {
            redact_loki_logging_config_projection(config);
        }
        if resource.plugin_name == "otel_tracing" {
            redact_otel_tracing_config_projection(config);
        }
    }
    body
}

fn redact_loki_logging_config_projection(config: &mut Value) {
    let marker = crate::plugins::utils::metadata_redaction::REDACTED_PLACEHOLDER;
    let Some(config) = config.as_object_mut() else {
        *config = json!(marker);
        return;
    };

    if let Some(endpoint) = config.get_mut("endpoint_url")
        && !endpoint.is_null()
    {
        *endpoint = match endpoint
            .as_str()
            .and_then(|value| url::Url::parse(value).ok())
        {
            Some(endpoint) => {
                json!(crate::plugins::loki_logging::redacted_endpoint_url(
                    &endpoint
                ))
            }
            None => json!(marker),
        };
    }
    if let Some(authorization) = config.get_mut("authorization_header")
        && !authorization.is_null()
    {
        *authorization = json!(marker);
    }
    if let Some(custom_headers) = config.get_mut("custom_headers") {
        redact_loki_custom_header_values(custom_headers, marker);
    }
}

fn redact_loki_custom_header_values(value: &mut Value, marker: &str) {
    match value {
        Value::Object(headers) => {
            for value in headers.values_mut() {
                if !value.is_null() {
                    *value = json!(marker);
                }
            }
        }
        Value::Null => {}
        _ => *value = json!(marker),
    }
}

fn redact_otel_tracing_config_projection(config: &mut Value) {
    let marker = crate::plugins::utils::metadata_redaction::REDACTED_PLACEHOLDER;
    let Some(config) = config.as_object_mut() else {
        *config = json!(marker);
        return;
    };

    if let Some(endpoint) = config.get_mut("endpoint")
        && !endpoint.is_null()
    {
        *endpoint = match endpoint
            .as_str()
            .and_then(|value| url::Url::parse(value).ok())
        {
            Some(endpoint) => {
                json!(crate::plugins::otel_tracing::redacted_endpoint_url(
                    &endpoint
                ))
            }
            None => json!(marker),
        };
    }
    if let Some(authorization) = config.get_mut("authorization")
        && !authorization.is_null()
    {
        *authorization = json!(marker);
    }
    if let Some(headers) = config.get_mut("headers") {
        redact_loki_custom_header_values(headers, marker);
    }
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
        || normalized.contains("function_key")
        || normalized.contains("client_secret")
        || normalized.contains("credential")
        || normalized.contains("private_key")
        || normalized.contains("service_account_json")
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

#[async_trait::async_trait]
impl AdminResource for Upstream {
    const RESOURCE_NAME: &'static str = "upstream";
    const RESOURCE_LABEL: &'static str = "Upstream";
    const VALIDATION_ERROR_LABEL: &'static str = "upstream fields";
    const NOT_FOUND_MESSAGE: &'static str = "Upstream not found";
    // Serialize create/update uniqueness prechecks under the namespace config
    // admission lease so concurrent writers cannot both pass the advisory
    // name check before either commits (issue #2999). Matches Proxy/Consumer/
    // PluginConfig; the SQL/Mongo unique `(namespace, name)` index remains the
    // datastore backstop.
    const SERIALIZE_NAMESPACE_CONFIG_ADMISSION: bool = true;

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

    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
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
        let error_chain_contains = |needle| {
            error
                .chain()
                .any(|cause| cause.to_string().contains(needle))
        };
        if error_chain_contains("referenced by one or more proxies") {
            return super::json_response(
                StatusCode::CONFLICT,
                &json!({"error": "Upstream is referenced by one or more proxies and cannot be deleted"}),
            );
        }
        if error_chain_contains("referenced by mesh_route_dispatch plugin_config") {
            return super::json_response(
                StatusCode::CONFLICT,
                &json!({"error": "Upstream is referenced by a mesh_route_dispatch plugin_config and cannot be deleted"}),
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
            pagination.query_offset_i64(),
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

#[async_trait::async_trait]
impl AdminResource for PluginConfig {
    const RESOURCE_NAME: &'static str = "plugin config";
    const RESOURCE_LABEL: &'static str = "Plugin config";
    const VALIDATION_ERROR_LABEL: &'static str = "plugin config fields";
    const NOT_FOUND_MESSAGE: &'static str = "Plugin config not found";
    const SERIALIZE_NAMESPACE_CONFIG_ADMISSION: bool = true;
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

    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
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
            pagination.query_offset_i64(),
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

    async fn compensate_late_delete(
        db: &dyn DatabaseBackend,
        namespace: &str,
        previous: &Self,
        previous_snapshot: Option<&GatewayConfig>,
        _previous_api_spec: Option<&ApiSpecDeleteSnapshot>,
        _http_client: crate::plugins::PluginHttpClient,
    ) -> DbResult<()> {
        let snapshot = previous_snapshot.ok_or_else(|| {
            anyhow::anyhow!("late plugin delete recovery is missing the namespace snapshot")
        })?;
        db.create_plugin_config(previous).await?;
        for prior_proxy in &snapshot.proxies {
            let prior_associations = prior_proxy
                .plugins
                .iter()
                .filter(|association| association.plugin_config_id == previous.id)
                .cloned()
                .collect::<Vec<_>>();
            if prior_associations.is_empty() {
                continue;
            }
            let Some(mut current_proxy) =
                db.get_proxy_for_write(namespace, &prior_proxy.id).await?
            else {
                continue;
            };
            let mut changed = false;
            for association in prior_associations {
                if !current_proxy
                    .plugins
                    .iter()
                    .any(|current| current.plugin_config_id == association.plugin_config_id)
                {
                    current_proxy.plugins.push(association);
                    changed = true;
                }
            }
            if changed {
                current_proxy.updated_at = Utc::now();
                if !db.update_proxy(&current_proxy).await? {
                    anyhow::bail!(
                        "late plugin delete compensation could not restore proxy '{}' associations",
                        current_proxy.id
                    );
                }
            }
        }
        Ok(())
    }

    async fn intervening_write_recovery(
        db: &dyn DatabaseBackend,
        namespace: &str,
        previous: Option<&Self>,
        http_client: crate::plugins::PluginHttpClient,
    ) -> DbResult<InterveningWriteRecovery> {
        let mut candidate = db.load_namespace_snapshot(namespace).await?;
        if validate_transaction_log_schema_graph_on_blocking_pool(
            candidate.clone(),
            http_client.clone(),
        )
        .await
        .is_ok()
        {
            return Ok(InterveningWriteRecovery::KeepCurrent);
        }

        let previous = previous.ok_or_else(|| {
            anyhow::anyhow!("late plugin recovery is missing the prior plugin config")
        })?;
        if let Some(current) = candidate
            .plugin_configs
            .iter_mut()
            .find(|plugin| plugin.namespace == namespace && plugin.id == previous.id)
        {
            *current = previous.clone();
        } else {
            candidate.plugin_configs.push(previous.clone());
        }
        match validate_transaction_log_schema_graph_on_blocking_pool(candidate, http_client).await {
            Ok(()) => Ok(InterveningWriteRecovery::Compensate),
            Err(AfterValidateError::BadRequest(errors)) => anyhow::bail!(
                "late plugin recovery could not produce a valid transaction-log schema graph: {}",
                errors.join("; ")
            ),
            Err(AfterValidateError::Db(error)) => Err(error),
            Err(AfterValidateError::Conflict(errors)) => anyhow::bail!(
                "late plugin recovery conflicted while validating the transaction-log schema graph: {}",
                errors.join("; ")
            ),
            Err(AfterValidateError::Response(_)) => anyhow::bail!(
                "late plugin recovery received an unexpected response while validating the transaction-log schema graph"
            ),
        }
    }

    async fn late_create_compensation_safe(
        db: &dyn DatabaseBackend,
        namespace: &str,
        current: &Self,
        written: &Self,
        _previous_snapshot: Option<&GatewayConfig>,
        http_client: crate::plugins::PluginHttpClient,
    ) -> DbResult<bool> {
        if current.updated_at != written.updated_at {
            return Ok(false);
        }
        if plugin_has_proxy_association(db, namespace, &written.id).await? {
            return Ok(false);
        }
        let mut candidate = db.load_namespace_snapshot(namespace).await?;
        candidate
            .plugin_configs
            .retain(|plugin| plugin.namespace != namespace || plugin.id != written.id);
        Ok(
            validate_transaction_log_schema_graph_on_blocking_pool(candidate, http_client)
                .await
                .is_ok(),
        )
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

        if crate::plugins::transaction_log_schema::participates_in_config_graph(resource) {
            if let Err(error) = crate::plugins::validate_plugin_config_policy_only(
                &resource.plugin_name,
                &resource.config,
                &state.backend_allow_ips,
            ) {
                return Err(AfterValidateError::BadRequest(vec![format!(
                    "Invalid plugin config: {}",
                    error
                )]));
            }
        } else if let Err(error) = validate_plugin_config_definition(state, resource) {
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
        validate_plugin_graph_candidates(
            db,
            state,
            namespace,
            &[],
            std::slice::from_ref(resource),
            None,
        )
        .await?;
        if crate::plugins::transaction_log_schema::is_enabled_config_graph_participant(resource)
            || existing.is_some_and(
                crate::plugins::transaction_log_schema::is_enabled_config_graph_participant,
            )
        {
            validate_transaction_log_schema_candidates(
                db,
                state,
                namespace,
                std::slice::from_ref(resource),
                None,
            )
            .await?;
        }

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
        validate_plugin_graph_candidates(db, state, namespace, &[], &[], Some(&existing.id))
            .await?;
        if crate::plugins::transaction_log_schema::is_enabled_config_graph_participant(existing) {
            validate_transaction_log_schema_candidates(
                db,
                state,
                namespace,
                &[],
                Some(&existing.id),
            )
            .await?;
        }
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

#[async_trait::async_trait]
impl AdminResource for Proxy {
    const RESOURCE_NAME: &'static str = "proxy";
    const RESOURCE_LABEL: &'static str = "Proxy";
    const VALIDATION_ERROR_LABEL: &'static str = "proxy fields";
    const NOT_FOUND_MESSAGE: &'static str = "Proxy not found";
    const SERIALIZE_NAMESPACE_CONFIG_ADMISSION: bool = true;

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

    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
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
            pagination.query_offset_i64(),
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

    async fn late_create_compensation_safe(
        db: &dyn DatabaseBackend,
        namespace: &str,
        current: &Self,
        written: &Self,
        _previous_snapshot: Option<&GatewayConfig>,
        _http_client: crate::plugins::PluginHttpClient,
    ) -> DbResult<bool> {
        if current.updated_at != written.updated_at {
            return Ok(false);
        }
        let current_associations = current
            .plugins
            .iter()
            .map(|association| association.plugin_config_id.as_str())
            .collect::<HashSet<_>>();
        let written_associations = written
            .plugins
            .iter()
            .map(|association| association.plugin_config_id.as_str())
            .collect::<HashSet<_>>();
        if current_associations != written_associations {
            return Ok(false);
        }
        Ok(!proxy_has_scoped_plugin(db, namespace, &written.id).await?)
    }

    async fn compensate_late_delete(
        db: &dyn DatabaseBackend,
        namespace: &str,
        previous: &Self,
        previous_snapshot: Option<&GatewayConfig>,
        previous_api_spec: Option<&ApiSpecDeleteSnapshot>,
        http_client: crate::plugins::PluginHttpClient,
    ) -> DbResult<()> {
        if let Some(api_spec_snapshot) = previous_api_spec {
            let bundle = crate::admin::api_specs::ExtractedBundle {
                proxy: previous.clone(),
                upstream: api_spec_snapshot.upstream.clone(),
                plugins: api_spec_snapshot.plugins.clone(),
            };
            db.restore_api_spec_bundle(
                &bundle,
                &api_spec_snapshot.spec,
                &api_spec_snapshot.additional_upstreams,
                &api_spec_snapshot.additional_plugins,
                &http_client,
            )
            .await?;
            return Ok(());
        }

        let snapshot = previous_snapshot.ok_or_else(|| {
            anyhow::anyhow!("late proxy delete recovery is missing the namespace snapshot")
        })?;
        let associated_ids: HashSet<&str> = previous
            .plugins
            .iter()
            .map(|association| association.plugin_config_id.as_str())
            .collect();
        let other_associated_ids: HashSet<&str> = snapshot
            .proxies
            .iter()
            .filter(|proxy| proxy.id != previous.id)
            .flat_map(|proxy| proxy.plugins.iter())
            .map(|association| association.plugin_config_id.as_str())
            .collect();
        let affected_plugins = snapshot
            .plugin_configs
            .iter()
            .filter(|plugin| {
                plugin.proxy_id.as_deref() == Some(previous.id.as_str())
                    || (plugin.scope == PluginScope::ProxyGroup
                        && associated_ids.contains(plugin.id.as_str())
                        && !other_associated_ids.contains(plugin.id.as_str()))
            })
            .cloned()
            .collect::<Vec<_>>();
        let affected_upstreams = snapshot
            .upstreams
            .iter()
            .filter(|upstream| previous.upstream_id.as_deref() == Some(upstream.id.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        for upstream in &affected_upstreams {
            if db.get_upstream(namespace, &upstream.id).await?.is_none() {
                db.create_upstream(upstream).await?;
            }
        }
        let mut proxy_without_associations = previous.clone();
        proxy_without_associations.plugins.clear();
        db.create_proxy(&proxy_without_associations).await?;
        for plugin in affected_plugins {
            if db.get_plugin_config(namespace, &plugin.id).await?.is_none() {
                db.create_plugin_config(&plugin).await?;
            }
        }
        if !db.update_proxy(previous).await? {
            anyhow::bail!("late proxy delete compensation could not restore associations");
        }
        Ok(())
    }

    async fn late_delete_api_spec_snapshot(
        db: &dyn DatabaseBackend,
        namespace: &str,
        previous: &Self,
        previous_snapshot: Option<&GatewayConfig>,
    ) -> DbResult<Option<ApiSpecDeleteSnapshot>> {
        let Some(spec) = db.get_api_spec_by_proxy(namespace, &previous.id).await? else {
            return Ok(None);
        };
        let upstreams = db.list_spec_owned_upstreams(namespace, &spec.id).await?;
        let plugins = db
            .list_spec_owned_plugin_configs(namespace, &spec.id)
            .await?;
        let upstream = match upstreams.as_slice() {
            [] => None,
            [upstream] => Some(upstream.clone()),
            _ => {
                return Err(api_spec_restore_snapshot_validation(format!(
                    "API spec '{}' owns multiple upstreams, which direct proxy delete recovery cannot reproduce safely",
                    spec.id
                )));
            }
        };
        let mut additional_upstreams = Vec::new();
        if let Some(current_upstream_id) = previous.upstream_id.as_deref()
            && upstream.as_ref().map(|item| item.id.as_str()) != Some(current_upstream_id)
        {
            match db.get_upstream(namespace, current_upstream_id).await? {
                Some(current) if current.api_spec_id.is_none() => {
                    additional_upstreams.push(current);
                }
                Some(current) => {
                    return Err(api_spec_restore_snapshot_validation(format!(
                        "API spec '{}' cannot snapshot proxy '{}' current upstream '{}': it is owned by API spec '{}'",
                        spec.id,
                        previous.id,
                        current.id,
                        current.api_spec_id.as_deref().unwrap_or("<unknown>")
                    )));
                }
                None => {
                    return Err(api_spec_restore_snapshot_validation(format!(
                        "API spec '{}' proxy '{}' references missing upstream '{}'",
                        spec.id, previous.id, current_upstream_id
                    )));
                }
            }
        }

        let snapshot = previous_snapshot.ok_or_else(|| {
            anyhow::anyhow!("direct API-spec proxy delete is missing the namespace snapshot")
        })?;
        let owned_plugin_ids: HashSet<&str> =
            plugins.iter().map(|plugin| plugin.id.as_str()).collect();
        let associated_ids: HashSet<&str> = previous
            .plugins
            .iter()
            .map(|association| association.plugin_config_id.as_str())
            .collect();
        let other_associated_ids: HashSet<&str> = snapshot
            .proxies
            .iter()
            .filter(|proxy| proxy.id != previous.id)
            .flat_map(|proxy| proxy.plugins.iter())
            .map(|association| association.plugin_config_id.as_str())
            .collect();
        let additional_plugin_ids = snapshot
            .plugin_configs
            .iter()
            .filter(|plugin| !owned_plugin_ids.contains(plugin.id.as_str()))
            .filter(|plugin| {
                plugin.proxy_id.as_deref() == Some(previous.id.as_str())
                    || (plugin.scope == PluginScope::ProxyGroup
                        && associated_ids.contains(plugin.id.as_str())
                        && !other_associated_ids.contains(plugin.id.as_str()))
            })
            .map(|plugin| plugin.id.clone())
            .collect::<Vec<_>>();
        let mut additional_plugins = Vec::with_capacity(additional_plugin_ids.len());
        for plugin_id in &additional_plugin_ids {
            let plugin = db
                .get_plugin_config(namespace, plugin_id)
                .await?
                .ok_or_else(|| {
                    api_spec_restore_snapshot_validation(format!(
                        "API spec '{}' direct proxy delete snapshot lost plugin '{}' before persistence",
                        spec.id, plugin_id
                    ))
                })?;
            if let Some(owner) = plugin.api_spec_id.as_deref() {
                return Err(api_spec_restore_snapshot_validation(format!(
                    "API spec '{}' cannot delete proxy '{}': cascade plugin '{}' is owned by API spec '{}'",
                    spec.id, previous.id, plugin.id, owner
                )));
            }
            validate_api_spec_proxy_plugin_association(&plugin, &previous.id)
                .map_err(|error| api_spec_restore_snapshot_validation(error.to_string()))?;
            additional_plugins.push(plugin);
        }

        let additional_plugin_id_set: HashSet<&str> =
            additional_plugin_ids.iter().map(String::as_str).collect();
        for association in &previous.plugins {
            let plugin_id = association.plugin_config_id.as_str();
            if owned_plugin_ids.contains(plugin_id) || additional_plugin_id_set.contains(plugin_id)
            {
                continue;
            }
            let plugin = db
                .get_plugin_config(namespace, plugin_id)
                .await?
                .ok_or_else(|| {
                    api_spec_restore_snapshot_validation(format!(
                        "API spec '{}' proxy association references missing plugin '{}'",
                        spec.id, plugin_id
                    ))
                })?;
            if let Some(owner) = plugin.api_spec_id.as_deref() {
                return Err(api_spec_restore_snapshot_validation(format!(
                    "API spec '{}' cannot delete proxy '{}': associated plugin '{}' is owned by API spec '{}'",
                    spec.id, previous.id, plugin.id, owner
                )));
            }
            validate_api_spec_proxy_plugin_association(&plugin, &previous.id)
                .map_err(|error| api_spec_restore_snapshot_validation(error.to_string()))?;
        }

        let bundle = crate::admin::api_specs::ExtractedBundle {
            proxy: previous.clone(),
            upstream: upstream.clone(),
            plugins: plugins.clone(),
        };
        validate_api_spec_restore_inputs(
            &bundle,
            &spec,
            &additional_upstreams,
            &additional_plugins,
            true,
        )
        .map_err(|error| api_spec_restore_snapshot_validation(error.to_string()))?;
        Ok(Some(ApiSpecDeleteSnapshot {
            spec,
            upstream,
            plugins,
            additional_upstreams,
            additional_plugins,
        }))
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

    fn map_precheck_db_error(error: &anyhow::Error) -> Response<Full<Bytes>> {
        if let Some(validation) = error.downcast_ref::<ApiSpecRestoreSnapshotValidation>() {
            return super::json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": validation.to_string()}),
            );
        }
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
        if let Some(conflict) = tcp_connection_throttle_attachment_conflict(error) {
            return Self::map_after_validate_errors(conflict.errors());
        }
        if super::chain_has_proxy_route_conflict(error) {
            return super::json_response(
                StatusCode::CONFLICT,
                &json!({"error": PROXY_ROUTE_CONFLICT_ERROR}),
            );
        }
        if let Some(conflict) = mtls_dns_identity_conflict(error) {
            // Typed, chain-deep classification must render the typed message,
            // not the outermost context; see the default `map_persist_db_error`.
            return super::json_response(
                StatusCode::CONFLICT,
                &json!({ "error": conflict.to_string() }),
            );
        }
        if super::chain_has_unique_constraint_violation(error) {
            return super::json_response(
                StatusCode::CONFLICT,
                &json!({ "error": super::RESOURCE_IDENTITY_CONFLICT_MESSAGE }),
            );
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
        validate_plugin_graph_candidates(
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

    async fn before_delete(
        db: &dyn DatabaseBackend,
        state: &AdminState,
        namespace: &str,
        existing: &Self,
        _ctx: &ValidationCtx<'_>,
    ) -> Result<(), AfterValidateError> {
        validate_direct_api_spec_proxy_delete_restore_ownership(db, namespace, existing).await?;
        validate_plugin_graph_proxy_deletion_candidate(db, state, namespace, &existing.id).await
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

#[async_trait::async_trait]
impl AdminResource for Consumer {
    const RESOURCE_NAME: &'static str = "consumer";
    const RESOURCE_LABEL: &'static str = "Consumer";
    const VALIDATION_ERROR_LABEL: &'static str = "consumer fields";
    const NOT_FOUND_MESSAGE: &'static str = "Consumer not found";
    const SERIALIZE_NAMESPACE_CONFIG_ADMISSION: bool = true;

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

    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
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
        // Ordinary Consumer responses are a closed credential projection, so a
        // read-modify-write PUT of such a response cannot express the state it
        // was never shown. Restore what the projection hides — Basic and
        // unknown/custom credential types omitted entirely, and known secrets
        // returned as the `[REDACTED]` placeholder. Explicit replacement and
        // deletion use the credential endpoints.
        crate::config::types::preserve_response_hidden_consumer_credentials(self, existing);
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
            pagination.query_offset_i64(),
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
    let mut namespace_config_admission_guard = if R::SERIALIZE_NAMESPACE_CONFIG_ADMISSION {
        match lock_namespace_config_admission(db_arc.clone(), namespace).await {
            Ok(guard) => Some(guard),
            Err(error) => return Ok(R::map_precheck_db_error(&error)),
        }
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
    if let Some(guard) = namespace_config_admission_guard.as_ref()
        && let Err(error) = guard.ensure_held()
    {
        return Ok(R::map_precheck_db_error(&error));
    }
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
            let persistence = match tokio::spawn(persist_create_to_settlement(
                OwnedWriteSettlementContext {
                    db: db_arc.clone(),
                    namespace: namespace.to_string(),
                    guard: namespace_config_admission_guard.take(),
                    http_client: super::plugin_validation_http_client(state),
                    state: state.clone(),
                    actor: actor.clone(),
                },
                resource.clone(),
            ))
            .await
            {
                Ok(result) => result,
                Err(error) => Err(anyhow::anyhow!(
                    "namespace create persistence task failed: {error}"
                )),
            };
            if let Err(error) = persistence {
                return Ok(R::map_persist_db_error(&error, action));
            }
        }
        WriteAction::Update { id } => {
            let Some(previous) = existing.clone() else {
                return Ok(super::json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &json!({"error": "Update persistence is missing the prior resource"}),
                ));
            };
            let persistence = match tokio::spawn(persist_update_to_settlement(
                OwnedWriteSettlementContext {
                    db: db_arc.clone(),
                    namespace: namespace.to_string(),
                    guard: namespace_config_admission_guard.take(),
                    http_client: super::plugin_validation_http_client(state),
                    state: state.clone(),
                    actor: actor.clone(),
                },
                id.to_string(),
                resource.clone(),
                previous,
            ))
            .await
            {
                Ok(result) => result,
                Err(error) => Err(anyhow::anyhow!(
                    "namespace update persistence task failed: {error}"
                )),
            };
            // The row vanished between the precheck and the write (concurrent
            // delete). The backend recorded no change — report not-found
            // rather than a phantom success (issue #2122 DB-M4).
            match persistence {
                Ok(false) => return Ok(not_found_response::<R>()),
                Ok(true) => {}
                Err(error) => return Ok(R::map_persist_db_error(&error, action)),
            }
        }
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
