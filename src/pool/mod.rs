use anyhow::Result;
use async_trait::async_trait;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, watch};

use crate::config::PoolConfig;
use crate::config::types::Proxy;

thread_local! {
    static KEY_BUF: RefCell<String> = RefCell::new(String::with_capacity(128));
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Structural + classification tag retained when a pool create failure is
/// broadcast to coalesced waiters.
///
/// Kept cloneable and free of live IO/TLS handles so waiters can rebuild
/// pool-specific errors without cloning non-`Clone` sources (`io::Error`,
/// `hyper::Error`, credential material, etc.). The canonical
/// [`crate::retry::ErrorClass`] is stored alongside this kind so ErrorClass /
/// health / retry diagnostics stay aligned with the creator's pre-wire
/// classification (DNS, TLS, timeout, refused/closed, protocol/ALPN, port
/// exhaustion, egress/policy denial, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedPoolCreateKind {
    /// Connect / handshake budget exhausted.
    TimedOut,
    /// DNS resolution / invalid server name failed.
    Dns,
    /// TLS handshake (or H2-over-TLS handshake) failed.
    Tls,
    /// TCP connect refused / equivalent connect-phase refusal.
    ConnectionRefused,
    /// Peer closed or aborted during connect/handshake.
    ConnectionClosed,
    /// Protocol / ALPN / framing failure (excluding intentional H1 fallback).
    Protocol,
    /// Ephemeral port exhaustion (`EADDRNOTAVAIL`).
    PortExhaustion,
    /// Gateway egress / dispatch policy denied the dial.
    DispatchPolicyRejected,
    /// Generic backend unreachable / pool acquire failure.
    Unavailable,
    /// Pool-internal / configuration failure.
    Internal,
    /// Direct-H2 ALPN negotiated `http/1.1` — callers should fall back to
    /// the reqwest pool rather than treating this as a hard backend outage.
    NegotiatedHttp1,
    /// Unclassified create failure.
    Other,
}

impl SharedPoolCreateKind {
    /// Map a canonical [`crate::retry::ErrorClass`] onto the shared create kind
    /// used for waiter reconstruction. Prefer this over substring heuristics.
    pub fn from_error_class(class: crate::retry::ErrorClass) -> Self {
        use crate::retry::ErrorClass;
        match class {
            ErrorClass::ConnectionTimeout | ErrorClass::ReadWriteTimeout => Self::TimedOut,
            ErrorClass::DnsLookupError => Self::Dns,
            ErrorClass::TlsError => Self::Tls,
            ErrorClass::ConnectionRefused => Self::ConnectionRefused,
            ErrorClass::ConnectionClosed => Self::ConnectionClosed,
            // Connect-phase pool creates treat RST like refusal for the
            // structural kind; the stored ErrorClass remains authoritative.
            ErrorClass::ConnectionReset => Self::ConnectionRefused,
            ErrorClass::ProtocolError => Self::Protocol,
            ErrorClass::PortExhaustion => Self::PortExhaustion,
            ErrorClass::DispatchPolicyRejected => Self::DispatchPolicyRejected,
            ErrorClass::ConnectionPoolError => Self::Unavailable,
            ErrorClass::ClientDisconnect
            | ErrorClass::ResponseBodyTooLarge
            | ErrorClass::RequestBodyTooLarge
            | ErrorClass::GracefulRemoteClose
            | ErrorClass::RequestError => Self::Other,
        }
    }
}

#[derive(Debug)]
struct SharedPoolCreateErrorInner {
    message: String,
    kind: SharedPoolCreateKind,
    /// Canonical pre-wire classification captured from the creator's typed
    /// classifier (`classify_grpc_proxy_error`, `classify_http2_pool_error`,
    /// `classify_http3_error` / `classify_boxed_setup_error`). Waiters and
    /// source-chain classifiers must prefer this over re-deriving from the
    /// reconstructed message alone.
    error_class: crate::retry::ErrorClass,
    /// Optional reconstruction detail (e.g. pool key for [`SharedPoolCreateKind::NegotiatedHttp1`]).
    /// Not included in [`Display`]; pool-key TLS material must be redacted by
    /// the typed error's own Display if logged.
    detail: Option<String>,
}

/// Cloneable create-failure payload shared with every waiter for one coalesced
/// creation attempt.
///
/// The original creator error often carries non-`Clone` typed sources. Rather
/// than requiring those errors to be cloneable (or retaining secrets embedded
/// in source chains), the pool captures a sanitized message plus
/// [`SharedPoolCreateKind`] / [`crate::retry::ErrorClass`] and fans that out.
/// Callers reconstruct their error type via `From<SharedPoolCreateError>`.
///
/// Coalescing scope is the `PendingCreation` entry itself (Arc identity + map
/// removal), not an id stamped on this payload.
#[derive(Debug, Clone)]
pub struct SharedPoolCreateError {
    inner: Arc<SharedPoolCreateErrorInner>,
}

impl SharedPoolCreateError {
    pub(crate) fn new(
        message: impl Into<String>,
        kind: SharedPoolCreateKind,
        error_class: crate::retry::ErrorClass,
        detail: Option<String>,
    ) -> Self {
        Self {
            inner: Arc::new(SharedPoolCreateErrorInner {
                message: message.into(),
                kind,
                error_class,
                detail,
            }),
        }
    }

    /// Build from an already-computed canonical [`crate::retry::ErrorClass`].
    pub fn from_classified(
        message: impl Into<String>,
        error_class: crate::retry::ErrorClass,
        detail: Option<String>,
    ) -> Self {
        let kind = SharedPoolCreateKind::from_error_class(error_class);
        Self::new(message, kind, error_class, detail)
    }

    /// Capture a broadcastable failure from a setup-phase std error. Uses the
    /// canonical boxed setup classifier rather than substring heuristics so
    /// H3/anyhow GenericPool waiters retain typed shared classification.
    pub fn capture(err: &(dyn std::error::Error + Send + Sync + 'static)) -> Self {
        let error_class = crate::retry::classify_boxed_setup_error(err);
        Self::from_classified(err.to_string(), error_class, None)
    }

    pub fn message(&self) -> &str {
        &self.inner.message
    }

    pub fn kind(&self) -> SharedPoolCreateKind {
        self.inner.kind
    }

    /// Canonical ErrorClass captured when the creator failed.
    pub fn error_class(&self) -> crate::retry::ErrorClass {
        self.inner.error_class
    }

    pub fn detail(&self) -> Option<&str> {
        self.inner.detail.as_deref()
    }
}

impl std::fmt::Display for SharedPoolCreateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for SharedPoolCreateError {}

/// Error types that can be broadcast to coalesced create waiters.
///
/// Implementations must preserve the creator's canonical pre-wire
/// classification (via existing typed classifiers) without cloning
/// non-`Clone` sources. Direct-H2 also preserves the
/// `BackendSelectedHttp1` structural signal.
pub trait ShareablePoolCreateError: 'static {
    fn to_shared(&self) -> SharedPoolCreateError;
}

impl ShareablePoolCreateError for anyhow::Error {
    fn to_shared(&self) -> SharedPoolCreateError {
        // H3 and reqwest GenericPool creates both surface `anyhow::Error`.
        // `classify_boxed_setup_error` is the shared setup-phase classifier
        // (typed chain + anchored fallback) and avoids a pool→http3 import
        // cycle while still preserving timeout/DNS/TLS/refused/port-exhaustion.
        SharedPoolCreateError::capture(self.as_ref())
    }
}

impl ShareablePoolCreateError for SharedPoolCreateError {
    fn to_shared(&self) -> SharedPoolCreateError {
        // Preserve kind/class/detail for a re-broadcast of the same payload.
        SharedPoolCreateError::new(
            self.message().to_string(),
            self.kind(),
            self.error_class(),
            self.detail().map(str::to_string),
        )
    }
}

/// Remaining slice of a backend connect budget after `connect_started`.
///
/// Returns `None` once the budget is exhausted, so each handshake stage
/// (TCP → TLS → H2/H3) shares one end-to-end deadline rather than restarting
/// the timer per phase. Pool-specific code converts `None` into its own
/// `BackendTimeout` error variant.
pub fn remaining_connect_timeout(
    connect_started: Instant,
    connect_timeout: Duration,
) -> Option<Duration> {
    connect_timeout.checked_sub(connect_started.elapsed())
}

#[async_trait]
pub trait PoolManager: Send + Sync + 'static {
    type Connection: Send + Sync + Clone + 'static;

    fn build_key(&self, proxy: &Proxy, host: &str, port: u16, shard: usize, buf: &mut String);

    /// Default cache-miss creation hook used by `GenericPool::get()`.
    ///
    /// Most pools can establish a connection from the pool key plus `Proxy`
    /// alone. Specialized pools that need extra per-call creation context can
    /// use `GenericPool::create_or_get_existing_owned()` instead.
    async fn create(&self, key: &str, proxy: &Proxy) -> Result<Self::Connection>;

    fn is_healthy(&self, conn: &Self::Connection) -> bool;

    fn destroy(&self, conn: Self::Connection);

    fn runtime_metrics_kind(&self) -> Option<crate::runtime_metrics::PoolKind> {
        None
    }
}

pub struct PoolEntry<C> {
    pub conn: C,
    pub last_used_epoch_ms: AtomicU64,
}

impl<C> PoolEntry<C> {
    fn new(conn: C) -> Self {
        Self {
            conn,
            last_used_epoch_ms: AtomicU64::new(now_epoch_ms()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PoolStats {
    pub size: usize,
    pub max_idle_per_host: usize,
    pub idle_timeout_seconds: u64,
}

enum LookupOutcome<C> {
    Hit(C),
    Miss(String),
    Unhealthy(String),
}

/// Outcome published to coalesced waiters for one pending creation entry.
///
/// `Finished` covers both successful insertion and creator cancellation: waiters
/// re-check the cache / re-elect. `Failed` is the broadcast path that prevents
/// serial redials of a hard-down backend among waiters on this entry.
#[derive(Debug, Clone)]
enum CreationNotify {
    Pending,
    Finished,
    Failed(SharedPoolCreateError),
}

struct PendingCreation {
    outcome_tx: watch::Sender<CreationNotify>,
}

impl PendingCreation {
    fn new() -> Self {
        let (outcome_tx, _outcome_rx) = watch::channel(CreationNotify::Pending);
        Self { outcome_tx }
    }

    async fn wait(&self) -> CreationNotify {
        let mut outcome = self.outcome_tx.subscribe();
        {
            let current = outcome.borrow().clone();
            if !matches!(current, CreationNotify::Pending) {
                return current;
            }
        }

        match outcome.changed().await {
            Ok(()) => outcome.borrow().clone(),
            Err(_) => {
                // Sender dropped without an explicit outcome. `PendingCreationGuard`
                // always publishes Finished/Failed before drop, so this is a
                // defensive path for shutdown / forgotten Arcs. Treat a still-
                // Pending value as Finished so waiters re-elect instead of
                // spinning forever on a dead channel.
                let current = outcome.borrow().clone();
                if matches!(current, CreationNotify::Pending) {
                    CreationNotify::Finished
                } else {
                    current
                }
            }
        }
    }

    fn finish(&self) {
        // Do not overwrite a Failed broadcast if one was already published.
        self.outcome_tx.send_if_modified(|current| {
            if matches!(current, CreationNotify::Pending) {
                *current = CreationNotify::Finished;
                true
            } else {
                false
            }
        });
    }

    fn finish_failed(&self, err: SharedPoolCreateError) {
        self.outcome_tx.send_replace(CreationNotify::Failed(err));
    }
}

struct PendingCreationGuard<'a, M: PoolManager> {
    pool: &'a GenericPool<M>,
    key: String,
    pending: Option<Arc<PendingCreation>>,
}

impl<'a, M: PoolManager> PendingCreationGuard<'a, M> {
    fn new(pool: &'a GenericPool<M>, key: String, pending: Arc<PendingCreation>) -> Self {
        Self {
            pool,
            key,
            pending: Some(pending),
        }
    }

    fn finish(mut self) {
        if let Some(pending) = self.pending.take() {
            self.pool.finish_pending_creation(&self.key, pending);
        }
    }

    fn fail(mut self, err: SharedPoolCreateError) {
        if let Some(pending) = self.pending.take() {
            self.pool
                .finish_pending_creation_failed(&self.key, pending, err);
        }
    }
}

impl<M: PoolManager> Drop for PendingCreationGuard<'_, M> {
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take() {
            // Cancellation / panic: wake waiters without broadcasting a failure
            // so a later waiter can elect a new creator for a fresh attempt.
            self.pool.finish_pending_creation(&self.key, pending);
        }
    }
}

pub struct GenericPool<M: PoolManager> {
    manager: Arc<M>,
    entries: Arc<DashMap<String, PoolEntry<M::Connection>>>,
    cfg: Arc<PoolConfig>,
    cleanup_interval: Duration,
    inflight: Arc<Semaphore>,
    pending_creations: Arc<DashMap<String, Arc<PendingCreation>>>,
}

impl<M: PoolManager> GenericPool<M> {
    /// Construct a generic pool with the given shard count for its internal
    /// `DashMap`s. `shards` must be a power of two; callers should resolve
    /// it via [`crate::util::sharding::pool_shard_amount`] which guarantees
    /// that contract from the operator-facing env var.
    pub fn new(
        manager: Arc<M>,
        cfg: PoolConfig,
        cleanup_interval: Duration,
        shards: usize,
    ) -> Arc<Self> {
        // Cold-path connection establishment is bounded per pool so a burst of
        // cache misses cannot fan out into unbounded concurrent dials.
        let inflight_limit = std::thread::available_parallelism()
            .map(|parallelism| parallelism.get().clamp(4, 256))
            .unwrap_or(32);
        let pool = Arc::new(Self {
            manager,
            entries: Arc::new(DashMap::with_shard_amount(shards)),
            cfg: Arc::new(cfg),
            cleanup_interval,
            inflight: Arc::new(Semaphore::new(inflight_limit)),
            pending_creations: Arc::new(DashMap::with_shard_amount(shards)),
        });
        pool.clone().spawn_cleanup();
        pool
    }

    pub fn manager(&self) -> &Arc<M> {
        &self.manager
    }

    pub fn pool_size(&self) -> usize {
        self.entries.len()
    }

    pub fn stats(&self) -> PoolStats {
        PoolStats {
            size: self.entries.len(),
            max_idle_per_host: self.cfg.max_idle_per_host,
            idle_timeout_seconds: self.cfg.idle_timeout_seconds,
        }
    }

    pub fn keys_snapshot(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    pub fn invalidate(&self, key: &str) {
        if let Some((_, entry)) = self.entries.remove(key) {
            if let Some(kind) = self.manager.runtime_metrics_kind() {
                crate::runtime_metrics::global_ref().record_pool_eviction(kind);
            }
            self.manager.destroy(entry.conn);
        }
    }

    pub fn clear(&self) {
        let keys = self.keys_snapshot();
        for key in keys {
            self.invalidate(&key);
        }
    }

    pub fn invalidate_matching(&self, predicate: impl Fn(&str) -> bool) {
        let keys = self.keys_snapshot();
        for key in keys {
            if predicate(&key) {
                self.invalidate(&key);
            }
        }
    }

    pub fn cached_with<F>(&self, build_key: F) -> Option<M::Connection>
    where
        F: FnOnce(&mut String),
    {
        match self.lookup_or_build_key(build_key) {
            LookupOutcome::Hit(conn) => Some(conn),
            LookupOutcome::Miss(_) => None,
            LookupOutcome::Unhealthy(key) => {
                self.invalidate(&key);
                None
            }
        }
    }

    pub fn cached(&self, key: &str) -> Option<M::Connection> {
        if let Some(entry) = self.entries.get(key) {
            let conn = entry.conn.clone();
            if self.manager.is_healthy(&conn) {
                entry
                    .last_used_epoch_ms
                    .store(now_epoch_ms(), Ordering::Relaxed);
                Some(conn)
            } else {
                drop(entry);
                self.invalidate(key);
                None
            }
        } else {
            None
        }
    }

    pub async fn get(
        &self,
        proxy: &Proxy,
        host: &str,
        port: u16,
        shard: usize,
    ) -> Result<M::Connection> {
        let build_manager = Arc::clone(&self.manager);
        let create_manager = Arc::clone(&self.manager);
        self.get_with(
            |buf| build_manager.build_key(proxy, host, port, shard, buf),
            |key| async move { create_manager.create(&key, proxy).await },
        )
        .await
    }

    pub async fn get_with<F, C, Fut>(&self, build_key: F, create: C) -> Result<M::Connection>
    where
        F: FnOnce(&mut String),
        C: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = Result<M::Connection>>,
    {
        match self.lookup_or_build_key(build_key) {
            LookupOutcome::Hit(conn) => Ok(conn),
            LookupOutcome::Miss(key) => self.create_or_get_existing_owned(key, create).await,
            LookupOutcome::Unhealthy(key) => {
                self.invalidate(&key);
                self.create_or_get_existing_owned(key, create).await
            }
        }
    }

    /// Specialized cache-miss path for pools that need extra per-call
    /// connection-establishment context in addition to the `Proxy`.
    ///
    /// Concurrent callers for the same key coalesce onto one creator. On
    /// success, waiters re-check the cache. On failure, the creator's error is
    /// captured as [`SharedPoolCreateError`] and broadcast to every waiter on
    /// that pending entry so a burst against a hard-down backend fails fast
    /// instead of serially redialing. Cancellation (creator drop) does not
    /// broadcast a failure — waiters re-elect. There is no durable negative
    /// cache: a later independent request registers a fresh pending entry.
    pub async fn create_or_get_existing_owned<C, Fut, E>(
        &self,
        key: String,
        create: C,
    ) -> std::result::Result<M::Connection, E>
    where
        C: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = std::result::Result<M::Connection, E>>,
        E: ShareablePoolCreateError + From<SharedPoolCreateError>,
    {
        let mut create = Some(create);

        loop {
            if let Some(conn) = self.cached(&key) {
                return Ok(conn);
            }

            let (pending, is_creator) = self.register_pending_creation(&key);
            if !is_creator {
                // `watch` stores a durable outcome, so even a waiter that
                // subscribes after the creator finishes will observe it and
                // either return the shared failure or loop without hanging.
                match pending.wait().await {
                    CreationNotify::Failed(err) => return Err(E::from(err)),
                    CreationNotify::Finished | CreationNotify::Pending => continue,
                }
            }

            let pending_guard = PendingCreationGuard::new(self, key.clone(), pending);
            let result = self
                .create_after_recheck(
                    key.clone(),
                    create
                        .take()
                        .expect("create closure should only be consumed by the creator"),
                )
                .await;
            match result {
                Ok(conn) => {
                    pending_guard.finish();
                    return Ok(conn);
                }
                Err(err) => {
                    let shared = err.to_shared();
                    pending_guard.fail(shared);
                    // Preserve the creator's full typed/source error. Only
                    // coalesced waiters need the cloneable reconstruction.
                    return Err(err);
                }
            }
        }
    }

    fn register_pending_creation(&self, key: &str) -> (Arc<PendingCreation>, bool) {
        match self.pending_creations.entry(key.to_owned()) {
            Entry::Occupied(existing) => (existing.get().clone(), false),
            Entry::Vacant(vacant) => {
                let pending = Arc::new(PendingCreation::new());
                vacant.insert(pending.clone());
                (pending, true)
            }
        }
    }

    fn finish_pending_creation(&self, key: &str, pending: Arc<PendingCreation>) {
        // Remove before notifying so a request that arrives after this
        // attempt completes cannot join the retired pending entry.
        self.pending_creations
            .remove_if(key, |_, current| Arc::ptr_eq(current, &pending));
        pending.finish();
    }

    fn finish_pending_creation_failed(
        &self,
        key: &str,
        pending: Arc<PendingCreation>,
        err: SharedPoolCreateError,
    ) {
        self.pending_creations
            .remove_if(key, |_, current| Arc::ptr_eq(current, &pending));
        pending.finish_failed(err);
    }

    async fn create_after_recheck<C, Fut, E>(
        &self,
        key: String,
        create: C,
    ) -> std::result::Result<M::Connection, E>
    where
        C: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = std::result::Result<M::Connection, E>>,
    {
        let _permit = self
            .inflight
            .clone()
            .acquire_owned()
            .await
            .expect("pool creation semaphore should remain open while the pool is alive");

        if let Some(conn) = self.cached(&key) {
            return Ok(conn);
        }

        let created = match create(key.clone()).await {
            Ok(created) => {
                if let Some(kind) = self.manager.runtime_metrics_kind() {
                    crate::runtime_metrics::global_ref().record_pool_handshake(kind);
                }
                created
            }
            Err(err) => {
                if let Some(kind) = self.manager.runtime_metrics_kind() {
                    crate::runtime_metrics::global_ref().record_pool_failure(kind);
                }
                return Err(err);
            }
        };
        let now = now_epoch_ms();

        match self.entries.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
                let entry = occupied.get_mut();
                if self.manager.is_healthy(&entry.conn) {
                    entry.last_used_epoch_ms.store(now, Ordering::Relaxed);
                    let existing = entry.conn.clone();
                    if let Some(kind) = self.manager.runtime_metrics_kind() {
                        crate::runtime_metrics::global_ref().record_pool_eviction(kind);
                    }
                    self.manager.destroy(created);
                    Ok(existing)
                } else {
                    let old = std::mem::replace(&mut entry.conn, created.clone());
                    entry.last_used_epoch_ms.store(now, Ordering::Relaxed);
                    if let Some(kind) = self.manager.runtime_metrics_kind() {
                        crate::runtime_metrics::global_ref().record_pool_eviction(kind);
                    }
                    self.manager.destroy(old);
                    Ok(created)
                }
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(PoolEntry::new(created.clone()));
                Ok(created)
            }
        }
    }

    fn lookup_or_build_key<F>(&self, build_key: F) -> LookupOutcome<M::Connection>
    where
        F: FnOnce(&mut String),
    {
        KEY_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            build_key(&mut buf);

            if let Some(entry) = self.entries.get(&*buf) {
                let conn = entry.conn.clone();
                if self.manager.is_healthy(&conn) {
                    entry
                        .last_used_epoch_ms
                        .store(now_epoch_ms(), Ordering::Relaxed);
                    LookupOutcome::Hit(conn)
                } else {
                    LookupOutcome::Unhealthy(buf.to_string())
                }
            } else {
                LookupOutcome::Miss(buf.to_string())
            }
        })
    }

    fn spawn_cleanup(self: Arc<Self>) {
        let entries = Arc::clone(&self.entries);
        let manager = Arc::clone(&self.manager);
        let idle_timeout_ms = self.cfg.idle_timeout_seconds.saturating_mul(1000);
        let interval = self.cleanup_interval;

        tokio::spawn(async move {
            let mut cleanup_timer = tokio::time::interval(interval);

            loop {
                cleanup_timer.tick().await;

                let now = now_epoch_ms();
                let mut keys_to_remove = Vec::new();

                for entry in entries.iter() {
                    let last_used = entry.last_used_epoch_ms.load(Ordering::Relaxed);
                    let idle_ms = now.saturating_sub(last_used);
                    if idle_ms > idle_timeout_ms || !manager.is_healthy(&entry.conn) {
                        keys_to_remove.push(entry.key().clone());
                    }
                }

                for key in keys_to_remove {
                    if let Some((_, entry)) = entries.remove(&key) {
                        if let Some(kind) = manager.runtime_metrics_kind() {
                            crate::runtime_metrics::global_ref().record_pool_eviction(kind);
                        }
                        manager.destroy(entry.conn);
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{
        AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, ResponseBodyMode,
    };
    use chrono::Utc;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use tokio::sync::Notify;

    #[derive(Default)]
    struct TestManager {
        attempts: AtomicUsize,
        creates: AtomicUsize,
        destroys: AtomicUsize,
        healthy: AtomicBool,
        unhealthy_checks_remaining: AtomicUsize,
        fail_creates_remaining: AtomicUsize,
        create_delay: Duration,
    }

    #[async_trait]
    impl PoolManager for TestManager {
        type Connection = String;

        fn build_key(&self, _proxy: &Proxy, host: &str, port: u16, shard: usize, buf: &mut String) {
            use std::fmt::Write;
            buf.clear();
            let _ = write!(buf, "{host}|{port}|{shard}");
        }

        async fn create(&self, key: &str, _proxy: &Proxy) -> Result<Self::Connection> {
            if !self.create_delay.is_zero() {
                tokio::time::sleep(self.create_delay).await;
            }
            self.attempts.fetch_add(1, Ordering::Relaxed);
            // `Bool::then` is lazy — `remaining - 1` only evaluates when
            // remaining > 0. The `.then_some(remaining - 1)` form was eager
            // and overflowed when fetch_update was retried after a CAS race
            // observed `remaining == 0`.
            if self
                .fail_creates_remaining
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                    (remaining > 0).then(|| remaining - 1)
                })
                .is_ok()
            {
                anyhow::bail!("synthetic create failure for {key}");
            }
            let generation = self.creates.fetch_add(1, Ordering::Relaxed) + 1;
            Ok(format!("{key}|gen={generation}"))
        }

        fn is_healthy(&self, _conn: &Self::Connection) -> bool {
            // Same lazy-vs-eager fix as `create()` above.
            if self
                .unhealthy_checks_remaining
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                    (remaining > 0).then(|| remaining - 1)
                })
                .is_ok()
            {
                return false;
            }
            self.healthy.load(Ordering::Relaxed)
        }

        fn destroy(&self, _conn: Self::Connection) {
            self.destroys.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn test_proxy() -> Proxy {
        let now = Utc::now();
        Proxy {
            id: "pool-test".to_string(),
            namespace: crate::config::types::default_namespace(),
            name: None,
            hosts: vec![],
            listen_path: Some("/pool".to_string()),
            backend_scheme: Some(BackendScheme::Http),
            dispatch_kind: DispatchKind::from(BackendScheme::Http),
            backend_host: "backend.example.com".to_string(),
            backend_port: 8080,
            backend_path: None,
            strip_listen_path: true,
            preserve_host_header: false,
            backend_connect_timeout_ms: 5_000,
            backend_read_timeout_ms: 30_000,
            backend_write_timeout_ms: 30_000,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            resolved_tls: BackendTlsConfig::default_verify(),
            dispatch_port_overrides: None,
            dispatch_port_override_fallback: None,
            dns_override: None,
            dns_cache_ttl_seconds: None,
            auth_mode: AuthMode::Single,
            plugins: vec![],
            pool_idle_timeout_seconds: None,
            pool_enable_http_keep_alive: None,
            pool_enable_http2: None,
            pool_tcp_keepalive_seconds: None,
            pool_http2_keep_alive_interval_seconds: None,
            pool_http2_keep_alive_timeout_seconds: None,
            pool_http2_initial_stream_window_size: None,
            pool_http2_initial_connection_window_size: None,
            pool_http2_adaptive_window: None,
            pool_http2_max_frame_size: None,
            pool_http2_max_concurrent_streams: None,
            pool_http3_connections_per_backend: None,
            h2_upgrade_policy: None,
            pool_max_requests_per_connection: None,
            pool_http1_max_pending_requests: None,
            upstream_id: None,
            upstream_subset: None,
            api_spec_id: None,
            circuit_breaker: None,
            retry: None,
            response_body_mode: ResponseBodyMode::default(),
            listen_port: None,
            frontend_tls: false,
            passthrough: false,
            udp_idle_timeout_seconds: 60,
            tcp_idle_timeout_seconds: Some(300),
            websocket_idle_timeout_seconds: None,
            allowed_methods: None,
            allowed_ws_origins: vec![],
            udp_max_response_amplification_factor: None,
            stream_proxy_protocol: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn pending_creation_wait_handles_late_subscribers() {
        let pending = PendingCreation::new();
        pending.finish();

        let outcome = tokio::time::timeout(Duration::from_millis(50), pending.wait())
            .await
            .expect("completed pending creation should not block late waiters");
        assert!(matches!(outcome, CreationNotify::Finished));
    }

    #[tokio::test]
    async fn pending_creation_wait_fans_out_shared_failure() {
        let pending = PendingCreation::new();
        let shared = SharedPoolCreateError::capture(&std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "connect timed out",
        ));
        pending.finish_failed(shared.clone());

        let outcome = tokio::time::timeout(Duration::from_millis(50), pending.wait())
            .await
            .expect("failed pending creation should not block late waiters");
        match outcome {
            CreationNotify::Failed(err) => {
                assert_eq!(err.kind(), SharedPoolCreateKind::TimedOut);
                assert_eq!(
                    err.error_class(),
                    crate::retry::ErrorClass::ConnectionTimeout
                );
                assert_eq!(err.message(), shared.message());
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn generic_pool_reuses_cached_connection() {
        let manager = Arc::new(TestManager {
            healthy: AtomicBool::new(true),
            ..Default::default()
        });
        let pool = GenericPool::new(
            manager.clone(),
            PoolConfig::default(),
            Duration::from_secs(60),
            64,
        );
        let proxy = test_proxy();

        let first = pool
            .get(&proxy, "backend.example.com", 443, 0)
            .await
            .unwrap();
        let second = pool
            .get(&proxy, "backend.example.com", 443, 0)
            .await
            .unwrap();

        assert_eq!(first, second);
        assert_eq!(manager.creates.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn generic_pool_clears_key_buffer_before_custom_lookup() {
        let manager = Arc::new(TestManager {
            healthy: AtomicBool::new(true),
            ..Default::default()
        });
        let pool = GenericPool::new(
            manager.clone(),
            PoolConfig::default(),
            Duration::from_secs(60),
            64,
        );
        let proxy = test_proxy();

        let _ = pool
            .get(&proxy, "backend.example.com", 443, 0)
            .await
            .unwrap();
        let manual = pool
            .create_or_get_existing_owned("custom-key".to_string(), |key| async move {
                Ok::<_, anyhow::Error>(format!("{key}|manual"))
            })
            .await
            .unwrap();

        assert_eq!(manual, "custom-key|manual");
        assert_eq!(
            pool.cached_with(|buf| buf.push_str("custom-key"))
                .as_deref(),
            Some("custom-key|manual"),
            "custom lookup closures must start from an empty thread-local key buffer"
        );
        assert_eq!(manager.creates.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn generic_pool_deduplicates_concurrent_creation() {
        let manager = Arc::new(TestManager {
            healthy: AtomicBool::new(true),
            create_delay: Duration::from_millis(25),
            ..Default::default()
        });
        let pool = GenericPool::new(
            manager.clone(),
            PoolConfig::default(),
            Duration::from_secs(60),
            64,
        );
        let proxy = test_proxy();

        let mut tasks = Vec::new();
        for _ in 0..16 {
            let pool = pool.clone();
            let proxy = proxy.clone();
            tasks.push(tokio::spawn(async move {
                pool.get(&proxy, "backend.example.com", 443, 0)
                    .await
                    .unwrap()
            }));
        }

        let mut results = Vec::new();
        for task in tasks {
            results.push(task.await.unwrap());
        }

        assert_eq!(manager.creates.load(Ordering::Relaxed), 1);
        assert!(results.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[tokio::test(start_paused = true)]
    async fn generic_pool_fans_out_create_failure_to_coalesced_waiters() {
        let create_delay = Duration::from_millis(50);
        let manager = Arc::new(TestManager {
            healthy: AtomicBool::new(true),
            // Keep failing for the coalesced burst; recovery is a later request.
            fail_creates_remaining: AtomicUsize::new(1),
            create_delay,
            ..Default::default()
        });
        let pool = GenericPool::new(
            manager.clone(),
            PoolConfig::default(),
            Duration::from_secs(60),
            64,
        );
        let proxy = test_proxy();
        let waiter_count = 16;

        let started = tokio::time::Instant::now();
        let mut tasks = Vec::new();
        for _ in 0..waiter_count {
            let pool = pool.clone();
            let proxy = proxy.clone();
            tasks.push(tokio::spawn(async move {
                pool.get(&proxy, "backend.example.com", 443, 0).await
            }));
        }

        let mut results = Vec::new();
        for task in tasks {
            results.push(task.await.unwrap());
        }
        let elapsed = started.elapsed();

        assert!(
            results.iter().all(|result| result.is_err()),
            "every coalesced waiter must observe the creation failure"
        );
        assert_eq!(
            manager.attempts.load(Ordering::Relaxed),
            1,
            "only one create attempt should run for the failed coalesced create"
        );
        assert_eq!(manager.creates.load(Ordering::Relaxed), 0);
        assert!(pool.pending_creations.is_empty());
        assert!(
            elapsed < create_delay.saturating_mul(3),
            "failure fan-out must not serially redial (elapsed {elapsed:?})"
        );
        assert!(
            elapsed >= create_delay,
            "waiters should wait for the single in-flight create (elapsed {elapsed:?})"
        );

        let shared_messages: Vec<&str> = results
            .iter()
            .filter_map(|result| {
                let err = result.as_ref().unwrap_err();
                err.downcast_ref::<SharedPoolCreateError>()
                    .map(SharedPoolCreateError::message)
            })
            .collect();
        assert_eq!(
            shared_messages.len(),
            waiter_count - 1,
            "one creator must retain its original error while every waiter receives the shared error"
        );
        assert!(
            shared_messages.windows(2).all(|pair| pair[0] == pair[1]),
            "all waiters must receive the same shared failure payload: {shared_messages:?}"
        );
        assert!(
            !shared_messages[0].is_empty(),
            "shared failure message must be non-empty"
        );

        // Later independent request can succeed (no durable negative cache).
        let recovered = pool
            .get(&proxy, "backend.example.com", 443, 0)
            .await
            .expect("independent request after failed coalesced create should retry create");
        assert!(recovered.contains("gen=1"));
        assert_eq!(manager.attempts.load(Ordering::Relaxed), 2);
        assert_eq!(manager.creates.load(Ordering::Relaxed), 1);
        assert!(pool.pending_creations.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn generic_pool_create_failure_fanout_is_key_scoped() {
        let create_delay = Duration::from_millis(40);
        let manager = Arc::new(TestManager {
            healthy: AtomicBool::new(true),
            fail_creates_remaining: AtomicUsize::new(1),
            create_delay,
            ..Default::default()
        });
        let pool = GenericPool::new(
            manager.clone(),
            PoolConfig::default(),
            Duration::from_secs(60),
            64,
        );
        let proxy = test_proxy();

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let pool = pool.clone();
            let proxy = proxy.clone();
            tasks.push(tokio::spawn(async move {
                pool.get(&proxy, "backend.example.com", 443, 0).await
            }));
        }
        for task in tasks {
            assert!(
                task.await.unwrap().is_err(),
                "shard-0 coalesced waiters must all observe the failure"
            );
        }
        assert_eq!(manager.attempts.load(Ordering::Relaxed), 1);
        assert!(pool.pending_creations.is_empty());

        // Distinct pool key must not inherit the prior attempt's failure.
        let other = pool
            .get(&proxy, "backend.example.com", 443, 1)
            .await
            .expect("distinct key should create independently after peer-key failure");
        assert!(other.contains("|1|"));
        assert_eq!(manager.attempts.load(Ordering::Relaxed), 2);
        assert_eq!(manager.creates.load(Ordering::Relaxed), 1);
        assert!(pool.pending_creations.is_empty());
    }

    #[tokio::test]
    async fn generic_pool_clears_pending_state_when_creator_is_cancelled() {
        let manager = Arc::new(TestManager {
            healthy: AtomicBool::new(true),
            ..Default::default()
        });
        let pool = GenericPool::new(manager, PoolConfig::default(), Duration::from_secs(60), 64);
        let key = "backend.example.com|443|0".to_string();
        let creator_started = Arc::new(Notify::new());
        let creator_blocked = Arc::new(Notify::new());

        let creator = {
            let pool = pool.clone();
            let key = key.clone();
            let creator_started = creator_started.clone();
            let creator_blocked = creator_blocked.clone();
            tokio::spawn(async move {
                pool.create_or_get_existing_owned(key, move |_key| {
                    let creator_started = creator_started.clone();
                    let creator_blocked = creator_blocked.clone();
                    async move {
                        creator_started.notify_waiters();
                        creator_blocked.notified().await;
                        Ok::<_, anyhow::Error>("creator-cancelled".to_string())
                    }
                })
                .await
            })
        };

        creator_started.notified().await;

        let waiter = {
            let pool = pool.clone();
            let key = key.clone();
            tokio::spawn(async move {
                pool.create_or_get_existing_owned(key, move |_key| async move {
                    Ok::<_, anyhow::Error>("recovered-after-cancel".to_string())
                })
                .await
                .unwrap()
            })
        };

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Some(pending) = pool.pending_creations.get(&key)
                    && Arc::strong_count(pending.value()) >= 3
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("waiter should join the in-flight creation");

        creator.abort();
        assert!(creator.await.unwrap_err().is_cancelled());

        let waiter_result = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter should be retried after creator cancellation")
            .unwrap();
        assert_eq!(waiter_result, "recovered-after-cancel");
        assert!(pool.pending_creations.is_empty());
        assert_eq!(pool.cached(&key).as_deref(), Some("recovered-after-cancel"));
    }

    #[tokio::test]
    async fn generic_pool_recreates_unhealthy_connections() {
        let manager = Arc::new(TestManager {
            healthy: AtomicBool::new(true),
            ..Default::default()
        });
        let pool = GenericPool::new(
            manager.clone(),
            PoolConfig::default(),
            Duration::from_secs(60),
            64,
        );
        let proxy = test_proxy();

        let first = pool
            .get(&proxy, "backend.example.com", 443, 0)
            .await
            .unwrap();
        manager
            .unhealthy_checks_remaining
            .store(1, Ordering::Relaxed);
        let second = pool
            .get(&proxy, "backend.example.com", 443, 0)
            .await
            .unwrap();

        assert_ne!(first, second);
        assert_eq!(manager.creates.load(Ordering::Relaxed), 2);
        assert_eq!(manager.destroys.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn generic_pool_evicts_idle_entries() {
        let manager = Arc::new(TestManager {
            healthy: AtomicBool::new(true),
            ..Default::default()
        });
        let pool = GenericPool::new(
            manager.clone(),
            PoolConfig {
                idle_timeout_seconds: 0,
                ..PoolConfig::default()
            },
            Duration::from_millis(10),
            64,
        );
        let proxy = test_proxy();

        let _ = pool
            .get(&proxy, "backend.example.com", 443, 0)
            .await
            .unwrap();
        assert_eq!(pool.pool_size(), 1);

        tokio::time::sleep(Duration::from_millis(40)).await;

        assert_eq!(pool.pool_size(), 0);
        assert_eq!(manager.destroys.load(Ordering::Relaxed), 1);
    }
}
