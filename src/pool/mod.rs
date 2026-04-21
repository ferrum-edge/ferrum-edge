use anyhow::Result;
use async_trait::async_trait;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
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

struct PendingCreation {
    completion_tx: watch::Sender<bool>,
}

impl PendingCreation {
    fn new() -> Self {
        let (completion_tx, _completion_rx) = watch::channel(false);
        Self { completion_tx }
    }

    async fn wait(&self) {
        let mut completion = self.completion_tx.subscribe();
        if *completion.borrow() {
            return;
        }

        let _ = completion.changed().await;
    }

    fn finish(&self) {
        self.completion_tx.send_replace(true);
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
}

impl<M: PoolManager> Drop for PendingCreationGuard<'_, M> {
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take() {
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
    pub fn new(manager: Arc<M>, cfg: PoolConfig, cleanup_interval: Duration) -> Arc<Self> {
        // Cold-path connection establishment is bounded per pool so a burst of
        // cache misses cannot fan out into unbounded concurrent dials.
        let inflight_limit = std::thread::available_parallelism()
            .map(|parallelism| parallelism.get().clamp(4, 256))
            .unwrap_or(32);
        let pool = Arc::new(Self {
            manager,
            entries: Arc::new(DashMap::new()),
            cfg: Arc::new(cfg),
            cleanup_interval,
            inflight: Arc::new(Semaphore::new(inflight_limit)),
            pending_creations: Arc::new(DashMap::new()),
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
            self.manager.destroy(entry.conn);
        }
    }

    pub fn clear(&self) {
        let keys = self.keys_snapshot();
        for key in keys {
            self.invalidate(&key);
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
    pub async fn create_or_get_existing_owned<C, Fut, E>(
        &self,
        key: String,
        create: C,
    ) -> std::result::Result<M::Connection, E>
    where
        C: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = std::result::Result<M::Connection, E>>,
    {
        let mut create = Some(create);

        loop {
            if let Some(conn) = self.cached(&key) {
                return Ok(conn);
            }

            let (pending, is_creator) = self.register_pending_creation(&key);
            if !is_creator {
                // `watch` stores a durable completion bit, so even a waiter
                // that subscribes after the creator finishes will observe the
                // completed state and loop back without hanging.
                pending.wait().await;
                continue;
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
            pending_guard.finish();
            return result;
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
        self.pending_creations
            .remove_if(key, |_, current| Arc::ptr_eq(current, &pending));
        pending.finish();
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

        let created = create(key.clone()).await?;
        let now = now_epoch_ms();

        match self.entries.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
                let entry = occupied.get_mut();
                if self.manager.is_healthy(&entry.conn) {
                    entry.last_used_epoch_ms.store(now, Ordering::Relaxed);
                    let existing = entry.conn.clone();
                    self.manager.destroy(created);
                    Ok(existing)
                } else {
                    let old = std::mem::replace(&mut entry.conn, created.clone());
                    entry.last_used_epoch_ms.store(now, Ordering::Relaxed);
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
    use crate::config::types::{AuthMode, BackendProtocol, BackendTlsConfig, ResponseBodyMode};
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
            if self
                .fail_creates_remaining
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                    (remaining > 0).then_some(remaining - 1)
                })
                .is_ok()
            {
                anyhow::bail!("synthetic create failure for {key}");
            }
            let generation = self.creates.fetch_add(1, Ordering::Relaxed) + 1;
            Ok(format!("{key}|gen={generation}"))
        }

        fn is_healthy(&self, _conn: &Self::Connection) -> bool {
            if self
                .unhealthy_checks_remaining
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                    (remaining > 0).then_some(remaining - 1)
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
            backend_protocol: BackendProtocol::Http,
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
            upstream_id: None,
            circuit_breaker: None,
            retry: None,
            response_body_mode: ResponseBodyMode::default(),
            listen_port: None,
            frontend_tls: false,
            passthrough: false,
            udp_idle_timeout_seconds: 60,
            tcp_idle_timeout_seconds: Some(300),
            allowed_methods: None,
            allowed_ws_origins: vec![],
            udp_max_response_amplification_factor: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn pending_creation_wait_handles_late_subscribers() {
        let pending = PendingCreation::new();
        pending.finish();

        tokio::time::timeout(Duration::from_millis(50), pending.wait())
            .await
            .expect("completed pending creation should not block late waiters");
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

    #[tokio::test]
    async fn generic_pool_clears_pending_state_after_create_failure() {
        let manager = Arc::new(TestManager {
            healthy: AtomicBool::new(true),
            fail_creates_remaining: AtomicUsize::new(1),
            create_delay: Duration::from_millis(25),
            ..Default::default()
        });
        let pool = GenericPool::new(
            manager.clone(),
            PoolConfig::default(),
            Duration::from_secs(60),
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

        let mut saw_error = false;
        let mut saw_success = false;
        for task in tasks {
            match task.await.unwrap() {
                Ok(_) => saw_success = true,
                Err(_) => saw_error = true,
            }
        }

        assert!(saw_error);
        assert!(saw_success);
        assert!(pool.pending_creations.is_empty());
        assert_eq!(manager.attempts.load(Ordering::Relaxed), 2);
        assert_eq!(manager.creates.load(Ordering::Relaxed), 1);

        let conn = pool
            .get(&proxy, "backend.example.com", 443, 0)
            .await
            .unwrap();
        assert!(conn.contains("gen=1"));
        assert!(pool.pending_creations.is_empty());
        assert_eq!(manager.attempts.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn generic_pool_clears_pending_state_when_creator_is_cancelled() {
        let manager = Arc::new(TestManager {
            healthy: AtomicBool::new(true),
            ..Default::default()
        });
        let pool = GenericPool::new(manager, PoolConfig::default(), Duration::from_secs(60));
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
                if let Some(pending) = pool.pending_creations.get(&key) {
                    if Arc::strong_count(pending.value()) >= 3 {
                        break;
                    }
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
