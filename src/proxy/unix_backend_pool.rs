//! Bounded connection pool for sidecar-ingress Unix-domain backends
//! (issue #3731).
//!
//! Complements [`super::unix_backend`]: every **new physical connection** still
//! runs the full admission gate — canonical containment, directory-chain
//! ownership, socket file type/owner/mode, the post-connect `(dev, ino)`
//! identity re-check, and peer-UID verification — under ONE end-to-end
//! establishment deadline. Pooling only removes the repeated `connect(2)` +
//! protocol handshake, never a check.
//!
//! ## Identity is the key
//!
//! [`UnixPoolKey`] is a STRUCTURED key, not a formatted string: namespace,
//! proxy id, effective upstream id, canonical resolved path, the admitted
//! `(dev, ino, owner_uid)` of the socket object, and the wire protocol. Every
//! retirement is an exact field comparison — there is deliberately no substring
//! matching anywhere in this module, because a substring rule on a
//! security-sensitive retirement can both under-retire (a prefix that does not
//! align on a path segment) and over-retire.
//!
//! Config/generation coverage: the pool is owned by `ProxyState`, which is
//! rebuilt wholesale on config replacement, so a reload constructs a NEW pool
//! and drops the old one — every idle sender is dropped and its driver task
//! ends when its last sender drops. Within one generation, a changed socket
//! path, UID expectation, or wire protocol yields a DIFFERENT key, so a
//! connection admitted under the old identity is never handed out under the new
//! one. [`UnixBackendConnectionPool::force_drain_all`] is the explicit
//! shutdown/test hook.
//!
//! ## Before every checkout
//!
//! A checkout re-runs `admit_socket_for_connect` (which stats the path afresh)
//! and compares the resulting `(dev, ino, owner_uid)` against the entry's
//! admitted identity. A mismatch retires **every** pooled connection for that
//! canonical path — across protocols and proxies — before any request byte is
//! written, and the caller re-admits and re-dials.
//!
//! ## Per-protocol lease semantics
//!
//! * **HTTP/1.1** — an EXCLUSIVE lease, returned to the idle set only after the
//!   ENTIRE response body has been read. Concretely that is the BUFFERED
//!   response path, via [`UnixBackendConnectionPool::checkin_h1_when_idle`].
//!   A streaming, upgraded, errored, partial, or `Connection: close` response
//!   never checks its lease back in — it is dropped, which closes the
//!   connection. Receiving response headers is never sufficient, and neither is
//!   hyper's own `SendRequest::ready()`: h1 `can_write_head()` is already true
//!   while a response body is still being read, so readiness would re-pool a
//!   connection mid-body and pipeline the next request onto it. Pooling
//!   STREAMING h1 responses needs an EOF-anchored lease handoff through
//!   `ResponseBody` and is a deliberate follow-up, not something approximated
//!   unsafely here.
//! * **h2c / native gRPC** — the multiplexable [`MeshMtlsSender`] is cloned per
//!   request and shared. A closed/GOAWAY carrier fails `is_closed()` /
//!   `is_ready()` and is replaced on the next checkout; concurrent misses for
//!   one key are coalesced behind a creation lock bounded by the same
//!   establishment deadline, so one burst opens one connection rather than N.
//!
//! ## Not pooled: WebSocket
//!
//! An RFC 6455 upgrade consumes its HTTP/1.1 carrier for the whole session, so
//! [`UnixBackendConnectionPool::dial_websocket_stream`] performs a dedicated
//! admitted dial that never enters the idle set (issue #3732).

#[cfg(unix)]
mod imp {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use dashmap::DashMap;
    use hyper::client::conn::http1;
    use hyper_util::rt::TokioIo;
    use tokio::sync::Mutex;
    use tracing::debug;

    use crate::config::PoolConfig;
    use crate::config::types::Proxy;
    use crate::proxy::body::{ReplayableRequestBody, SizeLimitedIncoming};
    use crate::proxy::hbone_pool::{entry_idle_expired, unix_secs};
    use crate::proxy::mesh_mtls_pool::MeshMtlsSender;
    use crate::proxy::unix_backend::{
        UnixBackendError, admit_and_connect, connect_admitted, connect_deadline,
        handshake_unix_h2c_sender,
    };
    use crate::runtime_metrics::PoolKind;
    use crate::util::unix_socket::AdmittedUnixSocket;

    /// Request body carried by the pooled HTTP/1.1 Unix sender.
    ///
    /// Identical to the shape the unpooled dispatch used, so the pooled sender's
    /// concrete `SendRequest<B>` type is fixed without changing what the
    /// dispatch path builds: `Left` is the streaming, size-limited frontend
    /// body; `Right` is the retry-replayable buffered body.
    pub type UnixH1RequestBody =
        http_body_util::Either<SizeLimitedIncoming, ReplayableRequestBody>;

    /// Concrete pooled HTTP/1.1 sender type.
    pub type UnixH1Sender = http1::SendRequest<UnixH1RequestBody>;

    /// Wire protocol spoken on an admitted Unix socket. Part of the pool key:
    /// an `http`-declared and an `http2`-declared listener on the same socket
    /// path must never share a physical connection.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum UnixWireProtocol {
        Http1,
        H2c,
    }

    /// Complete transport/security identity of a pooled Unix connection.
    ///
    /// Included: namespace, proxy id, effective upstream id, canonical resolved
    /// path, admitted device/inode/owner, wire protocol.
    ///
    /// Deliberately EXCLUDED: `backend_connect_timeout_ms` and
    /// `backend_read_timeout_ms` are request-only policy applied per dispatch
    /// (repo pool-key rule), and the connection carries no TLS/DNS/SNI identity
    /// at all — a Unix socket has no network authority. Nothing else configures
    /// the H1 or h2c client handshake for this transport, so there is no further
    /// client-behavior segment to encode.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct UnixPoolKey {
        namespace: String,
        proxy_id: String,
        upstream_id: Option<String>,
        path: PathBuf,
        dev: u64,
        ino: u64,
        owner_uid: u32,
        protocol: UnixWireProtocol,
    }

    impl UnixPoolKey {
        fn new(proxy: &Proxy, admitted: &AdmittedUnixSocket, protocol: UnixWireProtocol) -> Self {
            Self {
                namespace: proxy.namespace.clone(),
                proxy_id: proxy.id.clone(),
                upstream_id: proxy.upstream_id.clone(),
                path: admitted.resolved_path().to_path_buf(),
                dev: admitted.device_id(),
                ino: admitted.inode(),
                owner_uid: admitted.owner_uid(),
                protocol,
            }
        }

        /// Canonical socket path this key was admitted against. Retirement
        /// compares this by exact path equality, never by substring.
        pub fn path(&self) -> &Path {
            &self.path
        }
    }

    /// An exclusive HTTP/1.1 lease.
    ///
    /// Dropping the lease retires the physical connection. Only
    /// [`UnixBackendConnectionPool::checkin_h1`] returns it to the idle set, and
    /// only after the response body has been fully read.
    pub struct UnixH1Checkout {
        key: UnixPoolKey,
        admitted: AdmittedUnixSocket,
        /// `true` when this lease came from the idle set rather than a fresh
        /// dial. The dispatch path uses it to decide whether a pre-wire send
        /// failure is an idle keep-alive race worth replaying once on a fresh
        /// connection.
        reused: bool,
        pub sender: UnixH1Sender,
    }

    impl UnixH1Checkout {
        #[inline]
        pub fn reused(&self) -> bool {
            self.reused
        }

        #[inline]
        pub fn key(&self) -> &UnixPoolKey {
            &self.key
        }
    }

    struct IdleH1 {
        sender: UnixH1Sender,
        admitted: AdmittedUnixSocket,
        last_used_at: AtomicU64,
    }

    struct SharedH2c {
        sender: MeshMtlsSender,
        admitted: AdmittedUnixSocket,
        last_used_at: AtomicU64,
    }

    /// Bounded, lock-free-on-hit Unix backend connection manager.
    pub struct UnixBackendConnectionPool {
        pool_config: PoolConfig,
        /// Idle HTTP/1.1 senders per identity. A checked-out sender is NOT in
        /// this map, which is what makes the H1 lease exclusive.
        h1_idle: DashMap<UnixPoolKey, Vec<IdleH1>>,
        /// Shared multiplexable h2c carriers per identity.
        h2c_carriers: DashMap<UnixPoolKey, Vec<SharedH2c>>,
        /// Coalesces concurrent h2c misses for one identity.
        h2c_creation_locks: DashMap<UnixPoolKey, Arc<Mutex<()>>>,
        /// Last admitted `(dev, ino, owner_uid)` observed for a canonical path.
        ///
        /// This is the O(1) replacement detector: a checkout re-admits the path
        /// and compares against this entry, so a socket swap is caught even
        /// though the swap also changes the pool KEY (which would otherwise
        /// simply miss and leave the old connections pooled and live).
        path_identities: DashMap<PathBuf, (u64, u64, u32)>,
        last_prune_unix_secs: AtomicU64,
        hits: AtomicU64,
        misses: AtomicU64,
        physical_connects: AtomicU64,
        identity_retirements: AtomicU64,
        setup_failures: AtomicU64,
    }

    /// Bounded counters for tests and diagnostics. No per-target labels are
    /// exported, so the metric cardinality of this pool is constant.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct UnixPoolStats {
        pub hits: u64,
        pub misses: u64,
        pub physical_connects: u64,
        pub identity_retirements: u64,
        pub setup_failures: u64,
        pub idle_h1_connections: u64,
        pub active_h2c_connections: u64,
    }

    impl UnixBackendConnectionPool {
        pub fn new(pool_config: PoolConfig, shard_amount: usize) -> Self {
            let shards = crate::util::sharding::pool_shard_amount(shard_amount);
            Self {
                pool_config,
                h1_idle: DashMap::with_shard_amount(shards),
                h2c_carriers: DashMap::with_shard_amount(shards),
                h2c_creation_locks: DashMap::with_shard_amount(shards),
                path_identities: DashMap::with_shard_amount(shards),
                last_prune_unix_secs: AtomicU64::new(0),
                hits: AtomicU64::new(0),
                misses: AtomicU64::new(0),
                physical_connects: AtomicU64::new(0),
                identity_retirements: AtomicU64::new(0),
                setup_failures: AtomicU64::new(0),
            }
        }

        pub fn stats(&self) -> UnixPoolStats {
            UnixPoolStats {
                hits: self.hits.load(Ordering::Relaxed),
                misses: self.misses.load(Ordering::Relaxed),
                physical_connects: self.physical_connects.load(Ordering::Relaxed),
                identity_retirements: self.identity_retirements.load(Ordering::Relaxed),
                setup_failures: self.setup_failures.load(Ordering::Relaxed),
                idle_h1_connections: self
                    .h1_idle
                    .iter()
                    .map(|entry| entry.value().len() as u64)
                    .sum(),
                active_h2c_connections: self
                    .h2c_carriers
                    .iter()
                    .map(|entry| entry.value().len() as u64)
                    .sum(),
            }
        }

        /// Drop every pooled connection. Used at shutdown and by tests; a
        /// dropped sender ends its driver task once the connection closes.
        pub fn force_drain_all(&self) {
            self.h1_idle.clear();
            self.h2c_carriers.clear();
            self.h2c_creation_locks.clear();
            self.path_identities.clear();
        }

        /// Retire every pooled connection admitted against `path`, across
        /// protocols and proxies.
        ///
        /// Exact canonical-path equality — never a substring or prefix test.
        /// Called when a live re-admission proves the filesystem object at that
        /// path was replaced, BEFORE any further request byte is written to a
        /// connection that may now be talking to a different peer.
        pub fn retire_socket_path(&self, path: &Path) {
            let mut retired = 0u64;
            self.h1_idle.retain(|key, entries| {
                if key.path() == path {
                    retired = retired.saturating_add(entries.len() as u64);
                    false
                } else {
                    true
                }
            });
            self.h2c_carriers.retain(|key, entries| {
                if key.path() == path {
                    retired = retired.saturating_add(entries.len() as u64);
                    false
                } else {
                    true
                }
            });
            self.h2c_creation_locks.retain(|key, _| key.path() != path);
            self.path_identities.remove(path);
            if retired > 0 {
                self.identity_retirements
                    .fetch_add(retired, Ordering::Relaxed);
                crate::runtime_metrics::global_ref()
                    .record_pool_evictions(PoolKind::UnixBackend, retired);
            }
        }

        #[inline]
        fn idle_timeout_seconds(&self, proxy: &Proxy) -> u64 {
            proxy
                .pool_idle_timeout_seconds
                .unwrap_or(self.pool_config.idle_timeout_seconds)
        }

        /// Idle-connection ceiling per identity. Concurrency is bounded
        /// separately and earlier by the DestinationRule `maxConnections` gate,
        /// so this pool caps only what it retains.
        #[inline]
        fn max_idle_per_key(&self) -> usize {
            self.pool_config.max_idle_per_host.max(1)
        }

        /// Whether a pooled connection's admitted identity still IS the identity
        /// the caller just re-admitted.
        ///
        /// `expected` comes from a FRESH `admit_socket_for_connect` performed on
        /// this checkout, so comparing against it is strictly stronger than
        /// re-stating `still_names_checked_object` here — and it costs no extra
        /// `stat`. The periodic sweep does call `still_names_checked_object`,
        /// because it has no caller-supplied live identity to compare against.
        #[inline]
        fn identity_intact(admitted: &AdmittedUnixSocket, expected: &AdmittedUnixSocket) -> bool {
            admitted.device_id() == expected.device_id()
                && admitted.inode() == expected.inode()
                && admitted.owner_uid() == expected.owner_uid()
        }

        /// Amortized idle sweep. Runs at most once per `interval` seconds
        /// process-wide (CAS-guarded), never per request.
        fn maybe_prune_idle(&self) {
            let now = unix_secs();
            // A disabled idle timeout still needs a periodic closed-connection /
            // identity sweep, just not a per-second one.
            let interval = match self.pool_config.idle_timeout_seconds {
                0 => 60,
                seconds => seconds.clamp(1, 60),
            };
            let last = self.last_prune_unix_secs.load(Ordering::Relaxed);
            if now.saturating_sub(last) < interval {
                return;
            }
            if self
                .last_prune_unix_secs
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
            {
                return;
            }

            let idle_timeout = self.pool_config.idle_timeout_seconds;
            let mut evicted = 0u64;
            self.h1_idle.retain(|_, entries| {
                let before = entries.len();
                entries.retain(|entry| {
                    !entry.sender.is_closed()
                        && !entry_idle_expired(
                            entry.last_used_at.load(Ordering::Relaxed),
                            idle_timeout,
                            now,
                        )
                        && entry
                            .admitted
                            .still_names_checked_object()
                            .unwrap_or(false)
                });
                evicted = evicted.saturating_add(before.saturating_sub(entries.len()) as u64);
                !entries.is_empty()
            });
            self.h2c_carriers.retain(|_, entries| {
                let before = entries.len();
                entries.retain(|entry| {
                    !entry.sender.is_closed()
                        && !entry_idle_expired(
                            entry.last_used_at.load(Ordering::Relaxed),
                            idle_timeout,
                            now,
                        )
                        && entry
                            .admitted
                            .still_names_checked_object()
                            .unwrap_or(false)
                });
                evicted = evicted.saturating_add(before.saturating_sub(entries.len()) as u64);
                !entries.is_empty()
            });
            if evicted > 0 {
                crate::runtime_metrics::global_ref()
                    .record_pool_evictions(PoolKind::UnixBackend, evicted);
            }
            // Only retain locks that are still contended or still name a live
            // carrier, so the lock map cannot grow without bound.
            self.h2c_creation_locks
                .retain(|key, lock| Arc::strong_count(lock) > 1 || self.h2c_carriers.contains_key(key));
        }

        /// Re-admit `socket_path` and, when the resulting identity differs from
        /// anything pooled for that canonical path, retire those connections
        /// before returning.
        fn admit_and_reconcile(
            &self,
            socket_path: &str,
            allowed_roots: &[String],
            allowed_uids: &[u32],
        ) -> Result<AdmittedUnixSocket, UnixBackendError> {
            let admitted = crate::util::unix_socket::admit_socket_for_connect(
                socket_path,
                allowed_roots,
                allowed_uids,
            )
            .map_err(UnixBackendError::InadmissiblePath)?;
            let live = (
                admitted.device_id(),
                admitted.inode(),
                admitted.owner_uid(),
            );
            let path = admitted.resolved_path();
            let previous = self
                .path_identities
                .get(path)
                .map(|entry| *entry.value());
            match previous {
                Some(previous) if previous != live => {
                    // The filesystem object at this canonical path was replaced.
                    // Retire every connection admitted against the old identity
                    // BEFORE the caller can write a request byte, then record
                    // the new identity so the next checkout is a clean miss.
                    let owned = path.to_path_buf();
                    self.retire_socket_path(&owned);
                    self.path_identities.insert(owned, live);
                }
                Some(_) => {}
                None => {
                    self.path_identities.insert(path.to_path_buf(), live);
                }
            }
            Ok(admitted)
        }

        /// Acquire an exclusive HTTP/1.1 lease for `socket_path`.
        ///
        /// Cancellation-safe: there is no queueing wait. A hit returns
        /// immediately; a miss dials and handshakes inside ONE establishment
        /// deadline shared with the admission that preceded it.
        pub async fn checkout_h1(
            &self,
            proxy: &Proxy,
            socket_path: &str,
            connect_timeout_ms: u64,
            allowed_roots: &[String],
            allowed_uids: &[u32],
        ) -> Result<UnixH1Checkout, UnixBackendError> {
            self.maybe_prune_idle();
            let admitted =
                self.admit_and_reconcile(socket_path, allowed_roots, allowed_uids)?;
            let key = UnixPoolKey::new(proxy, &admitted, UnixWireProtocol::Http1);

            if let Some(checkout) = self.take_idle_h1(&key, &admitted, proxy) {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(checkout);
            }
            self.misses.fetch_add(1, Ordering::Relaxed);
            self.dial_h1(key, admitted, connect_timeout_ms).await
        }

        /// Force a fresh physical HTTP/1.1 connection, bypassing the idle set.
        ///
        /// Used for exactly one replay when a REUSED lease failed pre-wire — the
        /// classic idle keep-alive race, where the backend closed the connection
        /// between check-in and the next request. The admission gate runs again
        /// in full.
        pub async fn checkout_fresh_h1(
            &self,
            proxy: &Proxy,
            socket_path: &str,
            connect_timeout_ms: u64,
            allowed_roots: &[String],
            allowed_uids: &[u32],
        ) -> Result<UnixH1Checkout, UnixBackendError> {
            let admitted =
                self.admit_and_reconcile(socket_path, allowed_roots, allowed_uids)?;
            let key = UnixPoolKey::new(proxy, &admitted, UnixWireProtocol::Http1);
            self.misses.fetch_add(1, Ordering::Relaxed);
            self.dial_h1(key, admitted, connect_timeout_ms).await
        }

        async fn dial_h1(
            &self,
            key: UnixPoolKey,
            admitted: AdmittedUnixSocket,
            connect_timeout_ms: u64,
        ) -> Result<UnixH1Checkout, UnixBackendError> {
            let (timeout_ms, deadline) = connect_deadline(connect_timeout_ms)?;
            let connect = connect_admitted(&admitted, connect_timeout_ms);
            let stream = match tokio::time::timeout_at(deadline, connect).await {
                Ok(result) => result.inspect_err(|_| self.record_setup_failure())?,
                Err(_) => {
                    self.record_setup_failure();
                    return Err(UnixBackendError::ConnectTimeout { timeout_ms });
                }
            };

            let handshake =
                http1::Builder::new().handshake::<_, UnixH1RequestBody>(TokioIo::new(stream));
            let (sender, connection) = match tokio::time::timeout_at(deadline, handshake).await {
                Ok(Ok(parts)) => parts,
                Ok(Err(err)) => {
                    self.record_setup_failure();
                    return Err(UnixBackendError::Http1Handshake(err));
                }
                Err(_) => {
                    self.record_setup_failure();
                    return Err(UnixBackendError::ConnectTimeout { timeout_ms });
                }
            };
            // The driver is owned by the sender's lifetime: it resolves when the
            // connection closes, which happens as soon as the last sender for it
            // is dropped. Pool drain / `ProxyState` replacement therefore ends
            // these tasks deterministically without a detached generation
            // registry.
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    debug!("unix_backend_pool: h1 connection closed: {}", e);
                }
            });
            self.physical_connects.fetch_add(1, Ordering::Relaxed);
            crate::runtime_metrics::global_ref().record_pool_handshake(PoolKind::UnixBackend);

            Ok(UnixH1Checkout {
                key,
                admitted,
                reused: false,
                sender,
            })
        }

        fn take_idle_h1(
            &self,
            key: &UnixPoolKey,
            expected: &AdmittedUnixSocket,
            proxy: &Proxy,
        ) -> Option<UnixH1Checkout> {
            let idle_timeout = self.idle_timeout_seconds(proxy);
            let now = unix_secs();
            let mut entries = self.h1_idle.get_mut(key)?;
            while let Some(entry) = entries.pop() {
                if !Self::identity_intact(&entry.admitted, expected) {
                    // The path no longer names the admitted object. Drop this
                    // guard first, then retire everything for the path — no
                    // request byte has been written on any of them.
                    drop(entries);
                    let path = expected.resolved_path().to_path_buf();
                    self.retire_socket_path(&path);
                    return None;
                }
                // `is_closed()` (not `is_ready()`) is the reuse gate. hyper's
                // `is_ready()` reports "the dispatcher has already asked for the
                // next request", which is a scheduling artifact, not a liveness
                // fact — a perfectly good connection reads as not-ready until its
                // driver task next polls. The genuine idle keep-alive race (the
                // peer reaped the socket after check-in) is caught by the
                // dispatch path's `try_send_request` replay, which recovers the
                // unsent request and redials.
                if entry.sender.is_closed()
                    || entry_idle_expired(
                        entry.last_used_at.load(Ordering::Relaxed),
                        idle_timeout,
                        now,
                    )
                {
                    continue;
                }
                return Some(UnixH1Checkout {
                    key: key.clone(),
                    admitted: entry.admitted,
                    reused: true,
                    sender: entry.sender,
                });
            }
            None
        }

        /// Return an HTTP/1.1 lease to the idle set.
        ///
        /// The dispatch path MUST NOT call this directly for a connection that
        /// carried a request — use [`Self::checkin_h1_when_idle`], which waits
        /// for hyper to report the exchange complete. This entry point is for a
        /// lease whose request was ABANDONED before it was ever sent (an invalid
        /// backend URL, an unparseable method) and for tests.
        ///
        /// A sender that is closed, or whose socket identity changed, is dropped
        /// instead of pooled.
        pub fn checkin_h1(&self, checkout: UnixH1Checkout) {
            let UnixH1Checkout {
                key,
                admitted,
                reused: _,
                sender,
            } = checkout;
            if sender.is_closed() {
                return;
            }
            if !admitted.still_names_checked_object().unwrap_or(false) {
                let path = admitted.resolved_path().to_path_buf();
                drop(sender);
                self.retire_socket_path(&path);
                return;
            }
            let max_idle = self.max_idle_per_key();
            let mut entries = self.h1_idle.entry(key).or_default();
            if entries.len() >= max_idle {
                // Bound the idle set: drop the OLDEST idle connection, which is
                // the one most likely to have been reaped by the peer.
                entries.remove(0);
                crate::runtime_metrics::global_ref()
                    .record_pool_eviction(PoolKind::UnixBackend);
            }
            entries.push(IdleH1 {
                sender,
                admitted,
                last_used_at: AtomicU64::new(unix_secs()),
            });
        }

        /// Return an HTTP/1.1 lease whose response body has ALREADY been read in
        /// full, once hyper's dispatcher has also re-armed for the next request.
        ///
        /// The caller establishes the safety precondition (the body is
        /// complete); this only closes the scheduling gap. Reading the last body
        /// byte does not synchronously make the sender usable again — the
        /// connection driver has to poll once more before its `want` channel
        /// re-arms — so a synchronous check-in would pool a sender that the very
        /// next `try_send_request` would bounce, and the pool would never
        /// actually reuse anything.
        ///
        /// It is therefore ONLY correct for a fully-read body. Do not reuse it to
        /// pool a streaming response: h1 `can_write_head()` is true while a
        /// response body is still being read, so `ready()` would resolve mid-body.
        ///
        /// If the connection died instead, `ready()` resolves `Err` and the lease
        /// is dropped. The waiter therefore lives exactly as long as the
        /// connection it owns — it cannot outlive it or leak.
        ///
        /// An associated function rather than a method because `&Arc<Self>` is
        /// not a permitted method receiver on stable Rust.
        pub fn checkin_h1_when_idle(pool: &Arc<Self>, mut checkout: UnixH1Checkout) {
            if checkout.sender.is_closed() {
                return;
            }
            if checkout.sender.is_ready() {
                pool.checkin_h1(checkout);
                return;
            }
            let pool = Arc::clone(pool);
            tokio::spawn(async move {
                if checkout.sender.ready().await.is_ok() {
                    pool.checkin_h1(checkout);
                }
            });
        }

        /// Acquire a multiplexable h2c sender for `socket_path`.
        ///
        /// Concurrent misses for one identity are coalesced behind a creation
        /// lock whose wait is bounded by the same establishment deadline as the
        /// dial itself, so a wedged local app cannot pin queued requests past
        /// the budget the caller already committed to.
        pub async fn checkout_h2c(
            &self,
            proxy: &Proxy,
            socket_path: &str,
            connect_timeout_ms: u64,
            allowed_roots: &[String],
            allowed_uids: &[u32],
        ) -> Result<MeshMtlsSender, UnixBackendError> {
            self.maybe_prune_idle();
            let admitted =
                self.admit_and_reconcile(socket_path, allowed_roots, allowed_uids)?;
            let key = UnixPoolKey::new(proxy, &admitted, UnixWireProtocol::H2c);

            if let Some(sender) = self.take_shared_h2c(&key, &admitted, proxy) {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(sender);
            }

            let (timeout_ms, deadline) = connect_deadline(connect_timeout_ms)?;
            let lock = self
                .h2c_creation_locks
                .entry(key.clone())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone();
            let _guard = match tokio::time::timeout_at(deadline, lock.lock()).await {
                Ok(guard) => guard,
                Err(_) => {
                    self.record_setup_failure();
                    return Err(UnixBackendError::ConnectTimeout { timeout_ms });
                }
            };

            // The winner of the lock may have published a carrier while we
            // waited; re-check before spending another connect.
            if let Some(sender) = self.take_shared_h2c(&key, &admitted, proxy) {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(sender);
            }
            self.misses.fetch_add(1, Ordering::Relaxed);

            let connect = connect_admitted(&admitted, connect_timeout_ms);
            let stream = match tokio::time::timeout_at(deadline, connect).await {
                Ok(result) => result.inspect_err(|_| self.record_setup_failure())?,
                Err(_) => {
                    self.record_setup_failure();
                    return Err(UnixBackendError::ConnectTimeout { timeout_ms });
                }
            };
            let sender = handshake_unix_h2c_sender(stream, deadline, timeout_ms)
                .await
                .inspect_err(|_| self.record_setup_failure())?;
            self.physical_connects.fetch_add(1, Ordering::Relaxed);
            crate::runtime_metrics::global_ref().record_pool_handshake(PoolKind::UnixBackend);

            let max_idle = self.max_idle_per_key();
            {
                let mut entries = self.h2c_carriers.entry(key).or_default();
                while entries.len() >= max_idle {
                    entries.remove(0);
                    crate::runtime_metrics::global_ref()
                        .record_pool_eviction(PoolKind::UnixBackend);
                }
                entries.push(SharedH2c {
                    sender: sender.clone(),
                    admitted,
                    last_used_at: AtomicU64::new(unix_secs()),
                });
            }
            Ok(sender)
        }

        fn take_shared_h2c(
            &self,
            key: &UnixPoolKey,
            expected: &AdmittedUnixSocket,
            proxy: &Proxy,
        ) -> Option<MeshMtlsSender> {
            let idle_timeout = self.idle_timeout_seconds(proxy);
            let now = unix_secs();
            let mut retire = false;
            let mut selected = None;
            {
                let entries = self.h2c_carriers.get(key)?;
                for entry in entries.iter() {
                    if !Self::identity_intact(&entry.admitted, expected) {
                        retire = true;
                        break;
                    }
                    if entry.sender.is_closed()
                        || entry_idle_expired(
                            entry.last_used_at.load(Ordering::Relaxed),
                            idle_timeout,
                            now,
                        )
                    {
                        continue;
                    }
                    entry.last_used_at.store(now, Ordering::Relaxed);
                    selected = Some(entry.sender.clone());
                    break;
                }
            }
            if retire {
                let path = expected.resolved_path().to_path_buf();
                self.retire_socket_path(&path);
                return None;
            }
            selected
        }

        #[inline]
        fn record_setup_failure(&self) {
            self.setup_failures.fetch_add(1, Ordering::Relaxed);
            crate::runtime_metrics::global_ref().record_pool_failure(PoolKind::UnixBackend);
        }

        /// Dedicated admitted dial for an RFC 6455 WebSocket upgrade
        /// (issue #3732).
        ///
        /// NEVER pooled and never returned to the idle set: the upgrade consumes
        /// the connection for the whole session. Admission, containment,
        /// owner/mode/type, inode identity, and peer-UID verification all
        /// complete inside the single establishment deadline and BEFORE the
        /// caller writes the first upgrade byte.
        pub async fn dial_websocket_stream(
            socket_path: &str,
            connect_timeout_ms: u64,
            allowed_roots: &[String],
            allowed_uids: &[u32],
        ) -> Result<(AdmittedUnixSocket, tokio::net::UnixStream), UnixBackendError> {
            let (timeout_ms, deadline) = connect_deadline(connect_timeout_ms)?;
            let connect =
                admit_and_connect(socket_path, connect_timeout_ms, allowed_roots, allowed_uids);
            match tokio::time::timeout_at(deadline, connect).await {
                Ok(result) => result,
                Err(_) => Err(UnixBackendError::ConnectTimeout { timeout_ms }),
            }
        }
    }
}

/// Non-Unix build: there is no Unix-domain socket to pool, so the surface
/// exists only so `ProxyState` can always carry the type and every dispatch
/// path keeps its fail-closed refusal at compile time.
#[cfg(not(unix))]
mod imp {
    use crate::config::PoolConfig;
    use crate::config::types::Proxy;
    use crate::proxy::mesh_mtls_pool::MeshMtlsSender;
    use crate::proxy::unix_backend::UnixBackendError;

    pub struct UnixH1Checkout;

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct UnixPoolStats {
        pub hits: u64,
        pub misses: u64,
        pub physical_connects: u64,
        pub identity_retirements: u64,
        pub setup_failures: u64,
        pub idle_h1_connections: u64,
        pub active_h2c_connections: u64,
    }

    pub struct UnixBackendConnectionPool;

    impl UnixBackendConnectionPool {
        pub fn new(_pool_config: PoolConfig, _shard_amount: usize) -> Self {
            Self
        }

        pub fn force_drain_all(&self) {}

        pub fn stats(&self) -> UnixPoolStats {
            UnixPoolStats::default()
        }

        pub async fn checkout_h1(
            &self,
            _proxy: &Proxy,
            _socket_path: &str,
            _connect_timeout_ms: u64,
            _allowed_roots: &[String],
            _allowed_uids: &[u32],
        ) -> Result<UnixH1Checkout, UnixBackendError> {
            Err(UnixBackendError::PlatformUnsupported)
        }

        pub async fn checkout_fresh_h1(
            &self,
            _proxy: &Proxy,
            _socket_path: &str,
            _connect_timeout_ms: u64,
            _allowed_roots: &[String],
            _allowed_uids: &[u32],
        ) -> Result<UnixH1Checkout, UnixBackendError> {
            Err(UnixBackendError::PlatformUnsupported)
        }

        pub fn checkin_h1(&self, _checkout: UnixH1Checkout) {}

        pub fn checkin_h1_when_idle(
            _pool: &std::sync::Arc<Self>,
            _checkout: UnixH1Checkout,
        ) {
        }

        pub async fn checkout_h2c(
            &self,
            _proxy: &Proxy,
            _socket_path: &str,
            _connect_timeout_ms: u64,
            _allowed_roots: &[String],
            _allowed_uids: &[u32],
        ) -> Result<MeshMtlsSender, UnixBackendError> {
            Err(UnixBackendError::PlatformUnsupported)
        }
    }
}

pub use imp::*;
