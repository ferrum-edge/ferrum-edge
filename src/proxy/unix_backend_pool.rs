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
//! ## Config lifecycle
//!
//! The pool is owned by `ProxyState`, which SURVIVES a config reload (the
//! config itself is swapped through an `ArcSwap`), so publication has to retire
//! withdrawn carriers explicitly.
//!
//! EVERY successfully published request epoch reconciles the pool through
//! [`UnixBackendConnectionPool::retain_live_targets_for_publication`], with the
//! exact set of `mesh.unix_socket` target identities THE CONFIG THAT WAS
//! ACTUALLY PUBLISHED declares. That is all three publication paths —
//! `ProxyState::update_config`'s
//! initial full rebuild, its incremental delta branch, and
//! `ProxyState::apply_incremental`'s separate database/CP-DP path — and the
//! call happens immediately after the epoch swap, BEFORE any early return for a
//! delta-free (mesh-only / MMDB-only / projected-route-only) republication. A
//! candidate that was REJECTED, and one the epoch swap reported as genuinely
//! unchanged (`Ok(None)`, which never becomes current), do not reconcile and do
//! not advance the generation.
//!
//! Every pooled carrier whose
//! `(namespace, proxy id, upstream id, configured path, wire protocol)` tuple is
//! not in that set is retired before it can serve another request. The
//! comparison is exact tuple equality — there is no substring, prefix, or
//! path-containment rule anywhere in this module, because such a rule on a
//! security-sensitive retirement both under-retires (a prefix that does not
//! align on a path segment) and over-retires.
//!
//! That covers a withdrawn target, a deleted proxy or upstream, a namespace or
//! upstream re-binding, a changed socket path, and an `http` ⇄ `http2`
//! protocol flip. A change to the socket OBJECT (a replaced inode or a new
//! owner uid) is caught on the checkout path instead, by `admit_and_reconcile`,
//! because it is invisible to config. The containment allowlist and UID
//! allowlist are process env (`FERRUM_MESH_UNIX_SOCKET_ALLOWED_ROOTS` /
//! `_ALLOWED_UIDS`) and cannot change without a restart.
//!
//! ## The withdrawal fence
//!
//! Retiring the idle maps is NOT sufficient on its own. An HTTP/1.1 lease that
//! is checked out is deliberately absent from `h1_idle`, so a publication
//! cannot see it, and its exchange may finish long AFTER the target it belongs
//! to was withdrawn. Nothing about a socket that is still open and still names
//! the same inode would stop that late check-in from repopulating the idle set
//! under a config-declared identity that no longer exists.
//!
//! Every retirement bumps a monotonic PUBLICATION GENERATION
//! (`retain_live_targets`, `force_drain_all`, and hence `shutdown_drain`)
//! BEFORE its retirement pass runs. Three rules hang off that one counter, and
//! together they make a carrier NON-LAUNDERABLE: there is no instant, however
//! brief, at which a request can be handed a carrier that a publication has
//! already superseded.
//!
//! 1. **The lease token.** Every lease records the generation current when it
//!    was acquired, and a check-in is refused unless that is still the current
//!    generation. This generational test closes same-key ABA: a target
//!    withdrawn and re-added under the exact same tuple is a NEW incarnation,
//!    and a lease from the previous one must not re-enter it. The cost is that
//!    a lease outstanding across ANY publication is conservatively retired
//!    rather than reused — one connection per in-flight exchange per
//!    publication, paid off the hot path.
//! 2. **The entry token.** Every idle H1 entry and every shared h2c carrier
//!    also carries the generation it was PUBLISHED INTO THE MAP under, and a
//!    checkout refuses any entry whose token is not the current generation,
//!    reading both under the same shard guard. A two-read check-in fence alone
//!    was NOT enough: it makes an old-generation entry briefly VISIBLE between
//!    its insert and its withdrawal, and a concurrent checkout could pop it in
//!    that window and re-stamp it with the caller's own generation — laundering
//!    a carrier out of a withdrawn incarnation into a new request. With the
//!    token on the entry, that pop refuses instead.
//!
//!    So that an unrelated publication does not throw away every idle carrier
//!    in the pool, `retain_live_targets` ADVANCES the token of each retained
//!    entry to the new generation while it holds that entry's shard: an entry
//!    the pass itself observed under a still-declared identity is, by
//!    construction, a continuously-live carrier. A token can never run ahead of
//!    the counter, so a lost update between two concurrent passes only ever
//!    refuses reuse.
//! 3. **The live-set snapshot and withdrawal tombstone.** Publication installs
//!    a lock-free snapshot of the exact identities it declares. A check-in or
//!    h2c publish compares the identity already owned by its pool key against
//!    that snapshot, without constructing strings, before it can become
//!    reusable. This covers a withdrawn identity even when the retirement pass
//!    had no existing slot to tombstone. For keys the pass can see, an absent
//!    identity also keeps its emptied slot marked withdrawn, closing the map
//!    insertion race under the same shard guard. A later publication that
//!    declares the identity again clears the mark, leaving the slot empty: the
//!    re-added incarnation starts from a freshly admitted dial.
//!
//! ### The interleavings
//!
//! Publication is ordered "bump, install live snapshot, THEN retire"; a
//! check-in reads the generation, inserts a UNIQUELY IDENTIFIED entry, releases
//! the shard, and re-reads.
//!
//! * *Publication sees the insert.* The retirement pass finds the entry: it
//!   removes it (withdrawn identity) or advances its token (live identity).
//! * *Publication completes before the insert.* The check-in's post-insert
//!   re-read observes the bump — the shard release/acquire pair orders it — and
//!   withdraws exactly the entry it inserted, by id, so a losing cleanup can
//!   never delete a newer sibling carrier for the same key.
//! * *A checkout races that window.* The entry is visible but still carries the
//!   OLD token, and the checkout compares the token against the generation it
//!   reads under the same shard guard. It refuses and drops it; it cannot be
//!   re-stamped into a new request.
//! * *Same-key withdraw/re-add ABA.* Rule 1 keeps the outstanding lease out
//!   (its token is two generations stale). Rule 3 keeps a stale-epoch dial's
//!   late check-in out for as long as the identity is withdrawn, including
//!   when there was no slot at withdrawal, and the re-add clears an EMPTY slot,
//!   so the new incarnation cannot inherit a carrier from the old one.
//! * *Late h2c publish.* `checkout_h2c` publishes its carrier into a shared map
//!   after a dial that can straddle a publication, so it runs the identical
//!   sequence: tombstone check, insert with a token, post-insert re-read,
//!   exact-id withdrawal. `take_shared_h2c` refuses non-current tokens.
//! * *Shutdown.* `shutdown_drain` latches the pool closed AND bumps the
//!   generation, so a check-in that read the latch unset a moment earlier is
//!   still refused by rule 1.
//!
//! [`UnixBackendConnectionPool::force_drain_all`] retires everything but leaves
//! the pool usable; [`UnixBackendConnectionPool::shutdown_drain`] additionally
//! latches the pool closed so a late check-in racing graceful shutdown cannot
//! repopulate it.
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
//!   ENTIRE response body has been read, for BOTH the buffered and the
//!   streaming response path.
//!
//!   The buffered path reads the body inside the dispatch function and calls
//!   [`UnixBackendConnectionPool::checkin_h1_when_idle`] directly. The streaming
//!   path cannot: the body leaves the dispatch function. It therefore hands the
//!   lease to the client-visible `ProxyBody` as a
//!   [`crate::proxy::body::PooledBackendLease`] (see
//!   [`UnixBackendConnectionPool::streaming_lease`]), which returns it from
//!   exactly one place — the `Poll::Ready(None)` arm of `ProxyBody::poll_frame`,
//!   i.e. clean end-of-stream on the outermost body, which is reachable only
//!   after the inner `hyper::body::Incoming` yielded its own `Ready(None)`.
//!   Everything else (body error, backend close, client cancellation, an early
//!   body drop, a read timeout, an aborted request, a fired client deadline,
//!   shutdown) leaves the lease in place and its `Drop` retires the connection.
//!
//!   Receiving response headers is never sufficient, and neither is hyper's own
//!   `SendRequest::ready()`: h1 `can_write_head()` is already true while a
//!   response body is still being read, so readiness alone would re-pool a
//!   connection mid-body and pipeline the next request onto it. Readiness is
//!   used only as the SECOND half of the check-in, after the caller has already
//!   proven the body is complete, to close the dispatcher re-arm gap —
//!   `SendRequest::try_send_request` does not wait for readiness, so a sender
//!   pooled before its dispatcher re-arms would bounce the next request.
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
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use arc_swap::ArcSwapOption;
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
    pub type UnixH1RequestBody = http_body_util::Either<SizeLimitedIncoming, ReplayableRequestBody>;

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

    /// The CONFIG-declared identity of a Unix ingress target, independent of
    /// any filesystem observation.
    ///
    /// This is the half of [`UnixPoolKey`] that a published `GatewayConfig` can
    /// reproduce without touching the filesystem, and it is what
    /// [`UnixBackendConnectionPool::retain_live_targets`] compares on reload.
    /// Equality is exact on every field; nothing here is matched by substring
    /// or prefix.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct UnixTargetIdentity {
        pub namespace: String,
        pub proxy_id: String,
        pub upstream_id: Option<String>,
        /// The socket path exactly as the `mesh.unix_socket` tag declares it,
        /// BEFORE symlink resolution. Config can only reproduce this form.
        pub configured_path: String,
        pub protocol: UnixWireProtocol,
    }

    /// Complete transport/security identity of a pooled Unix connection.
    ///
    /// Included: namespace, proxy id, effective upstream id, the CONFIGURED
    /// socket path, the canonical resolved path, admitted device/inode/owner,
    /// and wire protocol.
    ///
    /// The configured path is carried in addition to the resolved one so config
    /// publication can retire withdrawn targets by exact tuple equality without
    /// re-resolving symlinks (see [`UnixTargetIdentity`]). Two configured paths
    /// that resolve to the same object still key separately, which is the
    /// conservative direction: it costs one extra connection and never shares
    /// one across declarations.
    ///
    /// Deliberately EXCLUDED: `backend_connect_timeout_ms` and
    /// `backend_read_timeout_ms` are request-only policy applied per dispatch
    /// (repo pool-key rule), and the connection carries no TLS/DNS/SNI identity
    /// at all — a Unix socket has no network authority. Nothing else configures
    /// the H1 or h2c client handshake for this transport, so there is no further
    /// client-behavior segment to encode.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct UnixPoolKey {
        /// Config-reproducible identity, stored once so publication and
        /// check-in liveness tests never allocate or rebuild it.
        target: UnixTargetIdentity,
        path: PathBuf,
        dev: u64,
        ino: u64,
        owner_uid: u32,
    }

    impl UnixPoolKey {
        fn new(
            proxy: &Proxy,
            configured_path: &str,
            admitted: &AdmittedUnixSocket,
            protocol: UnixWireProtocol,
        ) -> Self {
            Self {
                target: UnixTargetIdentity {
                    namespace: proxy.namespace.clone(),
                    proxy_id: proxy.id.clone(),
                    upstream_id: proxy.upstream_id.clone(),
                    configured_path: configured_path.to_string(),
                    protocol,
                },
                path: admitted.resolved_path().to_path_buf(),
                dev: admitted.device_id(),
                ino: admitted.inode(),
                owner_uid: admitted.owner_uid(),
            }
        }

        /// Canonical socket path this key was admitted against. Retirement
        /// compares this by exact path equality, never by substring.
        pub fn path(&self) -> &Path {
            &self.path
        }

        /// The config-reproducible identity of this key.
        fn target_identity(&self) -> &UnixTargetIdentity {
            &self.target
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
        /// The pool's publication generation at the moment this lease was
        /// acquired. The check-in fence admits the carrier back into the idle
        /// set only while this is still the current generation, which is what
        /// stops an exchange that outlived a withdrawal — or a withdrawal
        /// followed by a same-identity re-add — from repopulating the pool.
        generation: u64,
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

        /// The publication generation this lease is bound to.
        #[inline]
        #[allow(dead_code)] // Bin target omits lib::_test_support; external tests read it there.
        pub fn generation(&self) -> u64 {
            self.generation
        }
    }

    /// EOF-anchored owner of an exclusive HTTP/1.1 lease for a STREAMING
    /// response (issue #3731).
    ///
    /// Constructed by [`UnixBackendConnectionPool::streaming_lease`] and stored
    /// on the client-visible `ProxyBody`. Two exits, and only two:
    ///
    /// * `release_on_clean_eof` — the body yielded `Ready(None)`, so the whole
    ///   `hyper::body::Incoming` was consumed. Hand the carrier to
    ///   `checkin_h1_when_idle`, which additionally waits for hyper's h1
    ///   dispatcher to re-arm and re-checks liveness and socket identity.
    /// * `Drop` with the lease still present — every abnormal terminal. The
    ///   `UnixH1Checkout` drops, its `SendRequest` drops, and hyper closes the
    ///   connection. Nothing is pooled, so it can never be reused.
    struct UnixH1StreamingLease {
        pool: Arc<UnixBackendConnectionPool>,
        /// `Some` until one of the two exits fires.
        checkout: Option<UnixH1Checkout>,
    }

    impl crate::proxy::body::PooledBackendLease for UnixH1StreamingLease {
        fn release_on_clean_eof(mut self: Box<Self>) {
            if let Some(checkout) = self.checkout.take() {
                UnixBackendConnectionPool::checkin_h1_when_idle(&self.pool, checkout);
            }
        }
    }

    struct IdleH1 {
        /// Process-unique id, so a check-in that loses the publication race can
        /// withdraw EXACTLY the entry it inserted and no other — including a
        /// concurrently pooled carrier for the same key.
        id: u64,
        /// Publication generation this entry is REUSABLE under (fence rule 2).
        /// Set to the inserting lease's generation, and advanced by a
        /// retirement pass that observes the entry under a still-live identity.
        generation: AtomicU64,
        sender: UnixH1Sender,
        admitted: AdmittedUnixSocket,
        last_used_at: AtomicU64,
    }

    struct SharedH2c {
        /// See [`IdleH1::id`].
        id: u64,
        /// See [`IdleH1::generation`].
        generation: AtomicU64,
        sender: MeshMtlsSender,
        admitted: AdmittedUnixSocket,
        last_used_at: AtomicU64,
    }

    /// The parts of a pooled entry the shared slot maintenance needs, so the
    /// H1 and h2c maps cannot drift in how they are retired, pruned, fenced,
    /// or withdrawn.
    trait PooledEntry {
        fn id(&self) -> u64;
        fn generation(&self) -> &AtomicU64;
        fn admitted(&self) -> &AdmittedUnixSocket;
        fn last_used_at(&self) -> u64;
        fn is_closed(&self) -> bool;
    }

    impl PooledEntry for IdleH1 {
        fn id(&self) -> u64 {
            self.id
        }
        fn generation(&self) -> &AtomicU64 {
            &self.generation
        }
        fn admitted(&self) -> &AdmittedUnixSocket {
            &self.admitted
        }
        fn last_used_at(&self) -> u64 {
            self.last_used_at.load(Ordering::Relaxed)
        }
        fn is_closed(&self) -> bool {
            self.sender.is_closed()
        }
    }

    impl PooledEntry for SharedH2c {
        fn id(&self) -> u64 {
            self.id
        }
        fn generation(&self) -> &AtomicU64 {
            &self.generation
        }
        fn admitted(&self) -> &AdmittedUnixSocket {
            &self.admitted
        }
        fn last_used_at(&self) -> u64 {
            self.last_used_at.load(Ordering::Relaxed)
        }
        fn is_closed(&self) -> bool {
            self.sender.is_closed()
        }
    }

    /// Everything one pool key owns: its carriers, plus the config-liveness
    /// record the retirement pass leaves behind (fence rule 3).
    struct KeySlot<T> {
        /// Set when a publication found this key's identity ABSENT from the
        /// live set. A withdrawn slot holds no carriers and refuses every
        /// insert, so a request still routed by a superseded request epoch
        /// cannot establish a reusable carrier under an identity the published
        /// config no longer declares. Cleared by a publication that declares
        /// the identity again — which leaves the slot EMPTY, so the re-added
        /// incarnation starts from a freshly admitted dial.
        withdrawn: bool,
        entries: Vec<T>,
    }

    impl<T> Default for KeySlot<T> {
        fn default() -> Self {
            Self {
                withdrawn: false,
                entries: Vec::new(),
            }
        }
    }

    /// Retire, tombstone, or re-stamp every slot of one map against the newly
    /// published live set. Returns how many carriers were retired.
    ///
    /// `generation` is the value the publication just bumped to. Advancing a
    /// retained entry's token happens under the shard guard `retain` holds, so
    /// a concurrent checkout either sees the old token (and refuses) or the new
    /// one (and the entry really was observed live by this pass).
    fn retain_live_slots<T: PooledEntry>(
        map: &DashMap<UnixPoolKey, KeySlot<T>>,
        live: &std::collections::HashSet<UnixTargetIdentity>,
        generation: u64,
    ) -> u64 {
        let mut retired = 0u64;
        map.retain(|key, slot| {
            if live.contains(key.target_identity()) {
                slot.withdrawn = false;
                for entry in &slot.entries {
                    entry.generation().store(generation, Ordering::Release);
                }
            } else {
                retired = retired.saturating_add(slot.entries.len() as u64);
                slot.entries.clear();
                slot.withdrawn = true;
            }
            true
        });
        retired
    }

    /// Amortized sweep of one map: drop closed, expired, and
    /// identity-changed carriers, then reclaim slots that can no longer be
    /// reached. Returns how many carriers were evicted.
    ///
    /// A slot is kept when it still holds a carrier, and a WITHDRAWN slot is
    /// kept for as long as a check-in could still reach it (see
    /// [`tombstone_still_reachable`]) — that mark is a security decision, not a
    /// cache entry, so it is not dropped merely because the slot is empty.
    fn prune_slots<T: PooledEntry>(
        map: &DashMap<UnixPoolKey, KeySlot<T>>,
        idle_timeout: u64,
        now: u64,
    ) -> u64 {
        let mut evicted = 0u64;
        map.retain(|key, slot| {
            let before = slot.entries.len();
            slot.entries.retain(|entry| {
                !entry.is_closed()
                    && !entry_idle_expired(entry.last_used_at(), idle_timeout, now)
                    && entry.admitted().still_names_checked_object().unwrap_or(false)
            });
            evicted = evicted.saturating_add(before.saturating_sub(slot.entries.len()) as u64);
            if !slot.entries.is_empty() {
                return true;
            }
            slot.withdrawn && tombstone_still_reachable(key)
        });
        evicted
    }

    /// Remove EXACTLY entry `entry_id` under `key`, if it is still there.
    ///
    /// Used only by the losing side of the check-in fence, so it may find
    /// nothing (the retirement pass already emptied the slot). Matching on the
    /// process-unique id is what keeps a losing cleanup from deleting a NEWER
    /// sibling carrier pooled under the same key.
    fn withdraw_slot_entry<T: PooledEntry>(
        map: &DashMap<UnixPoolKey, KeySlot<T>>,
        key: &UnixPoolKey,
        entry_id: u64,
    ) -> bool {
        let Some(mut slot) = map.get_mut(key) else {
            return false;
        };
        let before = slot.entries.len();
        slot.entries.retain(|entry| entry.id() != entry_id);
        slot.entries.len() != before
    }

    /// Whether a withdrawn (tombstoned) slot can still be reached by any future
    /// check-in, and therefore has to be kept.
    ///
    /// A pool key pins `(dev, ino)`, and a check-in re-verifies exactly that
    /// through `still_names_checked_object` before inserting. Once the path no
    /// longer names the admitted object, no lease can ever insert under this
    /// key again, so the tombstone is dead weight and the periodic sweep drops
    /// it. This is what bounds tombstone growth against socket churn.
    fn tombstone_still_reachable(key: &UnixPoolKey) -> bool {
        use std::os::unix::fs::MetadataExt;

        std::fs::metadata(key.path())
            .is_ok_and(|meta| meta.dev() == key.dev && meta.ino() == key.ino)
    }

    /// Bounded, lock-free-on-hit Unix backend connection manager.
    pub struct UnixBackendConnectionPool {
        pool_config: PoolConfig,
        /// Idle HTTP/1.1 senders per identity. A checked-out sender is NOT in
        /// this map, which is what makes the H1 lease exclusive.
        h1_idle: DashMap<UnixPoolKey, KeySlot<IdleH1>>,
        /// Shared multiplexable h2c carriers per identity.
        h2c_carriers: DashMap<UnixPoolKey, KeySlot<SharedH2c>>,
        /// Coalesces concurrent h2c misses for one identity.
        h2c_creation_locks: DashMap<UnixPoolKey, Arc<Mutex<()>>>,
        /// Last admitted `(dev, ino, owner_uid)` observed for a canonical path.
        ///
        /// This is the O(1) replacement detector: a checkout re-admits the path
        /// and compares against this entry, so a socket swap is caught even
        /// though the swap also changes the pool KEY (which would otherwise
        /// simply miss and leave the old connections pooled and live).
        path_identities: DashMap<PathBuf, (u64, u64, u32)>,
        /// Latched by [`UnixBackendConnectionPool::shutdown_drain`]. Once set,
        /// no check-in may repopulate the pool, so the drain is terminal even
        /// against a response body that reaches EOF while shutdown is running.
        ///
        /// The latch alone is a single read, so it does not by itself order a
        /// check-in that observed it unset against the drain that follows;
        /// `shutdown_drain` also bumps `publication_generation`, and the
        /// two-step check-in fence is what makes the drain terminal against
        /// that interleaving.
        shutting_down: AtomicBool,
        /// Monotonic publication generation. Bumped by EVERY retirement
        /// (`retain_live_targets`, `force_drain_all`, `shutdown_drain`) BEFORE
        /// the retirement pass runs. A lease records the value current when it
        /// was checked out; the check-in fence compares it twice, around the
        /// insert. See the module-level "withdrawal fence" section.
        publication_generation: AtomicU64,
        /// Exact config-declared identities from the newest reconciled request
        /// epoch. `None` exists only before the first publication, while the
        /// serving state is still being constructed. Check-in reads this
        /// lock-free and compares against the identity already owned by its key.
        live_targets: ArcSwapOption<std::collections::HashSet<UnixTargetIdentity>>,
        /// Highest request-epoch config generation reconciled into this pool.
        ///
        /// Config swaps are serialized, but their post-swap maintenance can
        /// overlap. Keep the comparison and full retirement pass under this
        /// off-hot-path lock so an older publisher that resumes late cannot
        /// overwrite the live-set verdict of a newer published epoch.
        last_config_reconcile_generation: std::sync::Mutex<u64>,
        /// Allocator for [`IdleH1::id`] / [`SharedH2c::id`].
        next_entry_id: AtomicU64,
        last_prune_unix_secs: AtomicU64,
        hits: AtomicU64,
        misses: AtomicU64,
        physical_connects: AtomicU64,
        identity_retirements: AtomicU64,
        setup_failures: AtomicU64,
        withdrawal_fenced_checkins: AtomicU64,
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
        /// Carriers the withdrawal fence refused to (re)pool because their
        /// lease was bound to an older publication generation — counted both
        /// for a refusal before the insert and for an entry withdrawn after it.
        pub withdrawal_fenced_checkins: u64,
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
                shutting_down: AtomicBool::new(false),
                publication_generation: AtomicU64::new(0),
                live_targets: ArcSwapOption::empty(),
                last_config_reconcile_generation: std::sync::Mutex::new(0),
                next_entry_id: AtomicU64::new(0),
                last_prune_unix_secs: AtomicU64::new(0),
                hits: AtomicU64::new(0),
                misses: AtomicU64::new(0),
                physical_connects: AtomicU64::new(0),
                identity_retirements: AtomicU64::new(0),
                setup_failures: AtomicU64::new(0),
                withdrawal_fenced_checkins: AtomicU64::new(0),
            }
        }

        pub fn stats(&self) -> UnixPoolStats {
            let fenced = self.withdrawal_fenced_checkins.load(Ordering::Relaxed);
            UnixPoolStats {
                hits: self.hits.load(Ordering::Relaxed),
                misses: self.misses.load(Ordering::Relaxed),
                physical_connects: self.physical_connects.load(Ordering::Relaxed),
                identity_retirements: self.identity_retirements.load(Ordering::Relaxed),
                setup_failures: self.setup_failures.load(Ordering::Relaxed),
                idle_h1_connections: self
                    .h1_idle
                    .iter()
                    .map(|entry| entry.value().entries.len() as u64)
                    .sum(),
                active_h2c_connections: self
                    .h2c_carriers
                    .iter()
                    .map(|entry| entry.value().entries.len() as u64)
                    .sum(),
                withdrawal_fenced_checkins: fenced,
            }
        }

        /// The current publication generation. Exposed for diagnostics and for
        /// the external fence regression tests.
        #[inline]
        #[allow(dead_code)] // Bin target omits lib::_test_support; external tests read it there.
        pub fn publication_generation(&self) -> u64 {
            self.publication_generation.load(Ordering::Acquire)
        }

        /// Invalidate every OUTSTANDING lease and every pooled entry token by
        /// advancing the publication generation. Called BEFORE each retirement
        /// pass, never on the request path. Returns the new generation, which
        /// is the value the pass re-stamps retained live entries with.
        #[inline]
        fn advance_publication_generation(&self) -> u64 {
            self.publication_generation
                .fetch_add(1, Ordering::AcqRel)
                .wrapping_add(1)
        }

        #[inline]
        fn record_withdrawal_fenced_checkin(&self) {
            self.withdrawal_fenced_checkins
                .fetch_add(1, Ordering::Relaxed);
        }

        /// Whether the newest published request epoch still declares `key`.
        ///
        /// Before the first publication the pool is not reachable by serving
        /// traffic, and focused pool tests intentionally exercise standalone
        /// checkout/check-in, so an absent snapshot is treated as live. Every
        /// production publication installs `Some`, including an empty set.
        #[inline]
        fn target_is_live(&self, key: &UnixPoolKey) -> bool {
            let snapshot = self.live_targets.load();
            match snapshot.as_ref() {
                Some(live) => live.contains(key.target_identity()),
                None => true,
            }
        }

        /// Attribute `count` carriers the fence refused to reuse or retain.
        /// Fixed cardinality: one counter and one pool-kind eviction metric,
        /// never a per-target label.
        #[inline]
        fn record_fenced_carriers(&self, count: u64) {
            if count == 0 {
                return;
            }
            self.withdrawal_fenced_checkins
                .fetch_add(count, Ordering::Relaxed);
            crate::runtime_metrics::global_ref()
                .record_pool_evictions(PoolKind::UnixBackend, count);
        }

        /// Drop every pooled connection, leaving the pool usable.
        ///
        /// A dropped sender ends its driver task once the connection closes, so
        /// this is a complete retirement of the idle set without a task
        /// registry.
        ///
        /// In-flight exchanges are NOT in these maps — an HTTP/1.1 lease is
        /// checked out precisely so that it is not — so clearing the maps
        /// cannot reach them. The generation bump is what does: it is performed
        /// FIRST, so every lease outstanding right now is already bound to a
        /// superseded generation and its check-in is fenced out, whether it
        /// lands before or after the clear.
        ///
        /// This also drops the withdrawal tombstones, which is why the only
        /// production caller is `shutdown_drain`: it latches the pool closed in
        /// the same breath, so nothing can be pooled afterwards at all. A
        /// config publication must use `retain_live_targets`, which preserves
        /// them.
        pub fn force_drain_all(&self) {
            self.advance_publication_generation();
            self.h1_idle.clear();
            self.h2c_carriers.clear();
            self.h2c_creation_locks.clear();
            self.path_identities.clear();
        }

        /// Graceful-shutdown drain: retire everything AND latch the pool closed.
        ///
        /// Called from the bounded shutdown drain of every serving mode, after
        /// accept loops have stopped and in-flight requests have been given
        /// their `FERRUM_SHUTDOWN_DRAIN_SECONDS` budget. The latch is what makes
        /// the drain terminal: a streaming response that reaches EOF during the
        /// final moments of the drain would otherwise check its carrier back
        /// into a pool nobody will ever drain again. `force_drain_all`'s
        /// generation bump closes the interleaving the latch alone cannot — a
        /// check-in that read the latch unset a moment before it was set.
        pub fn shutdown_drain(&self) {
            self.shutting_down.store(true, Ordering::Release);
            self.force_drain_all();
        }

        #[inline]
        fn is_shutting_down(&self) -> bool {
            self.shutting_down.load(Ordering::Acquire)
        }

        /// Retire every pooled carrier whose config-declared identity is not in
        /// `live`.
        ///
        /// Called from EVERY successful publication on both of `ProxyState`'s
        /// swap paths (`update_config`'s full and incremental branches, and
        /// `apply_incremental`), against the config that publication actually
        /// made current. `live` is built from that config, so a withdrawn
        /// target, a deleted proxy or upstream, a re-bound namespace/upstream,
        /// a changed `mesh.unix_socket` path, and an `http` ⇄ `http2` protocol
        /// flip all fall out of the set and are retired here — before the next
        /// request can be handed a carrier that belongs to configuration that
        /// no longer exists.
        ///
        /// Exact tuple equality on [`UnixTargetIdentity`]; never a substring or
        /// prefix test. One pass over the idle maps per publication, not per
        /// request.
        ///
        /// The idle maps are only PART of the retirement. A checked-out
        /// HTTP/1.1 lease is deliberately absent from `h1_idle`, so this pass
        /// cannot see it and a comment claiming such an exchange "fails its own
        /// check-in revalidation" would be false — nothing about a still-open
        /// socket that still names the same inode expresses a config
        /// withdrawal. The generation bump below is what reaches it, and it
        /// happens BEFORE the pass so that a check-in racing this call either
        /// has its entry removed by the pass or observes the new generation on
        /// its post-insert re-read and withdraws exactly its own entry.
        ///
        /// What the pass does per key is therefore three-way, not two-way:
        ///
        /// * identity still live → keep the slot and ADVANCE each retained
        ///   entry's token to the new generation under the shard guard. These
        ///   are continuously-live idle carriers, observed by this very pass,
        ///   and they stay reusable — an unrelated publication must not empty
        ///   the pool.
        /// * identity withdrawn → drop the carriers and mark the slot
        ///   withdrawn. The mark survives, because a request routed by a
        ///   superseded epoch can still dial this target afterwards and would
        ///   otherwise pool a reusable carrier under an identity the published
        ///   config does not declare.
        /// * either way the slot itself is retained here; the periodic sweep
        ///   reclaims empty live slots and tombstones whose socket object no
        ///   longer exists.
        pub fn retain_live_targets_for_publication(
            &self,
            config_generation: u64,
            live: &std::collections::HashSet<UnixTargetIdentity>,
        ) {
            let mut last_generation = self
                .last_config_reconcile_generation
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if config_generation <= *last_generation {
                return;
            }
            self.retain_live_targets_inner(live);
            *last_generation = config_generation;
        }

        /// Unordered retirement entry point retained for focused pool tests and
        /// explicit drains that do not correspond to a request-epoch publish.
        pub fn retain_live_targets(&self, live: &std::collections::HashSet<UnixTargetIdentity>) {
            self.retain_live_targets_inner(live);
        }

        fn retain_live_targets_inner(
            &self,
            live: &std::collections::HashSet<UnixTargetIdentity>,
        ) {
            let generation = self.advance_publication_generation();
            // Install the liveness verdict before walking existing slots. A
            // stale-epoch dial that starts after the bump is therefore refused
            // even if no slot existed for the retirement pass to tombstone.
            // If a check-in races the tiny bump/store window, the slot walk
            // that follows observes and removes its insertion.
            self.live_targets.store(Some(Arc::new(live.clone())));
            let retired = retain_live_slots(&self.h1_idle, live, generation)
                .saturating_add(retain_live_slots(&self.h2c_carriers, live, generation));
            self.h2c_creation_locks
                .retain(|key, _| live.contains(key.target_identity()));
            // `path_identities` is the replacement memo, not a connection
            // holder. Keep it only for canonical paths that still have a pooled
            // carrier to protect. Forgetting a path with nothing pooled is
            // harmless — the next checkout re-admits from scratch and records a
            // fresh first observation, and there is no stale carrier left for a
            // swap detection to retire.
            let mut retained_paths: std::collections::HashSet<PathBuf> =
                std::collections::HashSet::new();
            for entry in self.h1_idle.iter() {
                if !entry.value().entries.is_empty() {
                    retained_paths.insert(entry.key().path().to_path_buf());
                }
            }
            for entry in self.h2c_carriers.iter() {
                if !entry.value().entries.is_empty() {
                    retained_paths.insert(entry.key().path().to_path_buf());
                }
            }
            self.path_identities
                .retain(|path, _| retained_paths.contains(path));
            if retired > 0 {
                self.identity_retirements
                    .fetch_add(retired, Ordering::Relaxed);
                crate::runtime_metrics::global_ref()
                    .record_pool_evictions(PoolKind::UnixBackend, retired);
            }
        }

        /// Retire every pooled connection admitted against `path`, across
        /// protocols and proxies.
        ///
        /// Exact canonical-path equality — never a substring or prefix test.
        /// Called when a live re-admission proves the filesystem object at that
        /// path was replaced, BEFORE any further request byte is written to a
        /// connection that may now be talking to a different peer.
        ///
        /// Unlike a config withdrawal this needs no generation bump: an
        /// outstanding lease admitted against the replaced object fails its own
        /// `still_names_checked_object` re-check at check-in, which is a real
        /// filesystem observation rather than a claim about config.
        ///
        /// It drops the carriers but PRESERVES a withdrawal tombstone: this is
        /// a statement about the filesystem, not about config, and discarding
        /// the config verdict here would let a stale-epoch check-in re-create a
        /// reusable slot under a withdrawn identity.
        pub fn retire_socket_path(&self, path: &Path) {
            let mut retired = 0u64;
            self.h1_idle.retain(|key, slot| {
                if key.path() == path {
                    retired = retired.saturating_add(slot.entries.len() as u64);
                    slot.entries.clear();
                    slot.withdrawn
                } else {
                    true
                }
            });
            self.h2c_carriers.retain(|key, slot| {
                if key.path() == path {
                    retired = retired.saturating_add(slot.entries.len() as u64);
                    slot.entries.clear();
                    slot.withdrawn
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
            let evicted = prune_slots(&self.h1_idle, idle_timeout, now)
                .saturating_add(prune_slots(&self.h2c_carriers, idle_timeout, now));
            if evicted > 0 {
                crate::runtime_metrics::global_ref()
                    .record_pool_evictions(PoolKind::UnixBackend, evicted);
            }
            // Only retain locks that are still contended or still name a live
            // carrier, so the lock map cannot grow without bound. A withdrawn
            // key's slot survives as a tombstone, so ask for a CARRIER rather
            // than for the key's presence.
            self.h2c_creation_locks.retain(|key, lock| {
                Arc::strong_count(lock) > 1
                    || self
                        .h2c_carriers
                        .get(key)
                        .is_some_and(|slot| !slot.entries.is_empty())
            });
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
            let live = (admitted.device_id(), admitted.inode(), admitted.owner_uid());
            let path = admitted.resolved_path();
            let previous = self.path_identities.get(path).map(|entry| *entry.value());
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
            // Read the generation BEFORE admission and the dial, so a
            // publication that lands anywhere between here and the check-in
            // fences this lease out of the pool.
            let generation = self.publication_generation.load(Ordering::Acquire);
            let admitted = self.admit_and_reconcile(socket_path, allowed_roots, allowed_uids)?;
            let key = UnixPoolKey::new(proxy, socket_path, &admitted, UnixWireProtocol::Http1);

            if let Some(checkout) = self.take_idle_h1(&key, &admitted, proxy) {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(checkout);
            }
            self.misses.fetch_add(1, Ordering::Relaxed);
            self.dial_h1(key, admitted, connect_timeout_ms, generation)
                .await
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
            let generation = self.publication_generation.load(Ordering::Acquire);
            let admitted = self.admit_and_reconcile(socket_path, allowed_roots, allowed_uids)?;
            let key = UnixPoolKey::new(proxy, socket_path, &admitted, UnixWireProtocol::Http1);
            self.misses.fetch_add(1, Ordering::Relaxed);
            self.dial_h1(key, admitted, connect_timeout_ms, generation)
                .await
        }

        async fn dial_h1(
            &self,
            key: UnixPoolKey,
            admitted: AdmittedUnixSocket,
            connect_timeout_ms: u64,
            generation: u64,
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
                generation,
                sender,
            })
        }

        /// Pop a reusable idle HTTP/1.1 carrier, or nothing.
        ///
        /// The publication generation is read HERE, under the shard guard, and
        /// compared against each candidate entry's own token (fence rule 2).
        /// That ordering is what makes the fence non-launderable: a publication
        /// that has already bumped the generation is visible to this read, and
        /// one that has not yet bumped cannot have started its retirement pass,
        /// so an entry whose token equals the value read here was current at
        /// the instant it was handed out. An entry from a superseded generation
        /// is dropped rather than re-stamped with the caller's generation.
        fn take_idle_h1(
            &self,
            key: &UnixPoolKey,
            expected: &AdmittedUnixSocket,
            proxy: &Proxy,
        ) -> Option<UnixH1Checkout> {
            let idle_timeout = self.idle_timeout_seconds(proxy);
            let now = unix_secs();
            let mut fenced = 0u64;
            let mut taken = None;
            {
                let mut slot = self.h1_idle.get_mut(key)?;
                let generation = self.publication_generation.load(Ordering::Acquire);
                while let Some(entry) = slot.entries.pop() {
                    if !Self::identity_intact(&entry.admitted, expected) {
                        // The path no longer names the admitted object. Drop
                        // this guard first, then retire everything for the
                        // path — no request byte has been written on any of
                        // them.
                        drop(slot);
                        let path = expected.resolved_path().to_path_buf();
                        self.retire_socket_path(&path);
                        self.record_fenced_carriers(fenced);
                        return None;
                    }
                    if entry.generation.load(Ordering::Acquire) != generation {
                        // Published under an incarnation this pool has already
                        // superseded — including one still sitting in the
                        // window between a fenced check-in's insert and its own
                        // cleanup. Never hand it out, and never launder it by
                        // adopting the caller's generation.
                        fenced = fenced.saturating_add(1);
                        continue;
                    }
                    // `is_closed()` (not `is_ready()`) is the reuse gate.
                    // hyper's `is_ready()` reports "the dispatcher has already
                    // asked for the next request", which is a scheduling
                    // artifact, not a liveness fact — a perfectly good
                    // connection reads as not-ready until its driver task next
                    // polls. The genuine idle keep-alive race (the peer reaped
                    // the socket after check-in) is caught by the dispatch
                    // path's `try_send_request` replay, which recovers the
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
                    taken = Some(UnixH1Checkout {
                        key: key.clone(),
                        admitted: entry.admitted,
                        reused: true,
                        generation,
                        sender: entry.sender,
                    });
                    break;
                }
            }
            self.record_fenced_carriers(fenced);
            taken
        }

        /// Return an HTTP/1.1 lease to the idle set.
        ///
        /// The dispatch path MUST NOT call this directly for a connection that
        /// carried a request — use [`Self::checkin_h1_when_idle`], which waits
        /// for hyper to report the exchange complete. This entry point is for a
        /// lease whose request was ABANDONED before it was ever sent (an invalid
        /// backend URL, an unparseable method) and for tests.
        ///
        /// A sender that is closed, whose socket identity changed, or whose
        /// lease is bound to a superseded publication generation is dropped
        /// instead of pooled.
        pub fn checkin_h1(&self, checkout: UnixH1Checkout) {
            self.checkin_h1_fenced(checkout, || {}, || {});
        }

        /// The check-in body, with the two seams the fence's regression tests
        /// need. Production passes empty closures, so this monomorphizes to the
        /// same code with no branch and no allocation.
        ///
        /// * `between_fence_reads` runs after the pre-insert generation check
        ///   and before the insert — the window a publication has to win for
        ///   the post-insert half of the fence to be the thing that saves us.
        /// * `after_insert` runs after the insert and after the shard guard is
        ///   released, but before the post-insert cleanup — the window in which
        ///   an old-generation entry is VISIBLE, and in which a concurrent
        ///   checkout must refuse it rather than launder it.
        pub(crate) fn checkin_h1_fenced(
            &self,
            checkout: UnixH1Checkout,
            between_fence_reads: impl FnOnce(),
            after_insert: impl FnOnce(),
        ) {
            let UnixH1Checkout {
                key,
                admitted,
                reused: _,
                generation,
                sender,
            } = checkout;
            if sender.is_closed() || self.is_shutting_down() {
                return;
            }
            // Fence, first read. A publication that already completed retired
            // this lease's incarnation; the carrier must not be pooled even if
            // the socket object is untouched and the connection is healthy.
            if self.publication_generation.load(Ordering::Acquire) != generation {
                drop(sender);
                self.record_withdrawal_fenced_checkin();
                return;
            }
            if !admitted.still_names_checked_object().unwrap_or(false) {
                let path = admitted.resolved_path().to_path_buf();
                drop(sender);
                self.retire_socket_path(&path);
                return;
            }
            if !self.target_is_live(&key) {
                drop(sender);
                self.record_withdrawal_fenced_checkin();
                return;
            }
            between_fence_reads();
            let entry_id = self.next_entry_id.fetch_add(1, Ordering::Relaxed);
            let max_idle = self.max_idle_per_key();
            let mut refused_by_tombstone = false;
            {
                let mut slot = self.h1_idle.entry(key.clone()).or_default();
                if slot.withdrawn {
                    // Fence rule 3. The last publication did not declare this
                    // identity, and this lease can only exist because the
                    // request was routed by a superseded request epoch. The
                    // carrier is fine for the exchange it already served; it
                    // must not become reusable.
                    refused_by_tombstone = true;
                } else {
                    if slot.entries.len() >= max_idle {
                        // Bound the idle set: drop the OLDEST idle connection,
                        // which is the one most likely to have been reaped by
                        // the peer.
                        slot.entries.remove(0);
                        crate::runtime_metrics::global_ref()
                            .record_pool_eviction(PoolKind::UnixBackend);
                    }
                    slot.entries.push(IdleH1 {
                        id: entry_id,
                        generation: AtomicU64::new(generation),
                        sender,
                        admitted,
                        last_used_at: AtomicU64::new(unix_secs()),
                    });
                }
                // The shard guard is released HERE, before the second fence
                // read: the release/acquire pair on that shard is what orders a
                // concurrent publication's generation bump ahead of the read
                // when the retirement pass ran before this insert.
            }
            if refused_by_tombstone {
                self.record_withdrawal_fenced_checkin();
                return;
            }
            after_insert();
            // Fence, second read. Either the publication's retirement pass saw
            // this entry and removed it, or it did not — in which case it
            // released the shard before we took it and the bump is visible now.
            // In the gap between the insert and this cleanup the entry is
            // visible but still carries the OLD token, so a concurrent checkout
            // refuses it (fence rule 2) rather than laundering it.
            if self.publication_generation.load(Ordering::Acquire) != generation
                && withdraw_slot_entry(&self.h1_idle, &key, entry_id)
            {
                self.record_fenced_carriers(1);
            }
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
            if checkout.sender.is_closed() || pool.is_shutting_down() {
                return;
            }
            // Fence early so a lease whose incarnation is already retired is
            // dropped here rather than parked in a waiter task. `checkin_h1`
            // re-evaluates the fence in full; this is only a fast path.
            if pool.publication_generation.load(Ordering::Acquire) != checkout.generation {
                pool.record_withdrawal_fenced_checkin();
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

        /// Wrap an exclusive HTTP/1.1 lease as a
        /// [`crate::proxy::body::PooledBackendLease`] for a STREAMING response.
        ///
        /// This is the EOF-anchored handoff. The returned guard owns the lease
        /// for as long as the client-visible `ProxyBody` lives; that body
        /// releases it from exactly one place, its `Poll::Ready(None)` arm, and
        /// drops it on every other terminal. Because the guard owns the only
        /// `UnixH1Checkout`, the connection cannot be handed to another request
        /// while the body is still streaming — the sender is not in `h1_idle`
        /// and there is no second reference to it.
        ///
        /// The guard is not "detached": it has no task of its own and no pool
        /// registry entry. Its lifetime is exactly the response body's.
        pub fn streaming_lease(
            pool: &Arc<Self>,
            checkout: UnixH1Checkout,
        ) -> Box<dyn crate::proxy::body::PooledBackendLease> {
            Box::new(UnixH1StreamingLease {
                pool: Arc::clone(pool),
                checkout: Some(checkout),
            })
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
            self.checkout_h2c_fenced(
                proxy,
                socket_path,
                connect_timeout_ms,
                allowed_roots,
                allowed_uids,
                (|| {}, || {}),
            )
            .await
        }

        /// The h2c checkout body, with the same two seams
        /// [`Self::checkin_h1_fenced`] exposes, as one `(before, after)` pair:
        /// `before` runs after the dial and before the carrier enters the
        /// shared map, and `after` runs once it is in the map and before the
        /// fence's cleanup — the window in which a superseded carrier is
        /// visible. Production passes empty closures.
        pub(crate) async fn checkout_h2c_fenced(
            &self,
            proxy: &Proxy,
            socket_path: &str,
            connect_timeout_ms: u64,
            allowed_roots: &[String],
            allowed_uids: &[u32],
            publish_seams: (impl FnOnce(), impl FnOnce()),
        ) -> Result<MeshMtlsSender, UnixBackendError> {
            let (before_publish, after_publish) = publish_seams;
            self.maybe_prune_idle();
            // Same fence as the H1 lease: a dial can straddle a publication, so
            // the generation is captured before admission and re-checked after
            // the carrier is published into the shared map.
            let generation = self.publication_generation.load(Ordering::Acquire);
            let admitted = self.admit_and_reconcile(socket_path, allowed_roots, allowed_uids)?;
            let key = UnixPoolKey::new(proxy, socket_path, &admitted, UnixWireProtocol::H2c);

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
            let entry_id = self.next_entry_id.fetch_add(1, Ordering::Relaxed);
            let mut refused_by_tombstone = false;
            before_publish();
            if !self.target_is_live(&key) {
                self.record_withdrawal_fenced_checkin();
                return Ok(sender);
            }
            {
                let mut slot = self.h2c_carriers.entry(key.clone()).or_default();
                if slot.withdrawn {
                    // Fence rule 3, exactly as on the H1 check-in: this dial
                    // can only have come from a superseded request epoch, so
                    // its carrier serves this RPC and nothing after it.
                    refused_by_tombstone = true;
                } else {
                    while slot.entries.len() >= max_idle {
                        slot.entries.remove(0);
                        crate::runtime_metrics::global_ref()
                            .record_pool_eviction(PoolKind::UnixBackend);
                    }
                    slot.entries.push(SharedH2c {
                        id: entry_id,
                        generation: AtomicU64::new(generation),
                        sender: sender.clone(),
                        admitted,
                        last_used_at: AtomicU64::new(unix_secs()),
                    });
                }
                // Shard guard released before the second fence read, as in
                // `checkin_h1_fenced`.
            }
            // The caller keeps this sender for the request it is already
            // authorized to make; the fence only decides whether the carrier
            // stays REUSABLE. A publication that landed during the dial retires
            // it immediately.
            if refused_by_tombstone {
                self.record_withdrawal_fenced_checkin();
                return Ok(sender);
            }
            after_publish();
            if self.publication_generation.load(Ordering::Acquire) != generation
                && withdraw_slot_entry(&self.h2c_carriers, &key, entry_id)
            {
                self.record_fenced_carriers(1);
            }
            Ok(sender)
        }

        /// Whether the PRODUCTION shared-h2c selector would hand a pooled
        /// carrier to a request for this identity right now.
        ///
        /// A read-only observation of `take_shared_h2c`, the exact hot-path
        /// predicate, so a test can inspect the after-publish window without
        /// re-entering `checkout_h2c` (which would block on the creation lock
        /// its caller still holds). It re-admits the path exactly as a checkout
        /// does and never dials.
        #[allow(dead_code)] // Bin target omits lib::_test_support; external tests reach it there.
        pub(crate) fn shared_h2c_selector_yields_carrier(
            &self,
            proxy: &Proxy,
            socket_path: &str,
            allowed_roots: &[String],
            allowed_uids: &[u32],
        ) -> bool {
            let Ok(admitted) = crate::util::unix_socket::admit_socket_for_connect(
                socket_path,
                allowed_roots,
                allowed_uids,
            ) else {
                return false;
            };
            let key = UnixPoolKey::new(proxy, socket_path, &admitted, UnixWireProtocol::H2c);
            self.take_shared_h2c(&key, &admitted, proxy).is_some()
        }

        /// Pick a live shared h2c carrier for `key`, or nothing.
        ///
        /// Carries the same entry-token rule as [`Self::take_idle_h1`]: the
        /// generation is read under the map guard and a carrier published under
        /// a superseded generation is never multiplexed onto, even in the
        /// window between a fenced publish and its own cleanup.
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
                let slot = self.h2c_carriers.get(key)?;
                let generation = self.publication_generation.load(Ordering::Acquire);
                for entry in slot.entries.iter() {
                    if !Self::identity_intact(&entry.admitted, expected) {
                        retire = true;
                        break;
                    }
                    if entry.generation.load(Ordering::Acquire) != generation
                        || entry.sender.is_closed()
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

    /// Wire protocol a Unix ingress target declares. Mirrors the Unix build's
    /// type so `ProxyState`'s reload reconciliation compiles everywhere.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum UnixWireProtocol {
        Http1,
        H2c,
    }

    /// Config-declared identity of a Unix ingress target. Never populated on a
    /// platform without Unix-domain sockets, but the type must exist so the
    /// shared reload path is not itself `cfg`-gated.
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub struct UnixTargetIdentity {
        pub namespace: String,
        pub proxy_id: String,
        pub upstream_id: Option<String>,
        pub configured_path: String,
        pub protocol: UnixWireProtocol,
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct UnixPoolStats {
        pub hits: u64,
        pub misses: u64,
        pub physical_connects: u64,
        pub identity_retirements: u64,
        pub setup_failures: u64,
        pub idle_h1_connections: u64,
        pub active_h2c_connections: u64,
        pub withdrawal_fenced_checkins: u64,
    }

    pub struct UnixBackendConnectionPool;

    impl UnixBackendConnectionPool {
        pub fn new(_pool_config: PoolConfig, _shard_amount: usize) -> Self {
            Self
        }

        /// Mirrors the Unix build's accessor. Nothing is ever pooled here, so
        /// the generation never advances.
        #[allow(dead_code)] // Parity with the Unix build; no Unix sockets to pool here.
        pub fn publication_generation(&self) -> u64 {
            0
        }

        pub fn force_drain_all(&self) {}

        pub fn shutdown_drain(&self) {}

        pub fn retain_live_targets_for_publication(
            &self,
            _config_generation: u64,
            _live: &std::collections::HashSet<UnixTargetIdentity>,
        ) {
        }

        pub fn retain_live_targets(&self, _live: &std::collections::HashSet<UnixTargetIdentity>) {}

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

        pub fn checkin_h1_when_idle(_pool: &std::sync::Arc<Self>, _checkout: UnixH1Checkout) {}

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
