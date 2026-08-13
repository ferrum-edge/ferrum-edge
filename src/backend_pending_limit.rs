//! Per-logical-destination backend HTTP/1.1 *in-flight-request* limiting for the
//! upstream-dispatch path.
//!
//! Enforces the Istio DestinationRule `connectionPool.http.http1MaxPendingRequests`
//! cap (materialized onto
//! `Upstream.port_overrides[port].http1_max_pending_requests`, see
//! [`crate::config::types::UpstreamPortOverride`]).
//!
//! # Honest reinterpretation — max concurrent in-flight H1 requests
//!
//! Envoy's `http1MaxPendingRequests` bounds the depth of the *pending queue*:
//! requests admitted but not yet assigned a connection slot. Ferrum dispatches
//! HTTP/1.1 over reqwest, whose `send().await` resolves when **response
//! headers** arrive — reqwest exposes **no connection-acquisition hook**, so a
//! slot held acquire-before-send / release-after-send unavoidably spans
//! connection-wait + request-upload + backend-TTFB, not the pending phase alone.
//! True pending-queue depth is therefore not implementable over reqwest.
//!
//! Mirroring how this repo honestly reinterprets DR `maxRetries` as a
//! per-request cap (see `docs/mesh.md`), this limiter reframes the knob as a
//! **max concurrent in-flight HTTP/1.1 requests per logical destination /
//! policy scope** cap, measured from dispatch to response-headers. When a
//! destination is already at its cap, the new request is shed immediately with
//! a 503 ("upstream overflow" in Envoy terms) instead of being queued
//! unboundedly. This bounds H1 concurrency to a destination and approximates
//! Envoy's overflow protection.
//!
//! # Logical admission scope (issue #3778)
//!
//! Lanes are keyed by a precomputed structured
//! [`BackendPendingScopeBase`] plus the effective DestinationRule policy port:
//!
//! ```text
//! (namespace/tenant, stable logical upstream/Service identity,
//!  optional Kubernetes Service UID, policy port, selected subset)
//! ```
//!
//! The stable logical identity is **always** present. Ordinary upstreams use
//! their resource id. Materialized mesh HTTP egress upstreams use their
//! cold-stamped Service FQDN so the Service's VIP/host route and every direct
//! workload-IP route share one lane instead of multiplying the cap by endpoint
//! count. When a Kubernetes Service `metadata.uid` is stamped, it is added
//! alongside that identity so delete/recreate opens a fresh lane while an
//! injected/reused UID cannot collapse otherwise distinct logical
//! destinations. Ordinary Service *spec* updates (including DestinationRule cap
//! changes) retain one shared counter — `metadata.generation` is intentionally
//! **not** part of the lane. Native / file / database config omits the UID and
//! uses `(namespace, upstream_id)` alone. Direct-backend proxies without an
//! upstream use `(namespace, proxy id)`.
//!
//! The selected endpoint host/IP is **not** part of the key: load-balanced
//! endpoint selection, DNS refresh, pod rotation, and retries to sibling
//! targets share one logical lane. Distinct Services, tenants, policy ports,
//! and subsets remain isolated. Multiple proxies intentionally targeting the
//! same logical Service/port/subset share that lane.
//!
//! Cap updates are deterministic: each acquire checks against the requesting
//! epoch's effective cap while reading/writing the shared count. Existing
//! guards release exactly once onto that same counter. When the Service UID
//! itself changes (delete/recreate), a new lane is opened and old guards drain
//! the prior counter under the existing race-safe zero-count retirement.
//!
//! This scope is intentionally reusable by later cross-protocol active-request
//! work (#3775 / `http2MaxRequests`) but is **not** that breaker: this module
//! remains the H1 reqwest in-flight approximation only.
//!
//! # Scope — HTTP/1.1 reqwest dispatch only
//!
//! The field is named `http1MaxPendingRequests`, so this limiter is consumed
//! **only on the reqwest/HTTP-1.1 backend-dispatch path** in
//! `proxy_to_backend` (`src/proxy/mod.rs`), the path Ferrum uses for plain
//! HTTP/1.1 upstreams (and the H1 fallback when a backend does not negotiate
//! HTTP/2 — including a backend the capability registry has classified
//! H2/TLS-unsupported), plus the H3→plain reqwest bridge that enforces the
//! same gate. It is acquired immediately before the request is dispatched onto
//! the shared reqwest client and released by its RAII guard the moment
//! dispatch returns (response headers arrived, or the dial failed). Under the
//! in-flight reinterpretation that release point is correct by definition:
//! the slot counts a request as in-flight from dispatch to response-headers,
//! not for the lifetime of the response stream. Because every H1-determined
//! dispatch is in-flight, there is **no body-shape exclusion** — bodyless
//! GET/HEAD and streamed-upload requests are capped alike.
//!
//! The multiplexed transports — direct HTTP/2, gRPC, HTTP/3, HBONE, and
//! mesh-mTLS — do **not** consume this limiter. They are not HTTP/1.1, and
//! their request concurrency is governed by HTTP/2 stream limits
//! (`connectionPool.http.http2MaxRequests` → `h2_max_concurrent_streams`), not
//! a connection-pending queue. A captured DestinationRule that sets both knobs
//! gets `http2MaxRequests` on its H2/gRPC dispatch and `http1MaxPendingRequests`
//! on its H1 dispatch, which is the correct per-protocol split.
//!
//! # Hot-path discipline (mirrors [`crate::backend_conn_limit`])
//!
//! - When no cap is configured for a destination port (`cap == None`),
//!   [`BackendPendingLimiter::try_acquire`] returns `Ok(None)` after a single
//!   `Option` check and never touches the `DashMap`.
//! - The logical identity prefix is **precomputed / interned** onto
//!   [`BackendPendingScopeBase`] (`Arc<str>`) during config publication
//!   (`GatewayConfig::resolve_pending_limit_scopes`). Repeat acquisitions
//!   append only the policy port into a reused thread-local buffer — no
//!   per-request `format!()`, no namespace/Service string reconstruction, and
//!   no avoidable lock beyond the DashMap shard already required for the
//!   atomic reserve.
//! - On the capped hit path the destination counter is looked up with a
//!   **borrowed `&str`** key via `String: Borrow<str>`, so a repeat request to
//!   a known scope allocates nothing. Only the cold first request to a new
//!   scope allocates the owned key for the `entry` insert.
//! - The counter map is a sharded [`dashmap::DashMap`] sized via
//!   [`crate::util::sharding::pool_shard_amount`]; counters are
//!   [`crossbeam_utils::CachePadded`] so a hot destination's count does not
//!   false-share with adjacent map slots.
//! - Acquisition checks the cap and reserves the slot **together under the
//!   DashMap shard lock** (`get_mut`/`entry`), so two concurrent requests can
//!   never both squeak past `cap - 1`, and — crucially — the reservation is
//!   atomic with the drop-time eviction below. A lock-free CAS on a cloned `Arc`
//!   would instead race eviction: an acquirer holding a stale clone could
//!   resurrect a counter the last drop just removed (orphaning it, splitting the
//!   count, and admitting past the cap) or leave a stranded zero-count entry.
//!   The shard lock is per-destination-shard and held only for a load + compare
//!   + increment, and the limiter engages only for ports with a configured cap.
//! - [`BackendPendingGuard`]'s `Drop` decrements exactly once on every dispatch
//!   exit (success, early return, error, task cancellation), so an in-flight
//!   slot can never leak and wedge a destination. The decrement runs inside a
//!   `remove_if` predicate under the **same shard lock** as acquisition, and the
//!   key is evicted in that same locked section when the count returns to zero.
//!   That keeps retired scopes from accumulating unbounded zero-count keys over
//!   the gateway lifetime, with no acquire/evict race.
//!
//! Observability stays fixed-cardinality: rejection metrics never emit raw
//! Service, namespace, upstream, subset, or host labels. Structured rejection
//! logs carry a bounded opaque FNV-1a scope digest plus the effective
//! DestinationRule policy port (distinct from the dial/backend port under
//! `targetPort` remapping) so operators can correlate the lane without an
//! admin diagnostic endpoint exposing raw identifiers.
//!
//! The implementation is deliberately a counting gate (a `CachePadded` atomic
//! mutated under the shard lock), not a `tokio::sync::Semaphore`: a semaphore
//! would block-and-queue an over-cap acquirer, but the desired Envoy "overflow"
//! semantics are to **reject immediately**, and a semaphore's per-destination
//! `Arc<Semaphore>` would need the same `DashMap` plumbing anyway. The counting
//! gate gives an alloc-free (on the hit path) try-acquire/reject on the request
//! path, with reservation and eviction serialized by the per-shard lock.

use std::cell::RefCell;
use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crossbeam_utils::CachePadded;
use dashmap::DashMap;

thread_local! {
    /// Reused per-thread buffer for `(scope_base, policy port)` counter-key
    /// lookups on the capped hot path. The scope base is an interned `Arc<str>`
    /// published at config reload; only the policy port is appended here so a
    /// repeat capped request to a known scope allocates nothing.
    static PENDING_KEY_BUF: RefCell<String> = RefCell::new(String::with_capacity(128));
}

/// Precomputed logical admission-scope identity for H1 pending limiting.
///
/// Built once per proxy (and once per upstream for top-level override rebind)
/// during config publication and shared via `Arc` so the request path never
/// reconstructs namespace / upstream / subset strings. The effective
/// DestinationRule policy port is appended at acquire time (multi-port
/// upstreams select it per target).
#[derive(Debug, Clone)]
pub struct BackendPendingScopeBase {
    /// Length-prefixed identity prefix ending with `|` so a port can be
    /// appended without delimiter ambiguity.
    prefix: Arc<str>,
    /// Bounded opaque FNV-1a digest of the logical identity (not the port).
    /// Structured rejection logs only; never a Prometheus label or
    /// authorization input.
    digest: u64,
}

impl BackendPendingScopeBase {
    /// Build a scope base from logical destination components.
    ///
    /// `upstream_id` is always the stable config/upstream (or proxy) identity.
    /// `k8s_service_uid`, when stamped by the Kubernetes translator, is added
    /// alongside that identity so delete/recreate isolates lanes without letting
    /// a reused UID collapse distinct upstreams. `subset == None` is a distinct
    /// lane from every named subset. Kubernetes `metadata.generation` is never
    /// part of this key.
    pub fn new(
        namespace: &str,
        upstream_id: &str,
        k8s_service_uid: Option<&str>,
        subset: Option<&str>,
    ) -> Self {
        let mut buf = String::with_capacity(
            32 + namespace.len()
                + upstream_id.len()
                + k8s_service_uid.map_or(0, str::len)
                + subset.map_or(0, str::len),
        );
        write_length_prefixed(&mut buf, "ns", namespace);
        buf.push('|');
        write_length_prefixed(&mut buf, "id", upstream_id);
        if let Some(uid) = k8s_service_uid.filter(|u| !u.is_empty()) {
            buf.push('|');
            write_length_prefixed(&mut buf, "uid", uid);
        }
        buf.push('|');
        match subset {
            Some(name) => {
                write_length_prefixed(&mut buf, "s", name);
            }
            None => buf.push('n'),
        }
        buf.push('|');
        let digest = fnv1a64(buf.as_bytes());
        Self {
            prefix: Arc::from(buf),
            digest,
        }
    }

    /// Opaque FNV-1a digest of the logical identity (excluding policy port).
    /// Diagnostics / structured rejection logs only — never authorization.
    #[inline]
    pub fn digest(&self) -> u64 {
        self.digest
    }

    /// Borrow the interned identity prefix (test/diagnostics).
    #[inline]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }
}

#[inline]
fn write_length_prefixed(buf: &mut String, tag: &str, value: &str) {
    buf.push_str(tag);
    let _ = write!(buf, "{}:", value.len());
    buf.push_str(value);
}

/// FNV-1a 64-bit: deterministic across Rust versions (unlike `DefaultHasher`).
/// Cold-path / diagnostics only; never used for authorization.
#[inline]
fn fnv1a64(bytes: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001B3;
    let mut h = FNV_OFFSET;
    for byte in bytes {
        h ^= u64::from(*byte);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Append the policy port onto a scope base into `buf`.
#[inline]
fn write_pending_key(buf: &mut String, scope: &BackendPendingScopeBase, port: u16) {
    buf.push_str(scope.prefix.as_ref());
    let _ = write!(buf, "{port}");
}

/// Shared per-logical-destination in-flight-request counter map.
///
/// Keyed by the length-prefixed scope encoding produced from
/// [`BackendPendingScopeBase`] + policy port. Looked up on the hit path by
/// borrowed `&str` via `String: Borrow<str>`, so the capped hot path allocates
/// nothing on a repeat request.
///
/// One instance lives on `ProxyState` and is shared across every reqwest/H1
/// dispatch for the gateway lifetime (including H3→plain bridges), so the cap
/// bounds concurrent in-flight requests per logical destination across all
/// proxies that intentionally share that Service/port/subset lane.
pub struct BackendPendingLimiter {
    inner: Arc<DashMap<String, Arc<BackendPendingCounter>>>,
}

#[derive(Debug)]
struct BackendPendingCounter {
    key: String,
    count: CachePadded<AtomicU64>,
}

impl Default for BackendPendingLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl BackendPendingLimiter {
    /// Construct a limiter with `DashMap` sharding sized for the hot path.
    ///
    /// A `0` shard override means "auto" (`max(64, num_cpus * 16)`), matching
    /// every other hot-path map in the codebase.
    pub fn new() -> Self {
        Self::with_shard_amount(crate::util::sharding::pool_shard_amount(0))
    }

    /// Construct a limiter with an explicit shard amount. Callers that want to
    /// honor the operator-facing `FERRUM_POOL_SHARD_AMOUNT` knob can pass
    /// `pool_shard_amount(env_config.pool_shard_amount)`.
    pub fn with_shard_amount(shards: usize) -> Self {
        Self {
            inner: Arc::new(DashMap::with_shard_amount(shards)),
        }
    }

    /// Try to acquire one in-flight slot for a precomputed logical scope and
    /// DestinationRule policy port.
    ///
    /// * `Ok(None)` — no cap configured. Hot path: a single `Option` check.
    /// * `Ok(Some(guard))` — a slot was reserved; hold until response headers
    ///   (or dial failure) then drop.
    /// * `Err(BackendPendingLimitExceeded)` — the requesting epoch's cap is
    ///   already reached for this logical lane.
    pub fn try_acquire(
        &self,
        scope: &BackendPendingScopeBase,
        port: u16,
        cap: Option<u32>,
    ) -> Result<Option<BackendPendingGuard>, BackendPendingLimitExceeded> {
        let Some(cap) = cap else {
            return Ok(None);
        };
        let cap_u64 = u64::from(cap);
        // A zero cap rejects unconditionally — reject BEFORE touching the map.
        // `try_acquire` never hands out a guard for a zero cap, so the drop-time
        // eviction can never fire for it; creating a counter here would leave a
        // permanent zero-count entry per unique scope (the exact unbounded growth
        // this limiter guards against). `http1MaxPendingRequests: 0` is rejected
        // at translate time, so production never reaches this; it is defensive.
        if cap_u64 == 0 {
            return Err(BackendPendingLimitExceeded { current: 0, cap: 0 });
        }
        let counter = PENDING_KEY_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            write_pending_key(&mut buf, scope, port);
            // Hit path: borrowed `&str` `get_mut` (write-locks only this shard,
            // no key allocation). Check the cap and reserve the slot while the
            // shard lock is held, so the reservation is atomic with a concurrent
            // release's eviction.
            if let Some(existing) = self.inner.get_mut(buf.as_str()) {
                let current = existing.count.load(Ordering::Relaxed);
                if current >= cap_u64 {
                    return Err(BackendPendingLimitExceeded {
                        current,
                        cap: cap_u64,
                    });
                }
                existing.count.fetch_add(1, Ordering::Relaxed);
                return Ok(existing.clone());
            }
            // Cold path: a new scope — allocate the owned key once and take
            // the first slot. `entry` re-resolves under the shard lock in case a
            // concurrent acquirer inserted between the `get_mut` miss and here; a
            // freshly inserted entry has count 0 < cap, so the cap check only ever
            // rejects on a sibling-inserted entry that is already at its cap.
            let entry = self.inner.entry(buf.clone()).or_insert_with(|| {
                Arc::new(BackendPendingCounter {
                    key: buf.clone(),
                    count: CachePadded::new(AtomicU64::new(0)),
                })
            });
            let current = entry.count.load(Ordering::Relaxed);
            if current >= cap_u64 {
                return Err(BackendPendingLimitExceeded {
                    current,
                    cap: cap_u64,
                });
            }
            entry.count.fetch_add(1, Ordering::Relaxed);
            Ok(entry.clone())
        })?;
        Ok(Some(BackendPendingGuard {
            counters: Arc::clone(&self.inner),
            counter,
        }))
    }

    /// Current in-flight count for a logical scope + policy port.
    /// Test/metrics only — the hot path uses `try_acquire` directly.
    // The binary target re-declares library modules, so this public inspection
    // seam is used by external tests but appears dead in that compilation.
    #[allow(dead_code)]
    pub fn current(&self, scope: &BackendPendingScopeBase, port: u16) -> u64 {
        PENDING_KEY_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            write_pending_key(&mut buf, scope, port);
            self.inner
                .get(buf.as_str())
                .map(|c| c.count.load(Ordering::Relaxed))
                .unwrap_or(0)
        })
    }

    #[cfg(test)]
    fn resident_counters(&self) -> usize {
        self.inner.len()
    }
}

/// RAII guard that holds one in-flight slot for a logical destination and
/// releases it on drop. Hold this only for the in-flight window (dispatch until
/// backend `send()` returns / response headers arrive) so the count reflects
/// requests *currently in flight to the destination*, not the full
/// response-stream lifetime.
#[derive(Debug)]
pub struct BackendPendingGuard {
    counters: Arc<DashMap<String, Arc<BackendPendingCounter>>>,
    counter: Arc<BackendPendingCounter>,
}

impl Drop for BackendPendingGuard {
    fn drop(&mut self) {
        // Release the slot and evict the entry if this was the last one, in ONE
        // shard-locked `remove_if`. The predicate runs under the DashMap shard
        // write lock, so the decrement and the at-zero removal are atomic with
        // respect to `try_acquire` (which checks-and-increments under the same
        // lock). That mutual exclusion is what eliminates the lock-free eviction
        // races: an acquirer can never observe/clone this counter "between" the
        // decrement and the removal, so it can neither resurrect an orphan
        // (cap bypass) nor leave a stranded zero-count entry.
        //
        // `fetch_sub` returning 1 means this drop took the count to 0 → remove
        // the now-idle key so retired scopes cannot retain unbounded
        // zero-count entries; any other value means a sibling slot is still held,
        // so the entry stays. `fetch_sub` (not `saturating_sub`) so a
        // double-release/missing-acquire bug underflows loudly instead of being
        // masked. The key is always present here: every guard decrements exactly
        // once and the entry lives for the guard's lifetime (count >= 1).
        self.counters
            .remove_if(self.counter.key.as_str(), |_, current| {
                current.count.fetch_sub(1, Ordering::AcqRel) == 1
            });
    }
}

/// Returned when a destination is already at its `http1MaxPendingRequests` cap.
/// Carries the observed count and the configured cap for diagnostics/logging.
#[derive(Debug, Clone, Copy)]
pub struct BackendPendingLimitExceeded {
    pub current: u64,
    pub cap: u64,
}

impl std::fmt::Display for BackendPendingLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "backend http1MaxPendingRequests reached: {} in flight (cap {})",
            self.current, self.cap
        )
    }
}

impl std::error::Error for BackendPendingLimitExceeded {}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(ns: &str, id: &str, subset: Option<&str>) -> BackendPendingScopeBase {
        BackendPendingScopeBase::new(ns, id, None, subset)
    }

    fn scope_uid(ns: &str, id: &str, uid: &str, subset: Option<&str>) -> BackendPendingScopeBase {
        BackendPendingScopeBase::new(ns, id, Some(uid), subset)
    }

    #[test]
    fn no_cap_skips_counter_entirely() {
        let limiter = BackendPendingLimiter::new();
        let s = scope("default", "backend", None);
        let guard = limiter
            .try_acquire(&s, 8080, None)
            .expect("no-cap acquire never errors");
        assert!(guard.is_none(), "no cap must not hand out a guard");
        assert_eq!(
            limiter.current(&s, 8080),
            0,
            "no-cap path must not touch the counter map"
        );
        assert_eq!(
            limiter.resident_counters(),
            0,
            "no-cap path must not create resident counters"
        );
    }

    #[test]
    fn under_cap_acquires_and_counts() {
        let limiter = BackendPendingLimiter::new();
        let s = scope("default", "backend", None);
        let _g1 = limiter
            .try_acquire(&s, 8080, Some(3))
            .expect("first under cap")
            .expect("guard present");
        let _g2 = limiter
            .try_acquire(&s, 8080, Some(3))
            .expect("second under cap")
            .expect("guard present");
        assert_eq!(limiter.current(&s, 8080), 2);
    }

    #[test]
    fn at_cap_rejects_next_acquire() {
        let limiter = BackendPendingLimiter::new();
        let s = scope("default", "h", None);
        let _g1 = limiter
            .try_acquire(&s, 7777, Some(1))
            .expect("first slot")
            .expect("guard present");
        let err = limiter
            .try_acquire(&s, 7777, Some(1))
            .expect_err("cap hit must error");
        assert_eq!(err.current, 1);
        assert_eq!(err.cap, 1);
    }

    #[test]
    fn cap_of_zero_always_rejects() {
        let limiter = BackendPendingLimiter::new();
        let s = scope("default", "h", None);
        limiter
            .try_acquire(&s, 1, Some(0))
            .expect_err("cap 0 rejects every request");
        assert_eq!(limiter.current(&s, 1), 0);
        assert_eq!(
            limiter.resident_counters(),
            0,
            "a zero cap must reject without creating a resident counter"
        );
    }

    #[test]
    fn drop_frees_slot_for_reuse() {
        let limiter = BackendPendingLimiter::new();
        let s = scope("default", "h", None);
        {
            let _g = limiter
                .try_acquire(&s, 7777, Some(1))
                .expect("first slot")
                .expect("guard present");
            limiter
                .try_acquire(&s, 7777, Some(1))
                .expect_err("cap hit while guard held");
        }
        assert_eq!(
            limiter.current(&s, 7777),
            0,
            "drop must decrement the counter exactly once"
        );
        let _g = limiter
            .try_acquire(&s, 7777, Some(1))
            .expect("slot freed after drop")
            .expect("guard present");
    }

    #[test]
    fn drop_removes_idle_counter_entry() {
        let limiter = BackendPendingLimiter::new();
        let s = scope("default", "ephemeral", None);
        {
            let _g = limiter
                .try_acquire(&s, 80, Some(1))
                .expect("slot acquired")
                .expect("guard present");
            assert_eq!(limiter.resident_counters(), 1);
        }

        assert_eq!(limiter.current(&s, 80), 0);
        assert_eq!(
            limiter.resident_counters(),
            0,
            "idle counters must be evicted so retired scopes cannot grow the map forever"
        );
    }

    #[test]
    fn unique_scopes_do_not_leave_resident_zero_count_entries() {
        let limiter = BackendPendingLimiter::new();

        for i in 0..1_000 {
            let s = scope("default", &format!("svc-{i}"), None);
            let guard = limiter
                .try_acquire(&s, 80, Some(1))
                .expect("slot acquired")
                .expect("guard present");
            drop(guard);
            assert_eq!(limiter.current(&s, 80), 0);
        }

        assert_eq!(
            limiter.resident_counters(),
            0,
            "completed unique scopes must not leave resident limiter keys"
        );
    }

    #[test]
    fn independent_services_sharing_endpoint_identity_stay_isolated() {
        // Two Services selecting the same pods under subset `v1` must not share
        // a lane — the previous host-keyed design collided here.
        let limiter = BackendPendingLimiter::new();
        let public = scope("shop", "checkout-public", Some("v1"));
        let internal = scope("shop", "checkout-internal", Some("v1"));

        let _a = limiter
            .try_acquire(&public, 8080, Some(1))
            .expect("public under cap")
            .expect("guard");
        limiter
            .try_acquire(&public, 8080, Some(1))
            .expect_err("public lane full");

        let _b = limiter
            .try_acquire(&internal, 8080, Some(10))
            .expect("internal must not see public's count")
            .expect("guard");
        assert_eq!(limiter.current(&public, 8080), 1);
        assert_eq!(limiter.current(&internal, 8080), 1);
    }

    #[test]
    fn endpoint_fanout_shares_one_logical_lane() {
        // Policy port is part of the key; selected host is not. Acquiring
        // repeatedly for the same scope/port saturates one lane regardless of
        // which endpoint would have been dialed.
        let limiter = BackendPendingLimiter::new();
        let s = scope("default", "reviews", Some("v1"));
        let _g1 = limiter
            .try_acquire(&s, 9080, Some(1))
            .expect("first")
            .expect("guard");
        limiter
            .try_acquire(&s, 9080, Some(1))
            .expect_err("second endpoint selection must share the same logical lane");
        assert_eq!(limiter.current(&s, 9080), 1);
    }

    #[test]
    fn namespaces_and_ports_and_subsets_are_isolated() {
        let limiter = BackendPendingLimiter::new();
        let a = scope("ns-a", "reviews", Some("v1"));
        let b = scope("ns-b", "reviews", Some("v1"));
        let a_v2 = scope("ns-a", "reviews", Some("v2"));
        let a_none = scope("ns-a", "reviews", None);

        let _g1 = limiter
            .try_acquire(&a, 80, Some(1))
            .expect("a")
            .expect("guard");
        let _g2 = limiter
            .try_acquire(&b, 80, Some(1))
            .expect("b ns")
            .expect("guard");
        let _g3 = limiter
            .try_acquire(&a, 443, Some(1))
            .expect("a port")
            .expect("guard");
        let _g4 = limiter
            .try_acquire(&a_v2, 80, Some(1))
            .expect("subset")
            .expect("guard");
        let _g5 = limiter
            .try_acquire(&a_none, 80, Some(1))
            .expect("unmatched")
            .expect("guard");

        assert_eq!(limiter.current(&a, 80), 1);
        assert_eq!(limiter.current(&b, 80), 1);
        assert_eq!(limiter.current(&a, 443), 1);
        assert_eq!(limiter.current(&a_v2, 80), 1);
        assert_eq!(limiter.current(&a_none, 80), 1);
    }

    #[test]
    fn k8s_uid_isolates_delete_recreate_generations() {
        let limiter = BackendPendingLimiter::new();
        let old = scope_uid("default", "reviews", "uid-old", Some("v1"));
        let new = scope_uid("default", "reviews", "uid-new", Some("v1"));

        let _g = limiter
            .try_acquire(&old, 80, Some(1))
            .expect("old")
            .expect("guard");
        let _n = limiter
            .try_acquire(&new, 80, Some(1))
            .expect("recreated Service must not inherit the old lane")
            .expect("guard");
        assert_eq!(limiter.current(&old, 80), 1);
        assert_eq!(limiter.current(&new, 80), 1);
    }

    #[test]
    fn matching_uid_does_not_collapse_distinct_upstreams() {
        // Optional UID is additive to the stable upstream id — a reused or
        // cross-cluster UID must not merge otherwise distinct destinations.
        let limiter = BackendPendingLimiter::new();
        let a = scope_uid("default", "reviews-a", "shared-uid", Some("v1"));
        let b = scope_uid("default", "reviews-b", "shared-uid", Some("v1"));
        let _ga = limiter
            .try_acquire(&a, 80, Some(1))
            .expect("a")
            .expect("guard");
        let _gb = limiter
            .try_acquire(&b, 80, Some(1))
            .expect("distinct upstream id must stay isolated despite matching UID")
            .expect("guard");
        assert_eq!(limiter.current(&a, 80), 1);
        assert_eq!(limiter.current(&b, 80), 1);
        assert_ne!(a.prefix(), b.prefix());
        assert!(
            a.prefix().contains("id"),
            "stable upstream id always present"
        );
        assert!(a.prefix().contains("uid"), "optional UID is additive");
    }

    #[test]
    fn same_upstream_and_uid_shares_lane_across_endpoint_churn() {
        let limiter = BackendPendingLimiter::new();
        let lane = scope_uid("default", "reviews", "uid-1", Some("v1"));
        // Host never enters the key; repeated acquires for the same logical
        // identity share one counter through endpoint/config churn.
        let _g = limiter
            .try_acquire(&lane, 80, Some(1))
            .expect("first")
            .expect("guard");
        limiter
            .try_acquire(&lane, 80, Some(1))
            .expect_err("endpoint rotation must retain the same lane");
        assert!(!lane.prefix().contains("10.0.0.5"));
    }

    #[test]
    fn cap_update_uses_request_cap_against_shared_count() {
        // Same logical identity; raising the cap admits more while preserving
        // the existing count. Lowering rejects until the count drains.
        // Rejection diagnostics use the requesting epoch's cap (`limit.cap`),
        // never a retained observed-cap claim from an earlier higher epoch.
        let limiter = BackendPendingLimiter::new();
        let s = scope("default", "reviews", None);
        let _g1 = limiter
            .try_acquire(&s, 80, Some(1))
            .expect("cap1")
            .expect("guard");

        let _g2 = limiter
            .try_acquire(&s, 80, Some(2))
            .expect("raised cap admits against preserved count")
            .expect("guard");
        assert_eq!(limiter.current(&s, 80), 2);

        let err = limiter
            .try_acquire(&s, 80, Some(1))
            .expect_err("lowered cap must reject while count is above it");
        assert_eq!(err.cap, 1, "rejection reports the requesting epoch's cap");
        assert_eq!(err.current, 2);
    }

    #[test]
    fn shared_destination_entry_stays_until_last_guard_drops() {
        let limiter = BackendPendingLimiter::new();
        let s = scope("default", "shared", None);
        let g1 = limiter
            .try_acquire(&s, 80, Some(2))
            .expect("first under cap")
            .expect("guard present");
        let g2 = limiter
            .try_acquire(&s, 80, Some(2))
            .expect("second under cap")
            .expect("guard present");
        assert_eq!(limiter.resident_counters(), 1);

        drop(g1);
        assert_eq!(
            limiter.resident_counters(),
            1,
            "a still-held slot must keep the destination counter resident"
        );
        assert_eq!(limiter.current(&s, 80), 1);

        drop(g2);
        assert_eq!(
            limiter.resident_counters(),
            0,
            "the last release must evict the now-idle counter"
        );
        assert_eq!(limiter.current(&s, 80), 0);
    }

    #[test]
    fn concurrent_acquire_never_exceeds_cap() {
        use std::sync::atomic::AtomicUsize;
        use std::thread;

        let limiter = Arc::new(BackendPendingLimiter::new());
        let s = Arc::new(scope("default", "h", None));
        let cap: u32 = 8;
        let granted = Arc::new(AtomicUsize::new(0));
        let held = Arc::new(std::sync::Mutex::new(Vec::new()));

        let mut handles = Vec::new();
        for _ in 0..64 {
            let limiter = Arc::clone(&limiter);
            let granted = Arc::clone(&granted);
            let held = Arc::clone(&held);
            let s = Arc::clone(&s);
            handles.push(thread::spawn(move || {
                if let Ok(Some(guard)) = limiter.try_acquire(&s, 9090, Some(cap)) {
                    granted.fetch_add(1, Ordering::Relaxed);
                    held.lock().expect("held lock").push(guard);
                }
            }));
        }
        for h in handles {
            h.join().expect("thread join");
        }

        assert_eq!(
            granted.load(Ordering::Relaxed),
            cap as usize,
            "exactly `cap` acquirers must win under contention"
        );
        assert_eq!(
            limiter.current(&s, 9090),
            u64::from(cap),
            "the counter must equal the number of held guards"
        );
        held.lock().expect("held lock").clear();
        assert_eq!(limiter.current(&s, 9090), 0);
    }

    #[test]
    fn concurrent_churn_keeps_count_balanced_and_evicts() {
        use std::thread;

        let limiter = Arc::new(BackendPendingLimiter::new());
        let s = Arc::new(scope("default", "hot", None));
        let cap: u32 = 1;

        let mut handles = Vec::new();
        for _ in 0..8 {
            let limiter = Arc::clone(&limiter);
            let s = Arc::clone(&s);
            handles.push(thread::spawn(move || {
                for _ in 0..4_000 {
                    if let Ok(Some(guard)) = limiter.try_acquire(&s, 80, Some(cap)) {
                        for _ in 0..24 {
                            std::hint::spin_loop();
                        }
                        drop(guard);
                    }
                }
            }));
        }
        for h in handles {
            h.join().expect("thread join");
        }

        assert_eq!(limiter.current(&s, 80), 0);
        assert_eq!(limiter.resident_counters(), 0);
    }

    #[test]
    fn over_cap_rejects_racing_last_drop_leave_no_resident_entry() {
        use std::thread;

        let limiter = Arc::new(BackendPendingLimiter::new());
        let s = Arc::new(scope("default", "spray", None));
        let cap: u32 = 1;

        let mut handles = Vec::new();
        for _ in 0..12 {
            let limiter = Arc::clone(&limiter);
            let s = Arc::clone(&s);
            handles.push(thread::spawn(move || {
                for _ in 0..3_000 {
                    if let Ok(Some(guard)) = limiter.try_acquire(&s, 80, Some(cap)) {
                        for _ in 0..8 {
                            std::hint::spin_loop();
                        }
                        drop(guard);
                    }
                }
            }));
        }
        for h in handles {
            h.join().expect("thread join");
        }

        assert_eq!(limiter.current(&s, 80), 0);
        assert_eq!(limiter.resident_counters(), 0);
    }

    #[test]
    fn delimiter_bearing_names_do_not_collide() {
        let a = BackendPendingScopeBase::new("a|b", "c", None, Some("d"));
        let b = BackendPendingScopeBase::new("a", "b|c", None, Some("d"));
        assert_ne!(a.prefix(), b.prefix());
        assert_ne!(a.digest(), b.digest());
    }
}
