//! Backend capability registry keyed by deduplicated backend target identity.
//!
//! The request hot path consults this registry to decide whether plain HTTPS
//! traffic should use the native HTTP/3 pool, the direct HTTP/2 pool, or the
//! generic reqwest path. Capabilities are learned at startup and refreshed by
//! a background task so protocol discovery stays out of the hot proxy path.

use dashmap::DashMap;
use std::cell::RefCell;
use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::config::types::{BackendScheme, Proxy, UpstreamTarget};
use crate::tls::backend::{append_optional_pool_key_component, append_pool_key_component};

thread_local! {
    /// Reused per-thread buffer for capability-key lookups on the request hot
    /// path. Mirrors the zero-allocation strategy used by `HTTP2_POOL_KEY_BUF`
    /// so `BackendCapabilityRegistry::get()` adds no per-request allocation.
    static CAPABILITY_KEY_BUF: RefCell<String> = RefCell::new(String::with_capacity(192));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolSupport {
    Unknown,
    Supported,
    Unsupported,
}

impl ProtocolSupport {
    #[inline]
    pub fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }
}

/// Merge a fresh protocol-probe classification with the previously cached
/// value.
///
/// When `preserve_previous` is set (transient DNS/connect/refused/timeout
/// failures), an existing classification is carried forward so a blip during
/// periodic refresh cannot wipe a proven `Supported` entry for up to the full
/// refresh interval.
///
/// A transient failure with **no** prior classification (or a prior `Unknown`)
/// still takes `probed`: there is no verdict to protect, and the first probe is
/// the only chance to record the definitive `Unsupported` that a backend which
/// simply does not speak the protocol should carry. Since the H3/QUIC "port has
/// no listener" case is indistinguishable from a connect timeout on the wire,
/// preserving `Unknown` there would leave every non-QUIC HTTPS backend
/// permanently unclassified.
///
/// Non-preserving probes (successful handshake, ALPN/protocol evidence that
/// the target lacks the protocol) always take `probed` as authoritative.
#[inline]
pub fn merge_protocol_probe_classification(
    previous: Option<ProtocolSupport>,
    probed: ProtocolSupport,
    preserve_previous: bool,
) -> ProtocolSupport {
    match previous {
        Some(previous) if preserve_previous && !matches!(previous, ProtocolSupport::Unknown) => {
            previous
        }
        _ => probed,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlainHttpCapabilities {
    pub h1: ProtocolSupport,
    pub h2_tls: ProtocolSupport,
    pub h3: ProtocolSupport,
}

impl Default for PlainHttpCapabilities {
    fn default() -> Self {
        Self {
            h1: ProtocolSupport::Unknown,
            h2_tls: ProtocolSupport::Unknown,
            h3: ProtocolSupport::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrpcTransportCapabilities {
    pub h2_tls: ProtocolSupport,
    pub h2c: ProtocolSupport,
}

impl Default for GrpcTransportCapabilities {
    fn default() -> Self {
        Self {
            h2_tls: ProtocolSupport::Unknown,
            h2c: ProtocolSupport::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackendCapabilityRecord {
    pub plain_http: PlainHttpCapabilities,
    pub grpc_transport: GrpcTransportCapabilities,
    pub hbone: ProtocolSupport,
    pub last_probe_at_unix_secs: u64,
    pub last_probe_error: Option<String>,
}

impl Default for BackendCapabilityRecord {
    fn default() -> Self {
        Self {
            plain_http: PlainHttpCapabilities::default(),
            grpc_transport: GrpcTransportCapabilities::default(),
            hbone: ProtocolSupport::Unknown,
            last_probe_at_unix_secs: now_unix_secs(),
            last_probe_error: None,
        }
    }
}

/// Pre-probe view of one registry entry, taken by
/// [`BackendCapabilityRegistry::snapshot_for_probe`].
///
/// The same snapshot serves two roles, and that is the point: it is the
/// `previous` input to [`merge_protocol_probe_classification`] *and* the
/// compare expectation handed back to
/// [`BackendCapabilityRegistry::commit_probe`]. Reading the registry a second
/// time before the write-back would reintroduce the race this type exists to
/// close — the merge would reason about one version while the commit compared
/// against another.
///
/// Holding the strong `Arc` for the whole probe window is load-bearing, not
/// incidental: every registry mutation publishes a **freshly allocated** `Arc`
/// (`upsert`, `mark_h3_unsupported`, `mark_h2_tls_unsupported`,
/// `mark_hbone_unsupported` all build a new record and replace the slot), so
/// pointer identity is a valid version token — and because this snapshot keeps
/// the old allocation alive, the allocator cannot recycle its address for a
/// newer record. That rules out ABA on the token.
///
/// A live-learning call that finds nothing to change (e.g. `mark_h3_unsupported`
/// on an already-`Unsupported` entry) leaves the `Arc` in place and therefore
/// does *not* invalidate an in-flight probe: no state changed, so there is
/// nothing for the probe to clobber.
#[derive(Debug, Clone, Default)]
pub struct BackendCapabilitySnapshot {
    previous: Option<Arc<BackendCapabilityRecord>>,
}

impl BackendCapabilitySnapshot {
    /// The record observed before the probe started, or `None` when the key
    /// was vacant (first classification of a newly configured target).
    #[inline]
    pub fn previous(&self) -> Option<&BackendCapabilityRecord> {
        self.previous.as_deref()
    }

    /// Whether the key was vacant when the snapshot was taken.
    #[allow(dead_code)] // Used by tests and external lib callers.
    #[inline]
    pub fn was_vacant(&self) -> bool {
        self.previous.is_none()
    }
}

/// Result of a [`BackendCapabilityRegistry::commit_probe`] write-back.
#[derive(Debug)]
pub enum CapabilityCommitOutcome {
    /// The probe result replaced exactly the snapshot it was computed against
    /// (or filled a key that was still vacant). Carries the record that is now
    /// published, so callers log and count committed state rather than a
    /// proposal.
    Committed(Arc<BackendCapabilityRecord>),
    /// A request-path live-learning downgrade — or a concurrent refresh —
    /// replaced or inserted the entry while the probe was in flight. The newer
    /// record wins and the probe result is discarded.
    RejectedStale,
    /// `retain_keys` pruned the key while the probe was in flight. The target
    /// is no longer active, so the probe result must not resurrect it.
    RejectedEvicted,
}

impl CapabilityCommitOutcome {
    #[allow(dead_code)] // Used by tests and external lib callers.
    #[inline]
    pub fn is_committed(&self) -> bool {
        matches!(self, Self::Committed(_))
    }

    /// Stable label for structured logs.
    #[inline]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Committed(_) => "committed",
            Self::RejectedStale => "stale_snapshot",
            Self::RejectedEvicted => "entry_evicted",
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackendCapabilityProbeTarget {
    pub key: String,
    /// Proxy clone with `backend_host` / `backend_port` rebased to the probe
    /// target. Probe helpers that take `&Proxy` read `.backend_host` /
    /// `.backend_port` directly — no separate host/port fields needed.
    pub proxy: Proxy,
    /// Whether this target opts into gateway-to-mesh HBONE probing.
    pub hbone_hint: bool,
    /// Sidecar HBONE listener port for this target. Defaults to Istio 15008.
    pub hbone_port: u16,
    /// Outer HBONE dial host. Defaults to the target host; NodeWaypoint targets
    /// override it with the destination NodeWaypoint endpoint.
    pub hbone_dial_host: String,
    /// DestinationRule policy port for this target. The probe still dials
    /// `.proxy.backend_port`, but per-port keepalive policy may be keyed by the
    /// owning Service port when mesh targetPort remaps are in play.
    pub dispatch_policy_port: u16,
    /// Peer identity the HBONE probe handshake must pin
    /// (`mesh.hbone_peer_spiffe_id` override, else `mesh.spiffe_id`), mirroring
    /// the request path so a probe cannot classify a peer Supported under
    /// weaker verification than dispatch uses.
    pub hbone_expected_peer: Option<crate::identity::SpiffeId>,
}

impl BackendCapabilityProbeTarget {
    pub fn from_proxy(proxy: &Proxy, target: Option<&UpstreamTarget>) -> Self {
        let effective_proxy = target
            .map(|target| crate::proxy::resolve_effective_proxy_for_target(proxy, Some(target)));
        let key_proxy = effective_proxy
            .as_ref()
            .map_or(proxy, |proxy| proxy.as_ref());
        let mut probe_proxy = key_proxy.clone();
        let mut hbone_hint = false;
        let mut hbone_port = crate::modes::mesh::hbone::ISTIO_HBONE_PORT;
        let mut hbone_dial_host = probe_proxy.backend_host.clone();
        let mut dispatch_policy_port = key_proxy.backend_port;
        let mut hbone_expected_peer = None;
        if let Some(target) = target {
            probe_proxy.backend_host = target.host.clone();
            probe_proxy.backend_port = target.port;
            dispatch_policy_port = target.dispatch_policy_port();
            hbone_hint = crate::proxy::hbone_pool::target_hbone_enabled(target);
            hbone_port = crate::proxy::hbone_pool::target_hbone_port(target);
            match crate::proxy::hbone_pool::target_hbone_dial_host(target) {
                Ok(host) => hbone_dial_host = host.to_string(),
                Err(err) => {
                    tracing::debug!(
                        target_host = %target.host,
                        error = %err,
                        "Skipping HBONE capability probe: invalid mesh.hbone_dial_host tag"
                    );
                    hbone_hint = false;
                }
            }
            match crate::proxy::hbone_pool::target_expected_peer_spiffe(target) {
                Ok(peer) => hbone_expected_peer = peer,
                Err(err) => {
                    // A corrupt pinned identity must not be probed UNPINNED —
                    // skip HBONE probing entirely; dispatch fails the same tag
                    // closed per request.
                    tracing::debug!(
                        target_host = %target.host,
                        error = %err,
                        "Skipping HBONE capability probe: invalid mesh.spiffe_id tag"
                    );
                    hbone_hint = false;
                }
            }
        }
        let key = capability_key_for_proxy_target(key_proxy, target);
        Self {
            key,
            proxy: probe_proxy,
            hbone_hint,
            hbone_port,
            hbone_dial_host,
            dispatch_policy_port,
            hbone_expected_peer,
        }
    }

    #[inline]
    pub fn host(&self) -> &str {
        &self.proxy.backend_host
    }

    #[inline]
    pub fn port(&self) -> u16 {
        self.proxy.backend_port
    }

    #[inline]
    pub fn scheme(&self) -> BackendScheme {
        self.proxy.backend_scheme.unwrap_or(BackendScheme::Https)
    }
}

fn mark_record_h2_tls_unsupported(record: &mut BackendCapabilityRecord) {
    record.plain_http.h2_tls = ProtocolSupport::Unsupported;
    record.grpc_transport.h2_tls = ProtocolSupport::Unsupported;
    // Backend still speaks HTTPS over HTTP/1.1 — record that explicitly so
    // operators can see "h1 only" when eyeballing the registry.
    record.plain_http.h1 = ProtocolSupport::Supported;
    record.last_probe_at_unix_secs = now_unix_secs();
    record.last_probe_error = Some(
        "H2/TLS classified H1-only after ALPN-negotiated HTTP/1.1 on request path".to_string(),
    );
}

#[derive(Debug)]
pub struct BackendCapabilityRegistry {
    entries: DashMap<String, Arc<BackendCapabilityRecord>>,
}

impl Default for BackendCapabilityRegistry {
    fn default() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }
}

impl BackendCapabilityRegistry {
    #[allow(dead_code)] // Used by tests and external lib callers; binary uses sharded constructor.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_shard_amount(shard_amount: usize) -> Self {
        Self {
            entries: DashMap::with_shard_amount(shard_amount),
        }
    }

    /// Hot-path lookup. Builds the key in a thread-local buffer — no
    /// per-request `Proxy` clone and no per-request `String` allocation on
    /// repeat calls from the same thread.
    pub fn get(
        &self,
        proxy: &Proxy,
        target: Option<&UpstreamTarget>,
    ) -> Option<Arc<BackendCapabilityRecord>> {
        CAPABILITY_KEY_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            write_capability_key(&mut buf, proxy, target);
            self.entries
                .get(buf.as_str())
                .map(|entry| entry.value().clone())
        })
    }

    /// Unconditional write. Used by tests and by callers that own the entry's
    /// lifecycle outright.
    ///
    /// The periodic/startup capability refresh must **not** use this: its
    /// read → probe → write sequence spans an await, so a blind write can
    /// overwrite a request-path downgrade learned during the probe. Use
    /// [`Self::snapshot_for_probe`] + [`Self::commit_probe`] there.
    #[allow(dead_code)] // Used by tests and external lib callers; the refresh path commits.
    pub fn upsert(&self, key: String, record: BackendCapabilityRecord) {
        self.entries
            .entry(key)
            .and_modify(|entry| *entry = Arc::new(record.clone()))
            .or_insert_with(|| Arc::new(record));
    }

    /// Take the pre-probe snapshot for `key`.
    ///
    /// Cold path (once per target per refresh cycle). The returned snapshot is
    /// both the merge input and the compare expectation for
    /// [`Self::commit_probe`] — see [`BackendCapabilitySnapshot`] for why those
    /// must be the same observation.
    pub fn snapshot_for_probe(&self, key: &str) -> BackendCapabilitySnapshot {
        BackendCapabilitySnapshot {
            previous: self.entries.get(key).map(|entry| entry.value().clone()),
        }
    }

    /// Compare-and-commit a probe result against the snapshot it was computed
    /// from.
    ///
    /// The write lands only while the entry is still the exact version the
    /// probe merged against:
    ///
    /// - occupied, same `Arc` → replaced ([`CapabilityCommitOutcome::Committed`]);
    /// - occupied, different `Arc`, or occupied when the probe expected a
    ///   vacant key → the probe lost to a newer writer
    ///   ([`CapabilityCommitOutcome::RejectedStale`]);
    /// - vacant when the probe expected an entry → the key was pruned by
    ///   `retain_keys` ([`CapabilityCommitOutcome::RejectedEvicted`]);
    /// - vacant as expected → inserted.
    ///
    /// Losing is fail-closed by construction: any request-path live-learning
    /// mutation (`mark_h3_unsupported`, `mark_h2_tls_unsupported`,
    /// `mark_hbone_unsupported`) publishes a new `Arc`, so a stale probe cannot
    /// resurrect a capability the data path just proved broken — regardless of
    /// which field the live mutation touched. Rejected results are dropped, not
    /// retried: the live observation is strictly more recent evidence than the
    /// probe, and the next refresh cycle re-classifies from the new baseline.
    ///
    /// Cold path only — takes the key's `DashMap` shard entry lock. Never call
    /// this from ordinary request lookup; `get()` stays lock-light and
    /// allocation-free.
    pub fn commit_probe(
        &self,
        key: String,
        expected: &BackendCapabilitySnapshot,
        record: BackendCapabilityRecord,
    ) -> CapabilityCommitOutcome {
        let expected = expected.previous.as_ref();
        match self.entries.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                let unchanged = expected.is_some_and(|arc| Arc::ptr_eq(entry.get(), arc));
                if !unchanged {
                    // Either the observed version was replaced mid-probe, or
                    // the probe expected a vacant key and lost the insert race.
                    return CapabilityCommitOutcome::RejectedStale;
                }
                let committed = Arc::new(record);
                entry.insert(committed.clone());
                CapabilityCommitOutcome::Committed(committed)
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                if expected.is_some() {
                    // `retain_keys` pruned the key mid-probe. The target is no
                    // longer configured, so the probe must not re-add it.
                    return CapabilityCommitOutcome::RejectedEvicted;
                }
                let committed = Arc::new(record);
                entry.insert(committed.clone());
                CapabilityCommitOutcome::Committed(committed)
            }
        }
    }

    #[allow(dead_code)] // Used by tests and external lib callers; the refresh path snapshots.
    pub fn get_by_key(&self, key: &str) -> Option<Arc<BackendCapabilityRecord>> {
        self.entries.get(key).map(|entry| entry.value().clone())
    }

    /// Downgrade the cached H3 classification for a backend target to
    /// `Unsupported` after an observed H3 connection / protocol failure.
    /// No-op when the target has no cached record (the next periodic refresh
    /// will classify it from scratch).
    ///
    /// Called from the proxy hot path after a 502 with a connection-class
    /// error from the native H3 backend pool, so subsequent requests skip
    /// the H3 pool and route via the cross-protocol bridge instead of
    /// repeatedly failing against a backend whose QUIC listener rolled back
    /// between refresh cycles.
    pub fn mark_h3_unsupported(&self, proxy: &Proxy, target: Option<&UpstreamTarget>) {
        let key = capability_key_for_proxy_target(proxy, target);
        if let Some(mut entry) = self.entries.get_mut(&key)
            && !matches!(entry.plain_http.h3, ProtocolSupport::Unsupported)
        {
            let mut new_record = (**entry).clone();
            new_record.plain_http.h3 = ProtocolSupport::Unsupported;
            new_record.last_probe_at_unix_secs = now_unix_secs();
            new_record.last_probe_error =
                Some("H3 downgraded after connection/protocol failure on request path".to_string());
            *entry = Arc::new(new_record);
        }
    }

    /// Downgrade the cached H2/TLS classification for a backend target to
    /// `Unsupported` after observing an ALPN-driven HTTP/1.1 fallback
    /// (`Http2PoolError::BackendSelectedHttp1`).
    ///
    /// The direct H2 pool's per-key ALPN learning cache was removed in
    /// favor of this registry, so without this downgrade every subsequent
    /// request would re-attempt the direct H2 handshake, re-negotiate
    /// HTTP/1.1, and re-pay the fallback cost until the next 24 h refresh.
    /// Marking the backend Unsupported here makes subsequent requests go
    /// straight to reqwest. The gRPC h2 transport bucket is downgraded in
    /// lockstep since the same ALPN observation is the signal for both. If
    /// the target has no cached record yet, this creates an initial H1-only
    /// record only when a backend SNI override requires direct H2; ordinary
    /// non-SNI proxies keep the historical occupied-entry-only behavior so
    /// `mark_h3_unsupported` / `mark_hbone_unsupported` asymmetry does not
    /// spill into unrelated proxies that share the target key.
    ///
    /// Returns `true` when the registry was mutated (including creation of
    /// that initial H1-only record) and `false` when the key was already
    /// marked H2/TLS-unsupported.
    pub fn mark_h2_tls_unsupported(&self, proxy: &Proxy, target: Option<&UpstreamTarget>) -> bool {
        let key = capability_key_for_proxy_target(proxy, target);
        match self.entries.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                if matches!(entry.get().plain_http.h2_tls, ProtocolSupport::Unsupported)
                    && matches!(
                        entry.get().grpc_transport.h2_tls,
                        ProtocolSupport::Unsupported
                    )
                {
                    return false;
                }
                let mut new_record = (**entry.get()).clone();
                mark_record_h2_tls_unsupported(&mut new_record);
                entry.insert(Arc::new(new_record));
                true
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                if proxy.resolved_tls.sni.is_none() {
                    return false;
                }
                let mut new_record = BackendCapabilityRecord::default();
                mark_record_h2_tls_unsupported(&mut new_record);
                entry.insert(Arc::new(new_record));
                true
            }
        }
    }

    /// Downgrade the HBONE classification for a backend target after a live
    /// gateway-to-mesh tunnel failure. If no refresh record exists yet, insert
    /// an HBONE-only `Unsupported` record so cold-start live failures are
    /// cached immediately instead of redialing the same unavailable waypoint on
    /// every request until the next refresh.
    pub fn mark_hbone_unsupported(&self, proxy: &Proxy, target: Option<&UpstreamTarget>) {
        let key = capability_key_for_proxy_target(proxy, target);
        let error = Some("HBONE downgraded after tunnel failure on request path".to_string());
        match self.entries.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                if matches!(entry.get().hbone, ProtocolSupport::Unsupported) {
                    return;
                }
                let mut new_record = (**entry.get()).clone();
                new_record.hbone = ProtocolSupport::Unsupported;
                new_record.last_probe_at_unix_secs = now_unix_secs();
                new_record.last_probe_error = error;
                entry.insert(Arc::new(new_record));
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(Arc::new(BackendCapabilityRecord {
                    hbone: ProtocolSupport::Unsupported,
                    last_probe_at_unix_secs: now_unix_secs(),
                    last_probe_error: error,
                    ..Default::default()
                }));
            }
        }
    }

    pub fn retain_keys(&self, active_keys: &std::collections::HashSet<String>) {
        self.entries.retain(|key, _| active_keys.contains(key));
    }

    /// Snapshot of every registry entry as `(key, record)` pairs.
    ///
    /// Consumed by the JWT-authenticated admin endpoint
    /// `GET /backend-capabilities` (see `src/admin/mod.rs` +
    /// `docs/admin_api.md`) and by test-side introspection. Not called
    /// on the hot path — allocates one `Vec` + clones every `Arc` — so
    /// request latency is unaffected.
    pub fn snapshot(&self) -> Vec<(String, Arc<BackendCapabilityRecord>)> {
        self.entries
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[cfg(test)]
    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }
}

/// Compute an owned capability key from a proxy + optional target. Cold path —
/// used once per unique probe target during setup. The request hot path should
/// go through `BackendCapabilityRegistry::get()` to reuse the thread-local
/// buffer.
pub fn capability_key_for_proxy_target(proxy: &Proxy, target: Option<&UpstreamTarget>) -> String {
    let mut buf = String::with_capacity(192);
    write_capability_key(&mut buf, proxy, target);
    buf
}

/// Compute an owned capability key from a proxy that already reflects its
/// target's host/port (i.e., a `BackendCapabilityProbeTarget.proxy`).
#[allow(dead_code)] // Used by tests and library callers; binary hot paths use target-aware lookup.
pub fn capability_key(proxy: &Proxy) -> String {
    capability_key_for_proxy_target(proxy, None)
}

/// Write the capability key into `buf`. Callers clear the buffer first if
/// they're reusing one (see `BackendCapabilityRegistry::get`).
///
/// Key shape:
/// `scheme|host|port|dns_override|ca|mtls_cert|mtls_key|sni|sans|verify|svidg=static|hbone_port|hbone_dial_host|hbone_peer_spiffe`.
/// `|` delimiter matches the pool-key conventions in the rest of the code;
/// user/config-controlled components are escaped before separators are appended.
/// The HBONE fields are populated only when the upstream target opts into
/// HBONE; direct backend capability observations remain shared for ordinary
/// targets that use the same connection identity. Invalid HBONE metadata uses
/// raw tag values in the key so malformed secured targets do not reuse probe
/// results from a different waypoint or peer.
fn write_capability_key(buf: &mut String, proxy: &Proxy, target: Option<&UpstreamTarget>) {
    let scheme = proxy.backend_scheme.unwrap_or(BackendScheme::Https);
    let (host, port) = match target {
        Some(t) => (t.host.as_str(), t.port),
        None => (proxy.backend_host.as_str(), proxy.backend_port),
    };
    let hbone_key_fields = target
        .filter(|t| crate::proxy::hbone_pool::target_hbone_enabled(t))
        .map(|target| {
            let hbone_port = crate::proxy::hbone_pool::target_hbone_port(target);
            let hbone_dial_host = crate::proxy::hbone_pool::target_hbone_dial_host(target)
                .ok()
                .or_else(|| {
                    target
                        .tags
                        .get(crate::proxy::hbone_pool::HBONE_DIAL_HOST_TAG)
                        .map(String::as_str)
                });
            let hbone_peer_spiffe = crate::proxy::hbone_pool::target_expected_peer_spiffe(target)
                .ok()
                .flatten()
                .map(|spiffe| spiffe.to_string())
                .or_else(|| {
                    target
                        .tags
                        .get(crate::proxy::hbone_pool::HBONE_PEER_SPIFFE_ID_TAG)
                        .or_else(|| {
                            target
                                .tags
                                .get(crate::proxy::hbone_pool::MESH_SPIFFE_ID_TAG)
                        })
                        .cloned()
                });
            (hbone_port, hbone_dial_host, hbone_peer_spiffe)
        });
    buf.push_str(scheme.to_scheme_str());
    buf.push('|');
    append_pool_key_component(buf, host);
    let _ = write!(buf, "|{port}|");
    append_optional_pool_key_component(buf, proxy.dns_override.as_deref());
    buf.push('|');
    crate::tls::backend::append_backend_tls_pool_key_fields(
        buf,
        &proxy.resolved_tls,
        proxy.resolved_tls.client_cert_path.as_deref(),
        proxy.resolved_tls.client_key_path.as_deref(),
        proxy.resolved_tls.verify_server_cert,
        None,
    );
    buf.push('|');
    if let Some((port, dial_host, peer_spiffe)) = hbone_key_fields {
        let _ = write!(buf, "{port}");
        buf.push('|');
        append_optional_pool_key_component(buf, dial_host);
        buf.push('|');
        append_optional_pool_key_component(buf, peer_spiffe.as_deref());
    }
}

#[inline]
pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub type SharedBackendCapabilityRegistry = Arc<BackendCapabilityRegistry>;

/// Single-flight + coalesce guard for `refresh_backend_capabilities`.
///
/// Callers flip `pending` to request a refresh. The first caller also flips
/// `running` and spawns the refresh task; subsequent callers leave `running`
/// alone and exit — the running task drains `pending` in a loop and then
/// uses a handoff-safe `try_finish()` that atomically re-checks `pending`
/// before releasing the runner role, so work queued mid-finish cannot be
/// orphaned. Invariants:
///
/// - At most one refresh task in flight at any moment.
/// - If a caller sets `pending` after the running task's last
///   `take_pending()` but before the runner releases `running`, the
///   runner observes the new pending flag in `try_finish()` and either
///   re-acquires the runner role itself or hands off to a freshly-spawned
///   task — no silent work loss.
#[derive(Debug, Default)]
pub struct RefreshCoalescer {
    running: AtomicBool,
    pending: AtomicBool,
}

impl RefreshCoalescer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark refresh work as needed. Returns `true` if the caller just
    /// transitioned to the "runner" role and must drive the refresh loop
    /// in a spawned task; `false` means an existing runner will absorb
    /// this request.
    pub fn request(&self) -> bool {
        self.pending.store(true, Ordering::Release);
        !self.running.swap(true, Ordering::AcqRel)
    }

    /// Consume one pending flag. Returns `true` when a refresh should run,
    /// `false` when the inner drain loop has caught up.
    pub fn take_pending(&self) -> bool {
        self.pending.swap(false, Ordering::AcqRel)
    }

    /// Attempt to release the runner role. Returns `true` if the caller is
    /// truly done and should exit; `false` if a concurrent `request()`
    /// queued work during the finish window and the caller has re-acquired
    /// the runner role (must loop back to `take_pending()`).
    ///
    /// Guarantees no orphaned `pending` flag: every path leaves either
    /// `running=false, pending=false` (truly idle), or `running=true` with
    /// *some* task (this one or a freshly-spawned one) responsible for
    /// draining.
    pub fn try_finish(&self) -> bool {
        // Release the runner role. Any concurrent `request()` from here
        // onward sees `running=false` and spawns a fresh runner, so the
        // only race is with a caller that already passed its
        // `running.swap` *before* this store (i.e. coalesced while we
        // were still running).
        self.running.store(false, Ordering::Release);
        if !self.pending.load(Ordering::Acquire) {
            return true;
        }
        // Pending is set and we just cleared `running`. Try to re-acquire
        // the runner role. `swap` returns the old value:
        // - old was `false` (we set it true): WE re-acquired → return
        //   `false` so the caller loops back and drains.
        // - old was `true` (a fresh `request()` already became the new
        //   runner): they own the drain → return `true` so the caller
        //   exits cleanly.
        self.running.swap(true, Ordering::AcqRel)
    }
}

pub type SharedRefreshCoalescer = Arc<RefreshCoalescer>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{
        AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, Proxy, ResponseBodyMode,
    };
    use chrono::Utc;

    fn minimal_proxy() -> Proxy {
        let now = Utc::now();
        Proxy {
            id: "p1".to_string(),
            namespace: crate::config::types::default_namespace(),
            name: None,
            hosts: vec![],
            listen_path: Some("/".to_string()),
            backend_scheme: Some(BackendScheme::Https),
            dispatch_kind: DispatchKind::from(BackendScheme::Https),
            backend_host: "backend.test".to_string(),
            backend_port: 443,
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

    #[test]
    fn registry_get_returns_none_before_upsert() {
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();
        assert!(registry.get(&proxy, None).is_none());
    }

    #[test]
    fn registry_upsert_stores_and_get_reads_same_key() {
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();
        let key = capability_key(&proxy);
        let mut record = BackendCapabilityRecord::default();
        record.plain_http.h2_tls = ProtocolSupport::Supported;
        record.plain_http.h3 = ProtocolSupport::Supported;
        registry.upsert(key.clone(), record);

        let fetched = registry.get(&proxy, None).expect("entry should exist");
        assert!(fetched.plain_http.h2_tls.is_supported());
        assert!(fetched.plain_http.h3.is_supported());
        assert!(!fetched.plain_http.h1.is_supported());

        let by_key = registry.get_by_key(&key).expect("key lookup should work");
        assert!(by_key.plain_http.h2_tls.is_supported());
    }

    #[test]
    fn registry_upsert_overwrites_existing_entry() {
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();
        let key = capability_key(&proxy);

        let mut first = BackendCapabilityRecord::default();
        first.plain_http.h2_tls = ProtocolSupport::Supported;
        registry.upsert(key.clone(), first);

        let mut second = BackendCapabilityRecord::default();
        second.plain_http.h2_tls = ProtocolSupport::Unsupported;
        second.plain_http.h1 = ProtocolSupport::Supported;
        registry.upsert(key, second);

        let fetched = registry.get(&proxy, None).unwrap();
        assert!(!fetched.plain_http.h2_tls.is_supported());
        assert!(fetched.plain_http.h1.is_supported());
    }

    #[test]
    fn registry_retain_keys_prunes_inactive_entries() {
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();
        let key = capability_key(&proxy);
        registry.upsert(key.clone(), BackendCapabilityRecord::default());

        let mut active = std::collections::HashSet::new();
        active.insert("some-other-key".to_string());
        registry.retain_keys(&active);

        assert!(registry.get(&proxy, None).is_none());
        assert!(registry.is_empty());
    }

    #[test]
    fn registry_mark_h3_unsupported_downgrades_supported_entry() {
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();
        let key = capability_key(&proxy);
        let mut record = BackendCapabilityRecord::default();
        record.plain_http.h3 = ProtocolSupport::Supported;
        record.plain_http.h2_tls = ProtocolSupport::Supported;
        registry.upsert(key, record);

        registry.mark_h3_unsupported(&proxy, None);

        let fetched = registry.get(&proxy, None).expect("entry must exist");
        assert_eq!(fetched.plain_http.h3, ProtocolSupport::Unsupported);
        assert!(
            fetched.last_probe_error.is_some(),
            "downgrade should stamp last_probe_error for operator visibility"
        );
        // H2 classification must NOT be affected — only H3 was observed broken.
        assert!(fetched.plain_http.h2_tls.is_supported());
    }

    #[test]
    fn registry_mark_h3_unsupported_is_noop_when_no_cached_entry() {
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();
        // No upsert — mark_h3_unsupported must not panic or create a phantom entry.
        registry.mark_h3_unsupported(&proxy, None);
        assert!(registry.get(&proxy, None).is_none());
    }

    #[test]
    fn registry_mark_h3_unsupported_is_idempotent() {
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();
        let key = capability_key(&proxy);
        let mut record = BackendCapabilityRecord::default();
        record.plain_http.h3 = ProtocolSupport::Unsupported;
        registry.upsert(key, record);

        // Second downgrade should be a cheap no-op — no allocation, no replacement.
        registry.mark_h3_unsupported(&proxy, None);
        let fetched = registry.get(&proxy, None).unwrap();
        assert_eq!(fetched.plain_http.h3, ProtocolSupport::Unsupported);
    }

    #[test]
    fn registry_mark_h2_tls_unsupported_downgrades_both_h2_buckets() {
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();
        let key = capability_key(&proxy);
        let mut record = BackendCapabilityRecord::default();
        record.plain_http.h2_tls = ProtocolSupport::Supported;
        record.plain_http.h3 = ProtocolSupport::Supported;
        record.grpc_transport.h2_tls = ProtocolSupport::Supported;
        registry.upsert(key, record);

        assert!(registry.mark_h2_tls_unsupported(&proxy, None));

        let fetched = registry.get(&proxy, None).unwrap();
        assert_eq!(fetched.plain_http.h2_tls, ProtocolSupport::Unsupported);
        assert_eq!(fetched.grpc_transport.h2_tls, ProtocolSupport::Unsupported);
        assert_eq!(
            fetched.plain_http.h1,
            ProtocolSupport::Supported,
            "HTTPS still works, just over h1"
        );
        // H3 classification must NOT be affected — ALPN fallback is an
        // H2 observation, not an H3 observation.
        assert_eq!(fetched.plain_http.h3, ProtocolSupport::Supported);
        assert!(fetched.last_probe_error.is_some());
    }

    #[test]
    fn registry_mark_h2_tls_unsupported_creates_h1_only_entry_when_missing() {
        let registry = BackendCapabilityRegistry::new();
        let mut proxy = minimal_proxy();
        proxy.resolved_tls.sni = Some("backend.mesh.internal".to_string());
        assert!(registry.mark_h2_tls_unsupported(&proxy, None));

        let fetched = registry.get(&proxy, None).unwrap();
        assert_eq!(fetched.plain_http.h2_tls, ProtocolSupport::Unsupported);
        assert_eq!(fetched.grpc_transport.h2_tls, ProtocolSupport::Unsupported);
        assert_eq!(fetched.plain_http.h1, ProtocolSupport::Supported);
        assert!(fetched.last_probe_error.is_some());
    }

    #[test]
    fn registry_mark_h2_tls_unsupported_without_sni_is_noop_when_missing() {
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();

        assert!(!registry.mark_h2_tls_unsupported(&proxy, None));
        assert!(
            registry.get(&proxy, None).is_none(),
            "non-SNI vacant downgrades should not create a shared H1-only entry"
        );
    }

    #[test]
    fn probe_target_carries_hbone_hint_from_upstream_tags() {
        let proxy = minimal_proxy();
        let mut tags = std::collections::HashMap::new();
        tags.insert("mesh.hbone".to_string(), "true".to_string());
        tags.insert("mesh.hbone_port".to_string(), "16008".to_string());
        tags.insert("mesh.hbone_dial_host".to_string(), "10.9.0.7".to_string());
        let target = UpstreamTarget {
            host: "orders.default.svc.cluster.local".to_string(),
            port: 8080,
            service_port_policy_key: None,
            weight: 100,
            tags,
            locality: None,
            path: None,
        };

        let probe_target = BackendCapabilityProbeTarget::from_proxy(&proxy, Some(&target));

        assert!(probe_target.hbone_hint);
        assert_eq!(probe_target.hbone_port, 16008);
        assert_eq!(probe_target.hbone_dial_host, "10.9.0.7");
        assert_eq!(probe_target.host(), "orders.default.svc.cluster.local");
        assert_eq!(probe_target.port(), 8080);
        assert_eq!(
            probe_target.key,
            capability_key_for_proxy_target(&proxy, Some(&target))
        );

        let mut other_hbone_port = target.clone();
        other_hbone_port
            .tags
            .insert("mesh.hbone_port".to_string(), "15008".to_string());
        assert_ne!(
            capability_key_for_proxy_target(&proxy, Some(&target)),
            capability_key_for_proxy_target(&proxy, Some(&other_hbone_port)),
            "HBONE targets sharing the same app host:port must not share capability entries when sidecar ports differ"
        );

        let mut other_dial_host = target.clone();
        other_dial_host
            .tags
            .insert("mesh.hbone_dial_host".to_string(), "10.9.0.8".to_string());
        assert_ne!(
            capability_key_for_proxy_target(&proxy, Some(&target)),
            capability_key_for_proxy_target(&proxy, Some(&other_dial_host)),
            "HBONE targets sharing the same app host:port must not share capability entries when waypoint dial hosts differ"
        );

        let mut other_peer = target.clone();
        other_peer.tags.insert(
            "mesh.hbone_peer_spiffe_id".to_string(),
            "spiffe://cluster.local/ns/ferrum-system/sa/node-waypoint-b".to_string(),
        );
        assert_ne!(
            capability_key_for_proxy_target(&proxy, Some(&target)),
            capability_key_for_proxy_target(&proxy, Some(&other_peer)),
            "HBONE targets sharing the same app host:port must not share capability entries when pinned peer identities differ"
        );

        let mut direct_target = target.clone();
        direct_target.tags.clear();
        assert_ne!(
            capability_key_for_proxy_target(&proxy, Some(&target)),
            capability_key_for_proxy_target(&proxy, Some(&direct_target)),
            "HBONE opt-in must be part of the capability key"
        );
    }

    #[test]
    fn probe_target_rejects_empty_hbone_dial_host_override() {
        let proxy = minimal_proxy();
        let mut tags = std::collections::HashMap::new();
        tags.insert("mesh.hbone".to_string(), "true".to_string());
        tags.insert("mesh.hbone_dial_host".to_string(), " ".to_string());
        let target = UpstreamTarget {
            host: "orders.default.svc.cluster.local".to_string(),
            port: 8080,
            service_port_policy_key: None,
            weight: 100,
            tags,
            locality: None,
            path: None,
        };

        let probe_target = BackendCapabilityProbeTarget::from_proxy(&proxy, Some(&target));

        assert!(
            !probe_target.hbone_hint,
            "malformed dial host must skip HBONE probing so dispatch fails closed"
        );
        assert_eq!(probe_target.hbone_dial_host, proxy.backend_host);
    }

    #[test]
    fn registry_mark_hbone_unsupported_downgrades_supported_entry() {
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();
        let key = capability_key(&proxy);
        let record = BackendCapabilityRecord {
            hbone: ProtocolSupport::Supported,
            plain_http: PlainHttpCapabilities {
                h2_tls: ProtocolSupport::Supported,
                ..PlainHttpCapabilities::default()
            },
            ..BackendCapabilityRecord::default()
        };
        registry.upsert(key, record);

        registry.mark_hbone_unsupported(&proxy, None);

        let fetched = registry.get(&proxy, None).unwrap();
        assert_eq!(fetched.hbone, ProtocolSupport::Unsupported);
        assert_eq!(
            fetched.plain_http.h2_tls,
            ProtocolSupport::Supported,
            "HBONE downgrade must not affect direct HTTPS capabilities"
        );
        assert!(fetched.last_probe_error.is_some());
    }

    #[test]
    fn registry_mark_hbone_unsupported_creates_entry_when_no_cached_record_exists() {
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();
        registry.mark_hbone_unsupported(&proxy, None);
        let fetched = registry
            .get(&proxy, None)
            .expect("live HBONE failure should create cached unsupported verdict");
        assert_eq!(fetched.hbone, ProtocolSupport::Unsupported);
        assert!(fetched.last_probe_error.is_some());
    }

    #[test]
    fn record_default_starts_with_no_probe_error() {
        // Regression guard: the periodic refresh path in
        // `probe_backend_capabilities` (src/proxy/mod.rs) constructs
        // `BackendCapabilityRecord::default()` per probe and only writes
        // to `last_probe_error` on genuine probe failure. If `Default`
        // ever started carrying a non-None error, every successful
        // refresh would leak a phantom error string into the admin
        // `GET /backend-capabilities` payload.
        let record = BackendCapabilityRecord::default();
        assert!(record.last_probe_error.is_none());
    }

    #[test]
    fn successful_refresh_clears_last_probe_error_after_h3_downgrade() {
        // Regression guard for the admin `last_probe_error` surface.
        //
        // Sequence:
        //   1. A request-path H3 failure stamps `last_probe_error` via
        //      `mark_h3_unsupported`.
        //   2. The next periodic refresh re-probes the backend and
        //      finds it healthy. The refresh path constructs a fresh
        //      `BackendCapabilityRecord::default()` (pre-cleared
        //      `last_probe_error`) and `upsert()`s it whole, replacing
        //      the prior record.
        //
        // The post-refresh entry must NOT carry the old error string.
        // If a future refactor switched `upsert` to a partial merge,
        // or made the refresh mutate the existing record in place
        // without explicitly clearing `last_probe_error`, operators
        // would see a stale "H3 downgraded after connection/protocol
        // failure" message indefinitely after the backend recovered —
        // that's the exact misleading-output regression we guard
        // against here.
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();
        let key = capability_key(&proxy);

        let mut prior = BackendCapabilityRecord::default();
        prior.plain_http.h3 = ProtocolSupport::Supported;
        prior.plain_http.h2_tls = ProtocolSupport::Supported;
        registry.upsert(key.clone(), prior);

        // Simulate a request-path H3 failure that downgrades H3 + stamps the error.
        registry.mark_h3_unsupported(&proxy, None);

        // Stamp a known-old `last_probe_at_unix_secs` into the downgraded
        // record so we can later assert the refresh advanced past it.
        // `now_unix_secs()` resolves to whole seconds, so two calls within
        // the same test run typically collapse to the same value — the
        // explicit `STALE_TS = 1` sentinel makes the timestamp-advance
        // invariant testable without sleeping for a full second.
        const STALE_TS: u64 = 1;
        let mut downgraded = (*registry.get(&proxy, None).expect("entry")).clone();
        assert!(
            downgraded.last_probe_error.is_some(),
            "precondition: downgrade must have stamped last_probe_error"
        );
        downgraded.last_probe_at_unix_secs = STALE_TS;
        registry.upsert(key.clone(), downgraded);

        // Simulate a successful periodic refresh: the refresh code
        // builds a fresh `BackendCapabilityRecord::default()` (whose
        // `last_probe_error` is already None and whose
        // `last_probe_at_unix_secs` comes from `now_unix_secs()`) and
        // upserts it whole.
        let mut refreshed = BackendCapabilityRecord::default();
        refreshed.plain_http.h3 = ProtocolSupport::Supported;
        refreshed.plain_http.h2_tls = ProtocolSupport::Supported;
        registry.upsert(key, refreshed);

        let fetched = registry.get(&proxy, None).expect("entry must exist");
        assert!(
            fetched.last_probe_error.is_none(),
            "successful refresh must clear stale last_probe_error from prior downgrade"
        );
        // Timestamp-freshness invariant: a future refactor that mutates
        // the existing record in place to clear the error string but
        // forgets to update the timestamp (or vice versa) must fail this
        // test. `> STALE_TS` is sufficient — `now_unix_secs()` is
        // guaranteed to exceed `1` for any reasonable wall clock.
        assert!(
            fetched.last_probe_at_unix_secs > STALE_TS,
            "successful refresh must advance last_probe_at_unix_secs (was {STALE_TS}, now {})",
            fetched.last_probe_at_unix_secs,
        );
        assert_eq!(fetched.plain_http.h3, ProtocolSupport::Supported);
        assert_eq!(fetched.plain_http.h2_tls, ProtocolSupport::Supported);
    }

    #[test]
    fn successful_refresh_clears_last_probe_error_after_h2_tls_downgrade() {
        // Same regression intent as the H3 variant, but starting from an
        // ALPN-driven HTTP/1.1 fallback signal that landed via
        // `mark_h2_tls_unsupported`. A subsequent successful refresh
        // (backend now serving H2 again) must not leak the old
        // "H2/TLS downgraded after ALPN-negotiated HTTP/1.1" string out
        // through `GET /backend-capabilities`.
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();
        let key = capability_key(&proxy);

        let mut prior = BackendCapabilityRecord::default();
        prior.plain_http.h2_tls = ProtocolSupport::Supported;
        prior.grpc_transport.h2_tls = ProtocolSupport::Supported;
        registry.upsert(key.clone(), prior);

        registry.mark_h2_tls_unsupported(&proxy, None);

        // See `successful_refresh_clears_last_probe_error_after_h3_downgrade`
        // for the rationale behind the stale-timestamp sentinel.
        const STALE_TS: u64 = 1;
        let mut downgraded = (*registry.get(&proxy, None).expect("entry")).clone();
        assert!(downgraded.last_probe_error.is_some());
        downgraded.last_probe_at_unix_secs = STALE_TS;
        registry.upsert(key.clone(), downgraded);

        let mut refreshed = BackendCapabilityRecord::default();
        refreshed.plain_http.h2_tls = ProtocolSupport::Supported;
        refreshed.grpc_transport.h2_tls = ProtocolSupport::Supported;
        registry.upsert(key, refreshed);

        let fetched = registry.get(&proxy, None).expect("entry must exist");
        assert!(
            fetched.last_probe_error.is_none(),
            "successful refresh must clear stale last_probe_error from prior H2 downgrade"
        );
        assert!(
            fetched.last_probe_at_unix_secs > STALE_TS,
            "successful refresh must advance last_probe_at_unix_secs (was {STALE_TS}, now {})",
            fetched.last_probe_at_unix_secs,
        );
        assert_eq!(fetched.plain_http.h2_tls, ProtocolSupport::Supported);
        assert_eq!(fetched.grpc_transport.h2_tls, ProtocolSupport::Supported);
    }

    #[test]
    fn successful_refresh_from_clean_registry_has_no_probe_error() {
        // Sanity guard: a successful first refresh against a previously
        // unseen target must never invent a `last_probe_error`. Catches
        // the obvious regression of `Default` accidentally seeding the
        // field, or the refresh path stamping a default error message
        // even on success.
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();
        let key = capability_key(&proxy);

        let mut refreshed = BackendCapabilityRecord::default();
        refreshed.plain_http.h2_tls = ProtocolSupport::Supported;
        refreshed.plain_http.h3 = ProtocolSupport::Supported;
        registry.upsert(key, refreshed);

        let fetched = registry.get(&proxy, None).expect("entry must exist");
        assert!(fetched.last_probe_error.is_none());
    }

    #[test]
    fn registry_retain_keys_keeps_active_entries() {
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();
        let key = capability_key(&proxy);
        registry.upsert(key.clone(), BackendCapabilityRecord::default());

        let mut active = std::collections::HashSet::new();
        active.insert(key.clone());
        registry.retain_keys(&active);

        assert!(registry.contains_key(&key));
    }

    #[test]
    fn refresh_coalescer_first_request_becomes_runner() {
        let coalescer = RefreshCoalescer::new();
        assert!(
            coalescer.request(),
            "first request should transition to runner role"
        );
    }

    #[test]
    fn refresh_coalescer_subsequent_request_coalesces() {
        let coalescer = RefreshCoalescer::new();
        assert!(coalescer.request());
        // Runner hasn't finished yet — a second request must NOT spawn a new
        // runner; instead the in-flight one will absorb via take_pending().
        assert!(!coalescer.request());
        assert!(!coalescer.request());
    }

    #[test]
    fn refresh_coalescer_drains_pending_requests_across_iterations() {
        let coalescer = RefreshCoalescer::new();
        assert!(coalescer.request());
        // Simulate a runner loop:
        assert!(coalescer.take_pending(), "first drain sees pending=true");

        // While the refresh is "running", another caller arrives:
        assert!(!coalescer.request(), "coalesced call does not re-spawn");

        // Runner's next iteration still sees pending.
        assert!(
            coalescer.take_pending(),
            "pending re-set during refresh must be observed"
        );
        // No more pending now.
        assert!(!coalescer.take_pending());
        assert!(coalescer.try_finish(), "idle runner finishes cleanly");

        // After finish, a new request becomes a fresh runner.
        assert!(coalescer.request());
    }

    #[test]
    fn refresh_coalescer_try_finish_detects_coalesced_mid_finish_request() {
        // Regression test for the handoff race: a caller that coalesced
        // between the runner's last `take_pending()` and its release of
        // the runner role must not be stranded.
        let coalescer = RefreshCoalescer::new();
        assert!(coalescer.request(), "initial runner");
        assert!(coalescer.take_pending(), "drain initial work");
        assert!(!coalescer.take_pending(), "no more work");

        // Simulate a caller that races the runner's finish: they set
        // `pending` and swap `running`, observing running=true (still set
        // by the current runner) and so coalesce.
        assert!(
            !coalescer.request(),
            "caller mid-finish coalesces with the running runner"
        );

        // Now the runner calls try_finish. It must observe the
        // just-coalesced pending flag and re-acquire the runner role
        // rather than leaving it stranded.
        assert!(
            !coalescer.try_finish(),
            "try_finish must not release when pending is set; it re-acquires the runner role"
        );
        assert!(
            coalescer.take_pending(),
            "re-acquired runner drains the coalesced pending flag"
        );
        assert!(!coalescer.take_pending(), "no further work");
        assert!(coalescer.try_finish(), "final try_finish releases cleanly");
    }

    #[test]
    fn refresh_coalescer_try_finish_idle_case_exits_cleanly() {
        // Straight happy-path: no one queued work during the finish window,
        // so try_finish must release the runner role and return `true`.
        let coalescer = RefreshCoalescer::new();
        assert!(coalescer.request());
        assert!(coalescer.take_pending());
        assert!(!coalescer.take_pending());
        assert!(coalescer.try_finish(), "idle try_finish exits cleanly");
        // A fresh request is now a new runner (running is released).
        assert!(
            coalescer.request(),
            "after try_finish, next request is runner"
        );
    }

    /// Stress test: race many `request()` calls against runner loops using
    /// `try_finish`. For every `request()` issued, at least one refresh
    /// must end up being counted — no pending flag may be orphaned.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn refresh_coalescer_no_orphaned_pending_under_contention() {
        use std::sync::atomic::AtomicU64;
        use std::sync::atomic::Ordering as AO;

        let coalescer = Arc::new(RefreshCoalescer::new());
        let refreshes = Arc::new(AtomicU64::new(0));
        let requests = Arc::new(AtomicU64::new(0));

        // Runner loop mimics `spawn_backend_capability_refresh`'s spawn
        // closure, with a lightweight "refresh" (just a counter bump).
        fn spawn_runner(
            coalescer: Arc<RefreshCoalescer>,
            refreshes: Arc<AtomicU64>,
        ) -> tokio::task::JoinHandle<()> {
            tokio::spawn(async move {
                loop {
                    while coalescer.take_pending() {
                        refreshes.fetch_add(1, AO::Relaxed);
                        // Yield to give other tasks a chance to race.
                        tokio::task::yield_now().await;
                    }
                    if coalescer.try_finish() {
                        break;
                    }
                }
            })
        }

        let mut handles = Vec::new();
        // Many concurrent requesters.
        for _ in 0..64 {
            let coalescer = coalescer.clone();
            let requests = requests.clone();
            let refreshes = refreshes.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..50 {
                    requests.fetch_add(1, AO::Relaxed);
                    if coalescer.request() {
                        // We became the runner — spawn the drain loop.
                        spawn_runner(coalescer.clone(), refreshes.clone());
                    }
                    tokio::task::yield_now().await;
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // Let any in-flight runners drain.
        for _ in 0..50 {
            tokio::task::yield_now().await;
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }

        // After quiescence:
        // 1. No pending flag may remain set.
        // 2. No runner role may remain held (otherwise a late caller would
        //    coalesce forever).
        assert!(
            !coalescer.pending.load(AO::Acquire),
            "pending flag leaked after quiescence"
        );
        assert!(
            !coalescer.running.load(AO::Acquire),
            "running flag leaked after quiescence"
        );
        // And: at least one refresh must have happened per requester
        // burst (coalescing allowed, but total loss of a flag is not).
        let r = refreshes.load(AO::Relaxed);
        let q = requests.load(AO::Relaxed);
        assert!(r >= 1, "no refreshes ran despite {q} requests");
        assert!(
            r <= q,
            "impossibly many refreshes ({r}) for {q} requests — sanity check"
        );
    }
}
