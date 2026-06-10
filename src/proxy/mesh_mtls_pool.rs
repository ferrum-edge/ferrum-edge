//! Sidecar-to-sidecar SVID-mTLS HTTP/2 connection pool (Sidecar egress).
//!
//! The Sidecar mesh transport is plain HTTP over mutual TLS to the peer
//! sidecar's inbound listener (`:15006`) — NOT HBONE (HBONE is the
//! Ambient/Waypoint transport on `:15008`; a Sidecar peer has no HBONE
//! listener). This pool owns multiplexed HTTP/2 client connections whose TLS
//! layer presents this gateway's SVID and verifies the peer's server SVID
//! against the mesh trust bundle, PINNED to the destination workload identity
//! from the target's `mesh.spiffe_id` tag. The peer's `auto`-serving frontend
//! terminates mTLS, sniffs the h2 preface (its mesh inbound `ServerConfig`
//! also advertises `h2` at ALPN), and routes the request by `:authority` to
//! its materialized local inbound loopback route.
//!
//! Pool mechanics mirror [`super::hbone_pool::HboneConnectionPool`]: a
//! `DashMap` of per-key sender lists with a shared-lock fast path, coalesced
//! creation, idle pruning, and an SVID-fingerprint + pinned-peer pool key so a
//! rotated SVID or a different pinned identity never reuses an old session.
//! Errors reuse [`HbonePoolError`] — the two pools share every failure shape
//! (DNS, TCP, SPIFFE TLS config, TLS/H2 handshake) except HBONE's CONNECT
//! stream, so the dispatch error mapping stays single-sourced.

use dashmap::DashMap;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use std::cell::RefCell;
use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use tracing::debug;

use crate::config::PoolConfig;
use crate::config::types::{Proxy, UpstreamTarget};
use crate::dns::DnsCache;
use crate::identity::{SharedSvidBundle, SpiffeId};
use crate::proxy::body::SizeLimitedIncoming;
use crate::tls::spiffe::build_spiffe_outbound_config;

use super::hbone_pool::{
    HbonePoolError, MESH_SPIFFE_ID_TAG, current_svid_identity, entry_idle_expired,
    matches_boolish_true, target_expected_peer_spiffe, unix_secs, write_pool_config_key,
};

/// Tag marking a target for Sidecar SVID-mTLS dispatch (the peer is a mesh
/// sidecar reached over mutual TLS on its inbound listener). Mutually
/// exclusive with `mesh.hbone` — the materializer emits exactly one per
/// topology.
pub const MESH_MTLS_TARGET_TAG: &str = "mesh.mtls";
/// Tag overriding the peer sidecar's inbound mTLS port. Absent ⇒ Istio's
/// conventional `15006`.
pub const MESH_MTLS_PORT_TAG: &str = "mesh.mtls_port";
/// Istio-convention sidecar inbound mTLS port.
pub const ISTIO_SIDECAR_INBOUND_PORT: u16 = 15006;

/// Multiplexed hyper H2 sender over the SVID-mTLS session. The body type is
/// [`SizeLimitedIncoming`] so dispatch enforces `max_request_body_size_bytes`
/// on the streamed request body exactly like the HBONE path.
pub type MeshMtlsSender = http2::SendRequest<SizeLimitedIncoming>;

thread_local! {
    static MESH_MTLS_POOL_KEY_BUF: RefCell<String> = RefCell::new(String::with_capacity(192));
}

struct MeshMtlsPoolEntry {
    sender: MeshMtlsSender,
    /// Unix seconds of the last checkout; atomic so the shared-lock fast path
    /// refreshes recency without the exclusive shard write lock.
    last_used_at: AtomicU64,
    idle_timeout_seconds: u64,
}

pub fn target_mesh_mtls_enabled(target: &UpstreamTarget) -> bool {
    target
        .tags
        .get(MESH_MTLS_TARGET_TAG)
        .is_some_and(|value| matches_boolish_true(value))
}

pub fn target_mesh_mtls_port(target: &UpstreamTarget) -> u16 {
    target
        .tags
        .get(MESH_MTLS_PORT_TAG)
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port > 0)
        .unwrap_or(ISTIO_SIDECAR_INBOUND_PORT)
}

/// The pinned peer identity a `mesh.mtls` target MUST declare. Unlike HBONE
/// (where operator-supplied targets may legitimately omit the tag), Sidecar
/// mTLS targets are only ever produced by the mesh materializer, which always
/// stamps the destination workload identity — so an absent tag here is a
/// config-corruption signal and fails the dial closed rather than silently
/// downgrading to trust-domain-only verification.
pub fn target_mesh_mtls_expected_peer(target: &UpstreamTarget) -> Result<SpiffeId, HbonePoolError> {
    target_expected_peer_spiffe(target)?.ok_or_else(|| HbonePoolError::InvalidPeerSpiffeTag {
        value: String::new(),
        message: format!(
            "mesh.mtls target {}:{} carries no {MESH_SPIFFE_ID_TAG} tag; refusing unpinned \
             sidecar mTLS dial",
            target.host, target.port
        ),
    })
}

pub struct MeshMtlsConnectionPool {
    entries: DashMap<String, Vec<MeshMtlsPoolEntry>>,
    creation_locks: DashMap<String, Arc<Mutex<()>>>,
    gateway_svid: SharedSvidBundle,
    dns_cache: DnsCache,
    pool_config: PoolConfig,
    last_idle_prune_unix_secs: AtomicU64,
}

impl MeshMtlsConnectionPool {
    pub fn new(
        pool_config: PoolConfig,
        dns_cache: DnsCache,
        gateway_svid: SharedSvidBundle,
        shard_amount: usize,
    ) -> Self {
        Self {
            entries: DashMap::with_shard_amount(shard_amount),
            creation_locks: DashMap::with_shard_amount(shard_amount),
            gateway_svid,
            dns_cache,
            pool_config,
            last_idle_prune_unix_secs: AtomicU64::new(0),
        }
    }

    pub fn pool_size(&self) -> usize {
        self.entries.iter().map(|entry| entry.value().len()).sum()
    }

    /// Checkout (or create) a multiplexed H2 sender to `target_host:mtls_port`
    /// whose mTLS session is pinned to `expected_peer`. The returned sender is
    /// a cheap clone of the pooled connection handle.
    pub async fn get_sender(
        &self,
        proxy: &Proxy,
        target_host: &str,
        mtls_port: u16,
        expected_peer: &SpiffeId,
    ) -> Result<MeshMtlsSender, HbonePoolError> {
        let (_, fingerprint) = current_svid_identity(&self.gateway_svid)?;
        let pool_config = self.pool_config.for_proxy(proxy);

        let fast_sender = with_mesh_mtls_pool_key(
            target_host,
            mtls_port,
            proxy.dns_override.as_deref(),
            &fingerprint,
            expected_peer,
            &pool_config,
            |key| self.try_cached_sender_read(key),
        );
        if let Some(sender) = fast_sender {
            return Ok(sender);
        }

        let key = with_mesh_mtls_pool_key(
            target_host,
            mtls_port,
            proxy.dns_override.as_deref(),
            &fingerprint,
            expected_peer,
            &pool_config,
            |key| key.to_string(),
        );
        self.get_or_create_sender(
            proxy,
            target_host,
            mtls_port,
            expected_peer,
            &key,
            &pool_config,
        )
        .await
    }

    async fn get_or_create_sender(
        &self,
        proxy: &Proxy,
        target_host: &str,
        mtls_port: u16,
        expected_peer: &SpiffeId,
        key: &str,
        pool_config: &PoolConfig,
    ) -> Result<MeshMtlsSender, HbonePoolError> {
        self.maybe_prune_idle_entries();
        let max_entries = pool_config.http2_connections_per_host.max(1);
        if let Some(sender) = self.cached_sender(key, max_entries) {
            return Ok(sender);
        }

        let connect_timeout = Duration::from_millis(proxy.backend_connect_timeout_ms);
        let creation_started = Instant::now();
        let creation_lock = self
            .creation_locks
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _creation_guard = tokio::time::timeout(connect_timeout, creation_lock.lock())
            .await
            .map_err(|_| HbonePoolError::ConnectTimeout {
                addr: format!("{target_host}:{mtls_port}"),
                timeout_ms: proxy.backend_connect_timeout_ms,
            })?;
        // Double-check under the creation lock: a coalesced waiter may find the
        // winner's connection already inserted.
        if let Some(sender) = self.cached_sender(key, max_entries) {
            return Ok(sender);
        }

        let remaining = crate::pool::remaining_connect_timeout(creation_started, connect_timeout)
            .ok_or_else(|| HbonePoolError::ConnectTimeout {
            addr: format!("{target_host}:{mtls_port}"),
            timeout_ms: proxy.backend_connect_timeout_ms,
        })?;
        let sender = match tokio::time::timeout(
            remaining,
            self.create_sender(proxy, target_host, mtls_port, expected_peer, pool_config),
        )
        .await
        {
            Ok(Ok(sender)) => {
                crate::runtime_metrics::global_ref()
                    .record_pool_handshake(crate::runtime_metrics::PoolKind::MeshMtls);
                sender
            }
            Ok(Err(err)) => {
                crate::runtime_metrics::global_ref()
                    .record_pool_failure(crate::runtime_metrics::PoolKind::MeshMtls);
                return Err(err);
            }
            Err(_) => {
                crate::runtime_metrics::global_ref()
                    .record_pool_failure(crate::runtime_metrics::PoolKind::MeshMtls);
                return Err(HbonePoolError::ConnectTimeout {
                    addr: format!("{target_host}:{mtls_port}"),
                    timeout_ms: proxy.backend_connect_timeout_ms,
                });
            }
        };
        self.entries
            .entry(key.to_string())
            .and_modify(|entries| {
                record_mesh_mtls_evictions(prune_pool_entries(entries));
                entries.push(MeshMtlsPoolEntry {
                    sender: sender.clone(),
                    last_used_at: AtomicU64::new(unix_secs()),
                    idle_timeout_seconds: pool_config.idle_timeout_seconds,
                });
                if entries.len() > max_entries {
                    let overflow = entries.len() - max_entries;
                    entries.drain(0..overflow);
                    record_mesh_mtls_evictions(overflow);
                }
            })
            .or_insert_with(|| {
                vec![MeshMtlsPoolEntry {
                    sender: sender.clone(),
                    last_used_at: AtomicU64::new(unix_secs()),
                    idle_timeout_seconds: pool_config.idle_timeout_seconds,
                }]
            });
        debug!(
            target_host,
            mtls_port,
            expected_peer = %expected_peer.as_str(),
            "Created sidecar SVID-mTLS HTTP/2 connection"
        );
        Ok(sender)
    }

    /// Exclusive-lock scan: prune dead/idle entries, return the first live
    /// multiplexed sender. Unlike the HBONE pool there is no Ready/Pending
    /// split — hyper's H2 sender accepts new streams as long as the connection
    /// is open (`is_closed()`); per-stream backpressure is awaited at send.
    fn cached_sender(&self, key: &str, _max_entries: usize) -> Option<MeshMtlsSender> {
        let mut entries = self.entries.get_mut(key)?;
        record_mesh_mtls_evictions(prune_pool_entries(&mut entries));
        for entry in entries.iter() {
            if entry.sender.is_closed() {
                continue;
            }
            entry.last_used_at.store(unix_secs(), Ordering::Relaxed);
            return Some(entry.sender.clone());
        }
        None
    }

    /// Shared-lock fast path mirroring the HBONE pool: scan for a live sender
    /// and refresh recency via a relaxed store, avoiding the exclusive shard
    /// write lock. Expired entries are skipped (not removed); dead senders fall
    /// through to the write path.
    fn try_cached_sender_read(&self, key: &str) -> Option<MeshMtlsSender> {
        let entries = self.entries.get(key)?;
        let now = unix_secs();
        for entry in entries.value().iter() {
            let last_used = entry.last_used_at.load(Ordering::Relaxed);
            if entry_idle_expired(last_used, entry.idle_timeout_seconds, now) {
                continue;
            }
            if entry.sender.is_closed() {
                continue;
            }
            entry.last_used_at.store(now, Ordering::Relaxed);
            return Some(entry.sender.clone());
        }
        None
    }

    fn maybe_prune_idle_entries(&self) {
        let now = unix_secs();
        let interval = if self.pool_config.idle_timeout_seconds == 0 {
            60
        } else {
            self.pool_config.idle_timeout_seconds.clamp(1, 60)
        };
        let last = self.last_idle_prune_unix_secs.load(Ordering::Relaxed);
        if now.saturating_sub(last) < interval {
            return;
        }
        if self
            .last_idle_prune_unix_secs
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        self.entries.retain(|_, entries| {
            record_mesh_mtls_evictions(prune_pool_entries(entries));
            !entries.is_empty()
        });
        self.creation_locks.retain(|key, lock| {
            self.entries.contains_key(key.as_str()) || Arc::strong_count(lock) > 1
        });
    }

    async fn create_sender(
        &self,
        proxy: &Proxy,
        target_host: &str,
        mtls_port: u16,
        expected_peer: &SpiffeId,
        pool_config: &PoolConfig,
    ) -> Result<MeshMtlsSender, HbonePoolError> {
        let resolved_ip = self
            .dns_cache
            .resolve(
                target_host,
                proxy.dns_override.as_deref(),
                proxy.dns_cache_ttl_seconds,
            )
            .await
            .map_err(|e| HbonePoolError::DnsLookup {
                host: target_host.to_string(),
                message: e.to_string(),
            })?;
        let sock_addr = std::net::SocketAddr::new(resolved_ip, mtls_port);
        let addr = sock_addr.to_string();
        let connect_timeout = Duration::from_millis(proxy.backend_connect_timeout_ms);
        let connect_started = Instant::now();

        let tcp = tokio::time::timeout(
            connect_timeout,
            crate::socket_opts::connect_with_socket_opts(sock_addr),
        )
        .await
        .map_err(|_| HbonePoolError::ConnectTimeout {
            addr: addr.clone(),
            timeout_ms: proxy.backend_connect_timeout_ms,
        })?
        .map_err(|source| HbonePoolError::Connect {
            addr: addr.clone(),
            source,
        })?;
        let _ = tcp.set_nodelay(true);
        if pool_config.enable_http_keep_alive {
            set_tcp_keepalive(&tcp, pool_config.tcp_keepalive_seconds);
        }

        // Plain mesh HTTP over mTLS speaks h2 to the peer sidecar's frontend
        // (which advertises h2 and preface-sniffs via `auto`), so advertise h2
        // only. The peer identity is PINNED: its server SVID URI SAN must equal
        // `expected_peer` exactly.
        let tls_config = build_spiffe_outbound_config(
            self.gateway_svid.clone(),
            Some(expected_peer.clone()),
            vec![b"h2".to_vec()],
        )?;
        let connector = TlsConnector::from(tls_config);
        let server_name = rustls::pki_types::ServerName::try_from(target_host.to_string())
            .map_err(|e| HbonePoolError::InvalidServerName {
                host: target_host.to_string(),
                message: e.to_string(),
            })?;

        let Some(remaining) =
            crate::pool::remaining_connect_timeout(connect_started, connect_timeout)
        else {
            return Err(HbonePoolError::ConnectTimeout {
                addr,
                timeout_ms: proxy.backend_connect_timeout_ms,
            });
        };
        let tls_stream = tokio::time::timeout(remaining, connector.connect(server_name, tcp))
            .await
            .map_err(|_| HbonePoolError::ConnectTimeout {
                addr: addr.clone(),
                timeout_ms: proxy.backend_connect_timeout_ms,
            })?
            .map_err(|e| HbonePoolError::TlsHandshake {
                host: target_host.to_string(),
                message: e.to_string(),
            })?;

        let mut builder = http2::Builder::new(TokioExecutor::new());
        builder.timer(TokioTimer::new());
        if pool_config.enable_http2 {
            builder
                .keep_alive_interval(Duration::from_secs(
                    pool_config.http2_keep_alive_interval_seconds,
                ))
                .keep_alive_timeout(Duration::from_secs(
                    pool_config.http2_keep_alive_timeout_seconds,
                ))
                .max_concurrent_reset_streams(4096);
        }
        builder
            .initial_stream_window_size(pool_config.http2_initial_stream_window_size)
            .initial_connection_window_size(pool_config.http2_initial_connection_window_size)
            .adaptive_window(pool_config.http2_adaptive_window)
            .max_frame_size(pool_config.http2_max_frame_size);
        if let Some(max_streams) = pool_config.http2_max_concurrent_streams {
            builder.max_concurrent_streams(max_streams);
            builder.initial_max_send_streams(max_streams as usize);
        }

        let Some(remaining) =
            crate::pool::remaining_connect_timeout(connect_started, connect_timeout)
        else {
            return Err(HbonePoolError::ConnectTimeout {
                addr,
                timeout_ms: proxy.backend_connect_timeout_ms,
            });
        };
        let io = TokioIo::new(tls_stream);
        let (sender, connection) = tokio::time::timeout(remaining, builder.handshake(io))
            .await
            .map_err(|_| HbonePoolError::ConnectTimeout {
                addr,
                timeout_ms: proxy.backend_connect_timeout_ms,
            })?
            .map_err(|e| HbonePoolError::H2Handshake {
                host: target_host.to_string(),
                message: e.to_string(),
            })?;

        // Connection driver exits when all sender handles are dropped.
        // In-flight requests are covered by RequestGuard on the dispatch path.
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                debug!(
                    "mesh_mtls_pool: sidecar mTLS HTTP/2 connection closed: {}",
                    e
                );
            }
        });

        Ok(sender)
    }
}

fn prune_pool_entries(entries: &mut Vec<MeshMtlsPoolEntry>) -> usize {
    let before = entries.len();
    let now = unix_secs();
    entries.retain(|entry| {
        !entry.sender.is_closed()
            && !entry_idle_expired(
                entry.last_used_at.load(Ordering::Relaxed),
                entry.idle_timeout_seconds,
                now,
            )
    });
    before.saturating_sub(entries.len())
}

fn record_mesh_mtls_evictions(count: usize) {
    crate::runtime_metrics::global_ref()
        .record_pool_evictions(crate::runtime_metrics::PoolKind::MeshMtls, count as u64);
}

fn set_tcp_keepalive(stream: &TcpStream, keepalive_seconds: u64) {
    #[cfg(unix)]
    use std::os::fd::AsFd;
    #[cfg(windows)]
    use std::os::windows::io::AsSocket;

    #[cfg(unix)]
    let borrowed = stream.as_fd();
    #[cfg(windows)]
    let borrowed = stream.as_socket();
    let socket = socket2::SockRef::from(&borrowed);
    let keepalive = socket2::TcpKeepalive::new().with_time(Duration::from_secs(keepalive_seconds));
    if let Err(e) = socket.set_tcp_keepalive(&keepalive) {
        debug!("mesh_mtls_pool: failed to set TCP keepalive: {}", e);
    }
}

fn with_mesh_mtls_pool_key<R>(
    host: &str,
    mtls_port: u16,
    dns_override: Option<&str>,
    svid_fingerprint: &str,
    expected_peer: &SpiffeId,
    pool_config: &PoolConfig,
    f: impl FnOnce(&str) -> R,
) -> R {
    MESH_MTLS_POOL_KEY_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        write_mesh_mtls_pool_key(
            &mut buf,
            host,
            mtls_port,
            dns_override,
            svid_fingerprint,
            expected_peer,
            pool_config,
        );
        f(&buf)
    })
}

fn write_mesh_mtls_pool_key(
    buf: &mut String,
    host: &str,
    mtls_port: u16,
    dns_override: Option<&str>,
    svid_fingerprint: &str,
    expected_peer: &SpiffeId,
    pool_config: &PoolConfig,
) {
    buf.clear();
    // The pinned peer identity is connection identity: a session verified
    // against one expected SVID must never serve a target pinning another.
    let _ = write!(
        buf,
        "mesh-mtls|{host}|{mtls_port}|{}|{svid_fingerprint}|{}",
        dns_override.unwrap_or_default(),
        expected_peer.as_str()
    );
    write_pool_config_key(buf, pool_config);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn target_with_tags(tags: &[(&str, &str)]) -> UpstreamTarget {
        UpstreamTarget {
            host: "10.0.0.1".to_string(),
            port: 8080,
            weight: 1,
            tags: tags
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
            locality: None,
            path: None,
        }
    }

    #[test]
    fn mtls_tag_and_port_parse() {
        assert!(!target_mesh_mtls_enabled(&target_with_tags(&[])));
        assert!(target_mesh_mtls_enabled(&target_with_tags(&[(
            MESH_MTLS_TARGET_TAG,
            "true"
        )])));
        assert_eq!(
            target_mesh_mtls_port(&target_with_tags(&[])),
            ISTIO_SIDECAR_INBOUND_PORT
        );
        assert_eq!(
            target_mesh_mtls_port(&target_with_tags(&[(MESH_MTLS_PORT_TAG, "16006")])),
            16006
        );
        assert_eq!(
            target_mesh_mtls_port(&target_with_tags(&[(MESH_MTLS_PORT_TAG, "0")])),
            ISTIO_SIDECAR_INBOUND_PORT
        );
    }

    #[test]
    fn mtls_expected_peer_is_required_and_fails_closed() {
        // Absent tag: a mesh.mtls target without a pinned identity must error.
        let err =
            target_mesh_mtls_expected_peer(&target_with_tags(&[(MESH_MTLS_TARGET_TAG, "true")]))
                .expect_err("missing mesh.spiffe_id must fail closed");
        assert!(matches!(err, HbonePoolError::InvalidPeerSpiffeTag { .. }));

        // Corrupt tag: same fail-closed shape.
        let err = target_mesh_mtls_expected_peer(&target_with_tags(&[
            (MESH_MTLS_TARGET_TAG, "true"),
            (MESH_SPIFFE_ID_TAG, "not-a-spiffe-id"),
        ]))
        .expect_err("invalid mesh.spiffe_id must fail closed");
        assert!(matches!(err, HbonePoolError::InvalidPeerSpiffeTag { .. }));

        // Valid tag resolves to the pinned identity.
        let peer = target_mesh_mtls_expected_peer(&target_with_tags(&[
            (MESH_MTLS_TARGET_TAG, "true"),
            (
                MESH_SPIFFE_ID_TAG,
                "spiffe://cluster.local/ns/default/sa/reviews",
            ),
        ]))
        .expect("valid pinned identity");
        assert_eq!(
            peer.as_str(),
            "spiffe://cluster.local/ns/default/sa/reviews"
        );
    }

    #[test]
    fn pool_key_partitions_by_peer_identity_and_svid() {
        let pool_config = PoolConfig::default();
        let peer_a = SpiffeId::new("spiffe://cluster.local/ns/default/sa/a").unwrap();
        let peer_b = SpiffeId::new("spiffe://cluster.local/ns/default/sa/b").unwrap();
        let key = |peer: &SpiffeId, fp: &str| {
            with_mesh_mtls_pool_key("10.0.0.1", 15006, None, fp, peer, &pool_config, |key| {
                key.to_string()
            })
        };
        assert_ne!(
            key(&peer_a, "fp"),
            key(&peer_b, "fp"),
            "different pinned identities must not share a session"
        );
        assert_ne!(
            key(&peer_a, "fp1"),
            key(&peer_a, "fp2"),
            "an SVID rotation must repartition the pool"
        );
        assert_eq!(key(&peer_a, "fp"), key(&peer_a, "fp"));
    }
}
