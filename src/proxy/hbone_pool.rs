//! Gateway-to-mesh HBONE connection pool.
//!
//! The pool owns HTTP/2 client connections to mesh sidecars on the standard
//! HBONE listener. Each request opens a CONNECT stream to the application port
//! and then speaks ordinary HTTP over the resulting byte tunnel.

use bytes::{Buf, Bytes};
use dashmap::DashMap;
use futures_util::FutureExt;
use h2::client::SendRequest;
use h2::{RecvStream, SendStream};
use http::{Method, Request, StatusCode, Version};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::fmt::Write;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use tracing::debug;

use crate::config::PoolConfig;
use crate::config::types::{Proxy, UpstreamTarget};
use crate::dns::DnsCache;
use crate::identity::{SharedSvidBundle, SvidBundle};
use crate::modes::mesh::hbone::{BAGGAGE_HEADER, ISTIO_HBONE_PORT, baggage_header_for_source};
use crate::retry::ErrorClass;
use crate::tls::spiffe::{SpiffeTlsError, build_spiffe_outbound_config};

pub const HBONE_TARGET_TAG: &str = "mesh.hbone";
pub const HBONE_PORT_TAG: &str = "mesh.hbone_port";
/// Tag carrying the destination workload's SPIFFE id. When present on a mesh
/// target it is the identity the outbound SVID-mTLS handshake must PIN: the
/// peer's server SVID URI SAN has to equal it exactly, not merely share a trust
/// domain. Stamped by `service_discovery::mesh` tag builders for both HBONE and
/// Sidecar-mTLS targets.
pub const MESH_SPIFFE_ID_TAG: &str = "mesh.spiffe_id";
const MAX_HBONE_WRITE_CHUNK: usize = 16 * 1024;
const ADAPTIVE_STREAM_WINDOW_SIZE: u32 = 16 * 1024 * 1024;
const ADAPTIVE_CONNECTION_WINDOW_SIZE: u32 = 64 * 1024 * 1024;

thread_local! {
    static HBONE_POOL_KEY_BUF: RefCell<String> = RefCell::new(String::with_capacity(160));
}

#[derive(Debug)]
struct HbonePoolEntry {
    sender: SendRequest<Bytes>,
    /// Unix seconds of the last checkout. Stored atomically so the shared-lock
    /// fast path (`try_cached_sender_read`) can refresh recency without taking
    /// the exclusive shard write lock — a busy connection must not be pruned as
    /// idle merely because it is only ever served by the fast path.
    last_used_at: AtomicU64,
    idle_timeout_seconds: u64,
}

enum CachedSender {
    Ready(SendRequest<Bytes>),
    Pending(SendRequest<Bytes>),
}

#[derive(Debug, thiserror::Error)]
pub enum HbonePoolError {
    #[error("gateway SVID bundle is not configured")]
    NoSvid,
    #[error("gateway SVID bundle has no leaf certificate")]
    NoLeafCert,
    #[error("DNS resolution failed for {host}: {message}")]
    DnsLookup { host: String, message: String },
    #[error("connect timeout after {timeout_ms}ms to {addr}")]
    ConnectTimeout { addr: String, timeout_ms: u64 },
    #[error("TCP connect failed to {addr}: {source}")]
    Connect {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid HBONE server name {host}: {message}")]
    InvalidServerName { host: String, message: String },
    #[error("invalid {MESH_SPIFFE_ID_TAG} tag '{value}' on mesh target: {message}")]
    InvalidPeerSpiffeTag { value: String, message: String },
    #[error("SPIFFE TLS config failed: {0}")]
    TlsConfig(#[from] SpiffeTlsError),
    #[error("TLS handshake failed for {host}: {message}")]
    TlsHandshake { host: String, message: String },
    #[error("HTTP/2 handshake failed for {host}: {message}")]
    H2Handshake { host: String, message: String },
    #[error("failed to build HBONE CONNECT request for {authority}: {message}")]
    InvalidConnectRequest { authority: String, message: String },
    #[error("HBONE CONNECT failed for {authority}: {message}")]
    ConnectStream { authority: String, message: String },
    #[error("HBONE CONNECT rejected for {authority} with status {status}")]
    ConnectRejected { authority: String, status: u16 },
}

impl HbonePoolError {
    pub fn error_class(&self) -> ErrorClass {
        match self {
            Self::NoSvid
            | Self::NoLeafCert
            | Self::TlsConfig(_)
            | Self::InvalidPeerSpiffeTag { .. } => ErrorClass::ConnectionPoolError,
            Self::DnsLookup { .. } | Self::InvalidServerName { .. } => ErrorClass::DnsLookupError,
            Self::ConnectTimeout { .. } => ErrorClass::ConnectionTimeout,
            Self::Connect { source, .. } => {
                if crate::retry::is_port_exhaustion(source) {
                    ErrorClass::PortExhaustion
                } else {
                    match source.kind() {
                        std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionReset => ErrorClass::ConnectionRefused,
                        std::io::ErrorKind::TimedOut => ErrorClass::ConnectionTimeout,
                        std::io::ErrorKind::BrokenPipe => ErrorClass::ConnectionClosed,
                        _ => ErrorClass::RequestError,
                    }
                }
            }
            Self::TlsHandshake { .. } => ErrorClass::TlsError,
            Self::H2Handshake { .. }
            | Self::InvalidConnectRequest { .. }
            | Self::ConnectStream { .. }
            | Self::ConnectRejected { .. } => ErrorClass::ProtocolError,
        }
    }

    pub fn is_capability_failure(&self) -> bool {
        matches!(
            self,
            Self::NoSvid
                | Self::NoLeafCert
                | Self::DnsLookup { .. }
                | Self::ConnectTimeout { .. }
                | Self::Connect { .. }
                | Self::InvalidServerName { .. }
                | Self::TlsConfig(_)
                | Self::TlsHandshake { .. }
                | Self::H2Handshake { .. }
        )
    }
}

pub struct HboneConnectionPool {
    entries: DashMap<String, Vec<HbonePoolEntry>>,
    creation_locks: DashMap<String, Arc<Mutex<()>>>,
    gateway_svid: SharedSvidBundle,
    dns_cache: DnsCache,
    pool_config: PoolConfig,
    last_idle_prune_unix_secs: AtomicU64,
}

impl HboneConnectionPool {
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

    pub async fn warmup_connection(
        &self,
        proxy: &Proxy,
        target_host: &str,
        target_port: u16,
        hbone_port: u16,
        expected_peer: Option<&crate::identity::SpiffeId>,
    ) -> Result<(), HbonePoolError> {
        let (source_identity, fingerprint) = current_svid_identity(&self.gateway_svid)?;
        let pool_config = self.pool_config.for_proxy(proxy);

        let fast_sender = with_hbone_pool_key(
            target_host,
            target_port,
            hbone_port,
            proxy.dns_override.as_deref(),
            &fingerprint,
            expected_peer,
            &pool_config,
            |key| self.try_cached_sender_read(key),
        );

        let sender = if let Some(sender) = fast_sender {
            sender
        } else {
            let key = with_hbone_pool_key(
                target_host,
                target_port,
                hbone_port,
                proxy.dns_override.as_deref(),
                &fingerprint,
                expected_peer,
                &pool_config,
                |key| key.to_string(),
            );
            self.get_or_create_sender(
                proxy,
                target_host,
                target_port,
                hbone_port,
                expected_peer,
                &key,
                &pool_config,
            )
            .await?
        };
        tokio::time::timeout(
            Duration::from_millis(proxy.backend_connect_timeout_ms),
            self.open_connect_stream(sender, target_host, target_port, &source_identity),
        )
        .await
        .map_err(|_| HbonePoolError::ConnectStream {
            authority: authority_for_host_port(target_host, target_port),
            message: format!(
                "timed out after {}ms waiting for HBONE CONNECT probe response",
                proxy.backend_connect_timeout_ms
            ),
        })??;
        Ok(())
    }

    pub fn pool_size(&self) -> usize {
        self.entries.iter().map(|entry| entry.value().len()).sum()
    }

    pub async fn get_tunnel(
        &self,
        proxy: &Proxy,
        target_host: &str,
        target_port: u16,
        hbone_port: u16,
        expected_peer: Option<&crate::identity::SpiffeId>,
    ) -> Result<HboneTunnel, HbonePoolError> {
        let (source_identity, fingerprint) = current_svid_identity(&self.gateway_svid)?;
        let pool_config = self.pool_config.for_proxy(proxy);

        let fast_sender = with_hbone_pool_key(
            target_host,
            target_port,
            hbone_port,
            proxy.dns_override.as_deref(),
            &fingerprint,
            expected_peer,
            &pool_config,
            |key| self.try_cached_sender_read(key),
        );

        let sender = if let Some(sender) = fast_sender {
            sender
        } else {
            let key = with_hbone_pool_key(
                target_host,
                target_port,
                hbone_port,
                proxy.dns_override.as_deref(),
                &fingerprint,
                expected_peer,
                &pool_config,
                |key| key.to_string(),
            );
            self.get_or_create_sender(
                proxy,
                target_host,
                target_port,
                hbone_port,
                expected_peer,
                &key,
                &pool_config,
            )
            .await?
        };
        tokio::time::timeout(
            Duration::from_millis(proxy.backend_connect_timeout_ms),
            self.open_connect_stream(sender, target_host, target_port, &source_identity),
        )
        .await
        .map_err(|_| HbonePoolError::ConnectStream {
            authority: authority_for_host_port(target_host, target_port),
            message: format!(
                "timed out after {}ms waiting for HBONE CONNECT response",
                proxy.backend_connect_timeout_ms
            ),
        })?
    }

    #[allow(clippy::too_many_arguments)]
    async fn get_or_create_sender(
        &self,
        proxy: &Proxy,
        target_host: &str,
        target_port: u16,
        hbone_port: u16,
        expected_peer: Option<&crate::identity::SpiffeId>,
        key: &str,
        pool_config: &PoolConfig,
    ) -> Result<SendRequest<Bytes>, HbonePoolError> {
        self.maybe_prune_idle_entries();
        let max_entries = pool_config.http2_connections_per_host.max(1);
        match self.cached_sender(key, max_entries) {
            Some(CachedSender::Ready(sender)) => return Ok(sender),
            Some(CachedSender::Pending(sender)) => {
                let authority = authority_for_host_port(target_host, target_port);
                match tokio::time::timeout(
                    Duration::from_millis(proxy.backend_connect_timeout_ms),
                    sender.ready(),
                )
                .await
                {
                    Ok(Ok(sender)) => return Ok(sender),
                    Ok(Err(err)) => {
                        debug!(
                            target_host,
                            target_port,
                            hbone_port,
                            error = %err,
                            "Cached HBONE HTTP/2 sender closed while waiting for readiness; creating a replacement"
                        );
                    }
                    Err(_) => {
                        return Err(HbonePoolError::ConnectStream {
                            authority,
                            message: format!(
                                "timed out after {}ms waiting for cached HBONE HTTP/2 sender readiness",
                                proxy.backend_connect_timeout_ms
                            ),
                        });
                    }
                }
            }
            None => {}
        }

        let connect_timeout = Duration::from_millis(proxy.backend_connect_timeout_ms);
        let creation_started = Instant::now();
        let authority = authority_for_host_port(target_host, target_port);
        let creation_lock = self
            .creation_locks
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _creation_guard = tokio::time::timeout(connect_timeout, creation_lock.lock())
            .await
            .map_err(|_| HbonePoolError::ConnectStream {
                authority: authority.clone(),
                message: format!(
                    "timed out after {}ms waiting to coalesce HBONE HTTP/2 sender creation",
                    proxy.backend_connect_timeout_ms
                ),
            })?;
        match self.cached_sender(key, max_entries) {
            Some(CachedSender::Ready(sender)) => {
                return Ok(sender);
            }
            Some(CachedSender::Pending(sender)) => {
                let remaining = crate::pool::remaining_connect_timeout(
                    creation_started,
                    connect_timeout,
                )
                .ok_or_else(|| HbonePoolError::ConnectStream {
                    authority: authority.clone(),
                    message: format!(
                        "timed out after {}ms waiting for coalesced HBONE HTTP/2 sender creation",
                        proxy.backend_connect_timeout_ms
                    ),
                })?;
                match tokio::time::timeout(remaining, sender.ready()).await {
                    Ok(Ok(sender)) => {
                        return Ok(sender);
                    }
                    Ok(Err(err)) => {
                        debug!(
                            target_host,
                            target_port,
                            hbone_port,
                            error = %err,
                            "Cached HBONE HTTP/2 sender closed after coalesced creation wait; creating a replacement"
                        );
                    }
                    Err(_) => {
                        return Err(HbonePoolError::ConnectStream {
                            authority,
                            message: format!(
                                "timed out after {}ms waiting for coalesced HBONE HTTP/2 sender readiness",
                                proxy.backend_connect_timeout_ms
                            ),
                        });
                    }
                }
            }
            None => {}
        }

        let remaining = match crate::pool::remaining_connect_timeout(
            creation_started,
            connect_timeout,
        ) {
            Some(remaining) => remaining,
            None => {
                return Err(HbonePoolError::ConnectStream {
                    authority: authority.clone(),
                    message: format!(
                        "timed out after {}ms waiting for coalesced HBONE HTTP/2 sender creation",
                        proxy.backend_connect_timeout_ms
                    ),
                });
            }
        };
        let sender = match tokio::time::timeout(
            remaining,
            self.create_sender(proxy, target_host, hbone_port, expected_peer, pool_config),
        )
        .await
        {
            Ok(Ok(sender)) => {
                crate::runtime_metrics::global_ref()
                    .record_pool_handshake(crate::runtime_metrics::PoolKind::Hbone);
                sender
            }
            Ok(Err(err)) => {
                crate::runtime_metrics::global_ref()
                    .record_pool_failure(crate::runtime_metrics::PoolKind::Hbone);
                return Err(err);
            }
            Err(_) => {
                crate::runtime_metrics::global_ref()
                    .record_pool_failure(crate::runtime_metrics::PoolKind::Hbone);
                return Err(HbonePoolError::ConnectStream {
                    authority,
                    message: format!(
                        "timed out after {}ms creating coalesced HBONE HTTP/2 sender",
                        proxy.backend_connect_timeout_ms
                    ),
                });
            }
        };
        self.entries
            .entry(key.to_string())
            .and_modify(|entries| {
                record_hbone_evictions(prune_pool_entries(entries));
                entries.push(HbonePoolEntry {
                    sender: sender.clone(),
                    last_used_at: AtomicU64::new(unix_secs()),
                    idle_timeout_seconds: pool_config.idle_timeout_seconds,
                });
                let max_entries = pool_config.http2_connections_per_host.max(1);
                if entries.len() > max_entries {
                    let overflow = entries.len() - max_entries;
                    entries.drain(0..overflow);
                    record_hbone_evictions(overflow);
                }
            })
            .or_insert_with(|| {
                vec![HbonePoolEntry {
                    sender: sender.clone(),
                    last_used_at: AtomicU64::new(unix_secs()),
                    idle_timeout_seconds: pool_config.idle_timeout_seconds,
                }]
            });
        debug!(
            target_host,
            target_port, hbone_port, "Created gateway HBONE HTTP/2 connection"
        );
        Ok(sender)
    }

    fn cached_sender(&self, key: &str, max_entries: usize) -> Option<CachedSender> {
        let mut entries = self.entries.get_mut(key)?;
        record_hbone_evictions(prune_pool_entries(&mut entries));
        let mut pending = None;
        let mut pending_idx = None;
        let mut idx = 0;
        while idx < entries.len() {
            let entry = &mut entries[idx];
            let sender = entry.sender.clone();
            match sender.clone().ready().now_or_never() {
                Some(Ok(ready)) => {
                    entry.last_used_at.store(unix_secs(), Ordering::Relaxed);
                    return Some(CachedSender::Ready(ready));
                }
                Some(Err(_)) => {
                    entries.remove(idx);
                    record_hbone_evictions(1);
                    continue;
                }
                None => {
                    if pending.is_none() {
                        pending = Some(sender);
                        pending_idx = Some(idx);
                    }
                }
            }
            idx += 1;
        }
        if entries.len() >= max_entries {
            if let Some(idx) = pending_idx
                && let Some(entry) = entries.get_mut(idx)
            {
                entry.last_used_at.store(unix_secs(), Ordering::Relaxed);
            }
            pending.map(CachedSender::Pending)
        } else {
            None
        }
    }

    /// Shared-lock fast path: scan for a ready sender and refresh its
    /// `last_used_at` via a relaxed atomic store, avoiding the exclusive shard
    /// write lock that `cached_sender` holds during prune + scan + clone.
    /// Refreshing recency here keeps a connection served only by this path from
    /// being pruned as idle. Expired entries are skipped (not removed); dead
    /// senders fall through to the write path.
    fn try_cached_sender_read(&self, key: &str) -> Option<SendRequest<Bytes>> {
        let entries = self.entries.get(key)?;
        let now = unix_secs();
        for entry in entries.value().iter() {
            let last_used = entry.last_used_at.load(Ordering::Relaxed);
            if entry_idle_expired(last_used, entry.idle_timeout_seconds, now) {
                continue;
            }
            let sender = entry.sender.clone();
            match sender.ready().now_or_never() {
                Some(Ok(ready)) => {
                    // Refresh recency on the shared-lock fast path so a busy
                    // connection is not pruned as idle. This is the whole point
                    // of this path existing: avoid the exclusive write lock.
                    entry.last_used_at.store(now, Ordering::Relaxed);
                    return Some(ready);
                }
                _ => continue,
            }
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
            record_hbone_evictions(prune_pool_entries(entries));
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
        hbone_port: u16,
        expected_peer: Option<&crate::identity::SpiffeId>,
        pool_config: &PoolConfig,
    ) -> Result<SendRequest<Bytes>, HbonePoolError> {
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
        let sock_addr = std::net::SocketAddr::new(resolved_ip, hbone_port);
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

        // HBONE is HTTP/2 CONNECT over mTLS — advertise h2 only so a sidecar can
        // reject non-HBONE clients at ALPN. When the target declared its
        // workload identity (`mesh.spiffe_id` tag), PIN it: the peer must
        // present exactly that SVID, not merely one from an allowed trust
        // domain — a same-trust-domain workload at a reused pod IP must not be
        // able to impersonate the destination.
        let tls_config = build_spiffe_outbound_config(
            self.gateway_svid.clone(),
            expected_peer.cloned(),
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

        let (stream_window_size, connection_window_size) = h2_window_sizes(pool_config);
        let mut builder = h2::client::Builder::new();
        // The lower-level h2 builder does not expose hyper's adaptive-window
        // toggle. When adaptive sizing is requested, h2_window_sizes() raises
        // the initial windows to the same high-throughput starting point used
        // by the direct HTTP/2 pool.
        builder
            .initial_window_size(stream_window_size)
            .initial_connection_window_size(connection_window_size)
            .max_frame_size(pool_config.http2_max_frame_size)
            .max_concurrent_reset_streams(4096);
        if let Some(max_streams) = pool_config.http2_max_concurrent_streams {
            builder.max_concurrent_streams(max_streams);
        }

        let Some(remaining) =
            crate::pool::remaining_connect_timeout(connect_started, connect_timeout)
        else {
            return Err(HbonePoolError::ConnectTimeout {
                addr,
                timeout_ms: proxy.backend_connect_timeout_ms,
            });
        };
        let (sender, mut connection) =
            tokio::time::timeout(remaining, builder.handshake(tls_stream))
                .await
                .map_err(|_| HbonePoolError::ConnectTimeout {
                    addr,
                    timeout_ms: proxy.backend_connect_timeout_ms,
                })?
                .map_err(|e| HbonePoolError::H2Handshake {
                    host: target_host.to_string(),
                    message: e.to_string(),
                })?;
        if pool_config.enable_http2
            && let Some(ping_pong) = connection.ping_pong()
        {
            spawn_h2_keepalive(
                ping_pong,
                pool_config.http2_keep_alive_interval_seconds,
                pool_config.http2_keep_alive_timeout_seconds,
            );
        }

        // Connection driver exits when all SendRequest handles are dropped.
        // In-flight tunnels are covered by RequestGuard on the dispatch path.
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                debug!("hbone_pool: HTTP/2 connection closed: {}", e);
            }
        });

        Ok(sender)
    }

    async fn open_connect_stream(
        &self,
        sender: SendRequest<Bytes>,
        target_host: &str,
        target_port: u16,
        source_identity: &crate::identity::SpiffeId,
    ) -> Result<HboneTunnel, HbonePoolError> {
        let authority = authority_for_host_port(target_host, target_port);

        let mut request = Request::builder()
            .method(Method::CONNECT)
            .version(Version::HTTP_2)
            .uri(authority.as_str())
            .body(())
            .map_err(|e| HbonePoolError::InvalidConnectRequest {
                authority: authority.clone(),
                message: e.to_string(),
            })?;
        let baggage = baggage_header_for_source(source_identity);
        request.headers_mut().insert(
            BAGGAGE_HEADER,
            http::HeaderValue::from_str(&baggage).map_err(|e| {
                HbonePoolError::InvalidConnectRequest {
                    authority: authority.clone(),
                    message: e.to_string(),
                }
            })?,
        );
        request.headers_mut().insert(
            "x-ferrum-mesh-protocol",
            http::HeaderValue::from_static("hbone"),
        );

        let mut sender = sender
            .ready()
            .await
            .map_err(|e| HbonePoolError::ConnectStream {
                authority: authority.clone(),
                message: e.to_string(),
            })?;
        let (response_fut, send_stream) =
            sender
                .send_request(request, false)
                .map_err(|e| HbonePoolError::ConnectStream {
                    authority: authority.clone(),
                    message: e.to_string(),
                })?;
        let response = response_fut
            .await
            .map_err(|e| HbonePoolError::ConnectStream {
                authority: authority.clone(),
                message: e.to_string(),
            })?;
        if response.status() != StatusCode::OK {
            return Err(HbonePoolError::ConnectRejected {
                authority,
                status: response.status().as_u16(),
            });
        }
        Ok(HboneTunnel {
            recv_stream: response.into_body(),
            send_stream,
            read_buf: Bytes::new(),
            write_closed: false,
            write_reservation: 0,
        })
    }
}

pub struct HboneTunnel {
    recv_stream: RecvStream,
    send_stream: SendStream<Bytes>,
    read_buf: Bytes,
    write_closed: bool,
    write_reservation: usize,
}

impl AsyncRead for HboneTunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if dst.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            if !self.read_buf.is_empty() {
                let to_copy = self.read_buf.len().min(dst.remaining());
                if let Err(e) = self.recv_stream.flow_control().release_capacity(to_copy) {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        e.to_string(),
                    )));
                }
                dst.put_slice(&self.read_buf[..to_copy]);
                self.read_buf.advance(to_copy);
                return Poll::Ready(Ok(()));
            }

            match self.recv_stream.poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    if chunk.is_empty() {
                        continue;
                    }
                    self.read_buf = chunk;
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        e.to_string(),
                    )));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for HboneTunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "HBONE tunnel write half already closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.write_reservation == 0 {
            let desired = buf.len().min(MAX_HBONE_WRITE_CHUNK);
            self.send_stream.reserve_capacity(desired);
            self.write_reservation = desired;
        }

        match self.send_stream.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) if capacity > 0 => {
                let to_write = capacity.min(self.write_reservation).min(buf.len());
                self.send_stream
                    .send_data(Bytes::copy_from_slice(&buf[..to_write]), false)
                    .map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string())
                    })?;
                self.write_reservation = self.write_reservation.saturating_sub(to_write);
                Poll::Ready(Ok(to_write))
            }
            Poll::Ready(Some(Ok(_))) | Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                e.to_string(),
            ))),
            Poll::Ready(None) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "HBONE tunnel write half closed",
            ))),
        }
    }

    // h2 send_data queues into the connection driver which flushes to
    // TCP independently; no explicit flush API on SendStream.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if !self.write_closed {
            self.send_stream
                .send_data(Bytes::new(), true)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string()))?;
            self.write_closed = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl Unpin for HboneTunnel {}

pub fn target_hbone_enabled(target: &UpstreamTarget) -> bool {
    target
        .tags
        .get(HBONE_TARGET_TAG)
        .is_some_and(|value| matches_boolish_true(value))
}

pub fn target_hbone_port(target: &UpstreamTarget) -> u16 {
    target
        .tags
        .get(HBONE_PORT_TAG)
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port > 0)
        .unwrap_or(ISTIO_HBONE_PORT)
}

/// The destination identity an outbound mesh dial must PIN, read from the
/// target's [`MESH_SPIFFE_ID_TAG`]. `Ok(None)` when the tag is absent —
/// operator-supplied targets without a declared peer identity keep
/// trust-domain-only verification. A PRESENT but unparseable tag is an error so
/// a corrupted identity fails the dial closed instead of silently downgrading
/// to unpinned verification.
pub fn target_expected_peer_spiffe(
    target: &UpstreamTarget,
) -> Result<Option<crate::identity::SpiffeId>, HbonePoolError> {
    match target.tags.get(MESH_SPIFFE_ID_TAG) {
        None => Ok(None),
        Some(value) => crate::identity::SpiffeId::new(value)
            .map(Some)
            .map_err(|e| HbonePoolError::InvalidPeerSpiffeTag {
                value: value.clone(),
                message: e.to_string(),
            }),
    }
}

pub(crate) fn authority_for_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn h2_window_sizes(pool_config: &PoolConfig) -> (u32, u32) {
    if pool_config.http2_adaptive_window {
        (
            pool_config
                .http2_initial_stream_window_size
                .max(ADAPTIVE_STREAM_WINDOW_SIZE),
            pool_config
                .http2_initial_connection_window_size
                .max(ADAPTIVE_CONNECTION_WINDOW_SIZE),
        )
    } else {
        (
            pool_config.http2_initial_stream_window_size,
            pool_config.http2_initial_connection_window_size,
        )
    }
}

pub fn svid_fingerprint(bundle: &SvidBundle) -> Result<String, HbonePoolError> {
    let leaf = bundle
        .cert_chain_der
        .first()
        .ok_or(HbonePoolError::NoLeafCert)?;
    let digest = Sha256::digest(leaf);
    let mut out = String::with_capacity(16);
    for byte in digest[..8].iter() {
        let _ = write!(out, "{byte:02x}");
    }
    Ok(out)
}

pub(crate) fn current_svid_identity(
    gateway_svid: &SharedSvidBundle,
) -> Result<(crate::identity::SpiffeId, String), HbonePoolError> {
    let snapshot = gateway_svid.load_full();
    let bundle = snapshot.as_ref().as_ref().ok_or(HbonePoolError::NoSvid)?;
    Ok((bundle.spiffe_id.clone(), svid_fingerprint(bundle)?))
}

fn prune_pool_entries(entries: &mut Vec<HbonePoolEntry>) -> usize {
    let before = entries.len();
    let now = unix_secs();
    entries.retain(|entry| {
        !entry_idle_expired(
            entry.last_used_at.load(Ordering::Relaxed),
            entry.idle_timeout_seconds,
            now,
        )
    });
    before.saturating_sub(entries.len())
}

fn record_hbone_evictions(count: usize) {
    crate::runtime_metrics::global_ref()
        .record_pool_evictions(crate::runtime_metrics::PoolKind::Hbone, count as u64);
}

// `last_used_secs`/`now_secs` are wall-clock `unix_secs()`, matching the
// connection-pool idle convention in `GenericPool` (`last_used_epoch_ms`) so
// the two pools age idle entries the same way. A backward wall-clock step
// (NTP correction, VM resume) makes `saturating_sub` under-count idle time, so
// an idle entry may survive a few extra prune cycles until the clock catches
// up — never unbounded, since dead senders are still culled by the `ready()`
// health probe on both the read and write paths. A forward step larger than
// the timeout can evict one fresh entry, after which it self-heals. A repo-wide
// migration to a monotonic clock (this pool's prune scheduler + `GenericPool`
// together) is the right place to remove that residual, not a piecemeal switch
// of this one field that would desync it from the rest of the pool's timing.
pub(crate) fn entry_idle_expired(
    last_used_secs: u64,
    idle_timeout_seconds: u64,
    now_secs: u64,
) -> bool {
    idle_timeout_seconds > 0 && now_secs.saturating_sub(last_used_secs) > idle_timeout_seconds
}

pub(crate) fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(crate) fn matches_boolish_true(value: &str) -> bool {
    value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("yes")
        || value.eq_ignore_ascii_case("on")
        || value == "1"
}

#[allow(clippy::too_many_arguments)]
fn with_hbone_pool_key<R>(
    host: &str,
    target_port: u16,
    hbone_port: u16,
    dns_override: Option<&str>,
    svid_fingerprint: &str,
    expected_peer: Option<&crate::identity::SpiffeId>,
    pool_config: &PoolConfig,
    f: impl FnOnce(&str) -> R,
) -> R {
    HBONE_POOL_KEY_BUF.with(|cell| {
        let mut buf = cell.borrow_mut();
        write_hbone_pool_key(
            &mut buf,
            host,
            target_port,
            hbone_port,
            dns_override,
            svid_fingerprint,
            expected_peer,
            pool_config,
        );
        f(&buf)
    })
}

#[cfg(test)]
fn pool_key_owned(
    host: &str,
    target_port: u16,
    hbone_port: u16,
    dns_override: Option<&str>,
    svid_fingerprint: &str,
    expected_peer: Option<&crate::identity::SpiffeId>,
    pool_config: &PoolConfig,
) -> String {
    with_hbone_pool_key(
        host,
        target_port,
        hbone_port,
        dns_override,
        svid_fingerprint,
        expected_peer,
        pool_config,
        |key| key.to_string(),
    )
}

#[allow(clippy::too_many_arguments)]
fn write_hbone_pool_key(
    buf: &mut String,
    host: &str,
    target_port: u16,
    hbone_port: u16,
    dns_override: Option<&str>,
    svid_fingerprint: &str,
    expected_peer: Option<&crate::identity::SpiffeId>,
    pool_config: &PoolConfig,
) {
    buf.clear();
    // The pinned peer identity is connection identity, not policy: a pooled
    // mTLS connection verified against one expected SVID must never be reused
    // for a target that pins a different (or no) identity.
    let _ = write!(
        buf,
        "hbone|{host}|{target_port}|{hbone_port}|{}|{svid_fingerprint}|{}",
        dns_override.unwrap_or_default(),
        expected_peer.map(|peer| peer.as_str()).unwrap_or_default()
    );
    write_pool_config_key(buf, pool_config);
}

pub(crate) fn write_pool_config_key(buf: &mut String, pool_config: &PoolConfig) {
    // Pool-MANAGEMENT policy is intentionally excluded from the key: it does
    // not change the h2-over-mTLS connection's identity or wire behavior, and
    // including it fragmented the pool (two proxies targeting the same sidecar
    // with the same SVID but different idle-timeout / per-host caps could not
    // share an established mTLS connection). Specifically:
    //   - idle_timeout_seconds is tracked per HbonePoolEntry for idle pruning;
    //   - http2_connections_per_host is applied as a max-entries cap at insert.
    // Only fields that affect the actual connection (protocol selection,
    // keepalive, and h2 SETTINGS) remain — mirroring the direct-H2 pool key,
    // per the "never add policy fields to pool keys" invariant.
    let _ = write!(
        buf,
        "|pool={},{},{},{},{},{},{},{},{}",
        u8::from(pool_config.enable_http_keep_alive),
        u8::from(pool_config.enable_http2),
        pool_config.tcp_keepalive_seconds,
        pool_config.http2_keep_alive_interval_seconds,
        pool_config.http2_keep_alive_timeout_seconds,
        pool_config.http2_initial_stream_window_size,
        pool_config.http2_initial_connection_window_size,
        u8::from(pool_config.http2_adaptive_window),
        pool_config.http2_max_frame_size
    );
    buf.push(',');
    match pool_config.http2_max_concurrent_streams {
        Some(value) => {
            let _ = write!(buf, "{value}");
        }
        None => buf.push_str("none"),
    }
}

fn spawn_h2_keepalive(mut ping_pong: h2::PingPong, interval_seconds: u64, timeout_seconds: u64) {
    let interval_seconds = interval_seconds.max(1);
    let timeout_seconds = timeout_seconds.max(1);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_seconds));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match tokio::time::timeout(
                Duration::from_secs(timeout_seconds),
                ping_pong.ping(h2::Ping::opaque()),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    debug!("hbone_pool: HTTP/2 keepalive ping failed: {}", e);
                    break;
                }
                Err(_) => {
                    debug!("hbone_pool: HTTP/2 keepalive ping timed out");
                    break;
                }
            }
        }
    });
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
        debug!("hbone_pool: failed to set TCP keepalive: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{
        AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, ResponseBodyMode,
    };
    use crate::dns::DnsConfig;
    use crate::identity::spiffe::{SpiffeId, TrustDomain};
    use crate::identity::{TrustBundle, TrustBundleSet};
    use arc_swap::ArcSwap;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn target_with_tags(tags: &[(&str, &str)]) -> UpstreamTarget {
        UpstreamTarget {
            host: "orders.default.svc.cluster.local".to_string(),
            port: 8080,
            weight: 100,
            tags: tags
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect::<HashMap<_, _>>(),
            locality: None,
            path: None,
        }
    }

    fn test_proxy(connect_timeout_ms: u64) -> Proxy {
        let now = Utc::now();
        Proxy {
            id: "hbone-test".to_string(),
            namespace: crate::config::types::default_namespace(),
            name: None,
            hosts: vec![],
            listen_path: Some("/hbone".to_string()),
            backend_scheme: Some(BackendScheme::Http),
            dispatch_kind: DispatchKind::from(BackendScheme::Http),
            backend_host: "orders.default.svc.cluster.local".to_string(),
            backend_port: 8080,
            backend_path: None,
            strip_listen_path: true,
            preserve_host_header: false,
            backend_connect_timeout_ms: connect_timeout_ms,
            backend_read_timeout_ms: 30_000,
            backend_write_timeout_ms: 30_000,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            resolved_tls: BackendTlsConfig::default_verify(),
            dispatch_port_overrides: None,
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
            pool_max_requests_per_connection: None,
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
            allowed_methods: None,
            allowed_ws_origins: vec![],
            udp_max_response_amplification_factor: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn hbone_tag_accepts_boolish_true_values() {
        for value in ["true", "TRUE", "1", "yes", "on"] {
            let target = target_with_tags(&[(HBONE_TARGET_TAG, value)]);
            assert!(target_hbone_enabled(&target), "{value} should enable HBONE");
        }
    }

    #[test]
    fn hbone_tag_rejects_absent_or_false_values() {
        assert!(!target_hbone_enabled(&target_with_tags(&[])));
        for value in ["false", "0", "off", "no", ""] {
            let target = target_with_tags(&[(HBONE_TARGET_TAG, value)]);
            assert!(
                !target_hbone_enabled(&target),
                "{value} should not enable HBONE"
            );
        }
    }

    #[test]
    fn hbone_port_defaults_and_overrides() {
        assert_eq!(target_hbone_port(&target_with_tags(&[])), ISTIO_HBONE_PORT);
        assert_eq!(
            target_hbone_port(&target_with_tags(&[(HBONE_PORT_TAG, "16008")])),
            16008
        );
        assert_eq!(
            target_hbone_port(&target_with_tags(&[(HBONE_PORT_TAG, "0")])),
            ISTIO_HBONE_PORT
        );
        assert_eq!(
            target_hbone_port(&target_with_tags(&[(HBONE_PORT_TAG, "not-a-port")])),
            ISTIO_HBONE_PORT
        );
    }

    #[test]
    fn authority_for_host_port_brackets_ipv6_literals() {
        assert_eq!(
            authority_for_host_port("orders.default.svc.cluster.local", 8080),
            "orders.default.svc.cluster.local:8080"
        );
        assert_eq!(
            authority_for_host_port("2001:db8::10", 8080),
            "[2001:db8::10]:8080"
        );
        assert_eq!(
            authority_for_host_port("[2001:db8::10]", 8080),
            "[2001:db8::10]:8080"
        );
    }

    #[test]
    fn adaptive_window_lifts_hbone_initial_window_sizes() {
        let fixed = PoolConfig {
            http2_initial_stream_window_size: 65_535,
            http2_initial_connection_window_size: 131_072,
            http2_adaptive_window: false,
            ..PoolConfig::default()
        };
        assert_eq!(h2_window_sizes(&fixed), (65_535, 131_072));

        let adaptive = PoolConfig {
            http2_initial_stream_window_size: 65_535,
            http2_initial_connection_window_size: 131_072,
            http2_adaptive_window: true,
            ..PoolConfig::default()
        };
        assert_eq!(
            h2_window_sizes(&adaptive),
            (ADAPTIVE_STREAM_WINDOW_SIZE, ADAPTIVE_CONNECTION_WINDOW_SIZE)
        );
    }

    #[test]
    fn pool_key_includes_ports_dns_svid_and_effective_pool_config() {
        let pool_config = PoolConfig {
            idle_timeout_seconds: 12,
            enable_http_keep_alive: false,
            enable_http2: true,
            http2_connections_per_host: 3,
            tcp_keepalive_seconds: 22,
            http2_keep_alive_interval_seconds: 33,
            http2_keep_alive_timeout_seconds: 44,
            http2_initial_stream_window_size: 65_535,
            http2_initial_connection_window_size: 131_072,
            http2_adaptive_window: false,
            http2_max_frame_size: 16_384,
            http2_max_concurrent_streams: None,
            ..PoolConfig::default()
        };
        let pinned_peer =
            crate::identity::SpiffeId::new("spiffe://cluster.local/ns/default/sa/orders")
                .expect("valid spiffe id");
        let key = pool_key_owned(
            "orders.default.svc.cluster.local",
            8080,
            15008,
            Some("10.0.0.2"),
            "0123456789abcdef",
            Some(&pinned_peer),
            &pool_config,
        );
        assert_eq!(
            key,
            "hbone|orders.default.svc.cluster.local|8080|15008|10.0.0.2|0123456789abcdef|spiffe://cluster.local/ns/default/sa/orders|pool=0,1,22,33,44,65535,131072,0,16384,none"
        );
        // An unpinned dial must not share a connection with a pinned one.
        let unpinned_key = pool_key_owned(
            "orders.default.svc.cluster.local",
            8080,
            15008,
            Some("10.0.0.2"),
            "0123456789abcdef",
            None,
            &pool_config,
        );
        assert_ne!(
            key, unpinned_key,
            "pinned-peer identity is connection identity and must partition the pool"
        );
    }

    #[test]
    fn pool_key_changes_when_per_proxy_pool_overrides_change() {
        let base_config = PoolConfig::default();
        let overridden_config = PoolConfig {
            // A genuine connection-affecting H2 setting (still part of the key
            // after pool-management policy was dropped from it).
            http2_initial_stream_window_size: base_config.http2_initial_stream_window_size + 1,
            ..base_config.clone()
        };

        let base_key = pool_key_owned(
            "orders.default.svc.cluster.local",
            8080,
            15008,
            None,
            "fingerprint",
            None,
            &base_config,
        );
        let overridden_key = pool_key_owned(
            "orders.default.svc.cluster.local",
            8080,
            15008,
            None,
            "fingerprint",
            None,
            &overridden_config,
        );

        assert_ne!(
            base_key, overridden_key,
            "HBONE pools with different effective per-proxy H2 sizing must not share senders"
        );
    }

    #[test]
    fn pool_key_ignores_pool_management_policy() {
        // F19: idle_timeout_seconds and http2_connections_per_host are
        // pool-management policy, not connection identity. Two proxies that
        // differ ONLY in those must produce the SAME key so they can share an
        // established mTLS connection to the same sidecar.
        let base_config = PoolConfig::default();
        let policy_only_config = PoolConfig {
            idle_timeout_seconds: base_config.idle_timeout_seconds + 100,
            http2_connections_per_host: base_config.http2_connections_per_host + 5,
            ..base_config.clone()
        };
        let base_key = pool_key_owned(
            "orders.default.svc.cluster.local",
            8080,
            15008,
            None,
            "fingerprint",
            None,
            &base_config,
        );
        let policy_only_key = pool_key_owned(
            "orders.default.svc.cluster.local",
            8080,
            15008,
            None,
            "fingerprint",
            None,
            &policy_only_config,
        );
        assert_eq!(
            base_key, policy_only_key,
            "HBONE pool key must not be fragmented by idle-timeout / per-host-cap policy"
        );
    }

    #[test]
    fn idle_maintenance_removes_unreachable_empty_keys() {
        let pool_config = PoolConfig {
            idle_timeout_seconds: 1,
            ..PoolConfig::default()
        };
        let pool = HboneConnectionPool::new(
            pool_config,
            DnsCache::new(DnsConfig::default()),
            Arc::new(ArcSwap::new(Arc::new(None))),
            4,
        );

        pool.entries.insert(
            "hbone|old|8080|15008||oldfingerprint".to_string(),
            Vec::new(),
        );

        pool.maybe_prune_idle_entries();

        assert!(
            pool.entries.is_empty(),
            "map-level idle maintenance should drop keys with no live senders"
        );
    }

    #[test]
    fn idle_maintenance_prunes_orphaned_creation_locks() {
        let pool_config = PoolConfig {
            idle_timeout_seconds: 1,
            ..PoolConfig::default()
        };
        let pool = HboneConnectionPool::new(
            pool_config,
            DnsCache::new(DnsConfig::default()),
            Arc::new(ArcSwap::new(Arc::new(None))),
            4,
        );
        let stale_key = "hbone|stale|8080|15008||oldfingerprint".to_string();
        let active_key = "hbone|active|8080|15008||oldfingerprint".to_string();
        let active_lock = Arc::new(Mutex::new(()));
        let active_ref = active_lock.clone();

        pool.creation_locks
            .insert(stale_key.clone(), Arc::new(Mutex::new(())));
        pool.creation_locks
            .insert(active_key.clone(), active_lock.clone());

        pool.maybe_prune_idle_entries();

        assert!(!pool.creation_locks.contains_key(&stale_key));
        assert!(
            pool.creation_locks.contains_key(&active_key),
            "in-flight creation locks with external references must survive pruning"
        );

        drop(active_ref);
        drop(active_lock);
        pool.last_idle_prune_unix_secs.store(0, Ordering::Relaxed);
        pool.maybe_prune_idle_entries();

        assert!(!pool.creation_locks.contains_key(&active_key));
    }

    #[tokio::test]
    async fn coalesced_creation_lock_wait_obeys_connect_timeout() {
        let pool_config = PoolConfig {
            idle_timeout_seconds: 60,
            ..PoolConfig::default()
        };
        let pool = HboneConnectionPool::new(
            pool_config.clone(),
            DnsCache::new(DnsConfig::default()),
            Arc::new(ArcSwap::new(Arc::new(None))),
            4,
        );
        let proxy = test_proxy(10);
        let key = pool_key_owned(
            "orders.default.svc.cluster.local",
            8080,
            ISTIO_HBONE_PORT,
            None,
            "fingerprint",
            None,
            &pool_config,
        );
        let creation_lock = Arc::new(Mutex::new(()));
        let _held_guard = creation_lock.lock().await;
        pool.creation_locks
            .insert(key.clone(), creation_lock.clone());

        let started = Instant::now();
        let err = pool
            .get_or_create_sender(
                &proxy,
                "orders.default.svc.cluster.local",
                8080,
                ISTIO_HBONE_PORT,
                None,
                &key,
                &pool_config,
            )
            .await
            .expect_err("coalesced lock wait should time out");

        assert!(
            started.elapsed() < Duration::from_secs(1),
            "lock wait must respect backend_connect_timeout_ms instead of queueing indefinitely"
        );
        match err {
            HbonePoolError::ConnectStream { authority, message } => {
                assert_eq!(authority, "orders.default.svc.cluster.local:8080");
                assert!(message.contains("waiting to coalesce HBONE HTTP/2 sender creation"));
            }
            other => panic!("expected ConnectStream timeout, got {other:?}"),
        }
    }

    #[test]
    fn idle_expiration_uses_last_used_time() {
        let now: u64 = 1_000_000;

        assert!(
            entry_idle_expired(now - 2, 1, now),
            "entries idle longer than the timeout should expire"
        );
        assert!(
            !entry_idle_expired(now, 1, now),
            "freshly used entries should stay in the pool"
        );
        assert!(
            !entry_idle_expired(now - 60, 0, now),
            "zero idle timeout disables idle pruning"
        );
    }

    #[test]
    fn fingerprint_uses_first_eight_sha256_bytes_of_leaf_cert() {
        let td = TrustDomain::new("cluster.local").unwrap();
        let bundle = SvidBundle {
            spiffe_id: SpiffeId::from_parts(&td, "ns/default/sa/gateway").unwrap(),
            cert_chain_der: vec![b"leaf-cert".to_vec(), b"intermediate".to_vec()],
            private_key_pkcs8_der: Vec::new(),
            trust_bundles: TrustBundleSet::local_only(TrustBundle {
                trust_domain: td,
                x509_authorities: vec![],
                jwt_authorities: vec![],
                refresh_hint_seconds: None,
            }),
        };

        let expected_digest = Sha256::digest(b"leaf-cert");
        let mut expected = String::new();
        for byte in expected_digest[..8].iter() {
            let _ = write!(expected, "{byte:02x}");
        }

        assert_eq!(svid_fingerprint(&bundle).unwrap(), expected);
    }

    #[test]
    fn capability_failure_excludes_per_request_connect_failures() {
        let rejected = HbonePoolError::ConnectRejected {
            authority: "orders.default.svc.cluster.local:8080".to_string(),
            status: 403,
        };
        assert!(
            !rejected.is_capability_failure(),
            "policy or workload-level CONNECT rejection must not downgrade HBONE support"
        );

        let stream_failure = HbonePoolError::ConnectStream {
            authority: "orders.default.svc.cluster.local:8080".to_string(),
            message: "stream reset".to_string(),
        };
        assert!(
            !stream_failure.is_capability_failure(),
            "a single CONNECT stream failure should not mark the sidecar HBONE-unsupported"
        );

        let h2_failure = HbonePoolError::H2Handshake {
            host: "orders.default.svc.cluster.local".to_string(),
            message: "ALPN mismatch".to_string(),
        };
        assert!(
            h2_failure.is_capability_failure(),
            "pre-CONNECT HTTP/2 establishment failure is a capability signal"
        );
    }

    #[test]
    fn with_hbone_pool_key_matches_pool_key_owned() {
        let pool_config = PoolConfig::default();
        let owned = pool_key_owned("host", 8080, 15008, None, "fp", None, &pool_config);
        let via_callback =
            with_hbone_pool_key("host", 8080, 15008, None, "fp", None, &pool_config, |key| {
                key.to_string()
            });
        assert_eq!(owned, via_callback);
    }

    #[test]
    fn read_path_returns_none_on_empty_and_missing_keys() {
        let pool = HboneConnectionPool::new(
            PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            Arc::new(ArcSwap::new(Arc::new(None))),
            4,
        );
        assert!(pool.try_cached_sender_read("missing").is_none());
        pool.entries.insert("empty".to_string(), Vec::new());
        assert!(pool.try_cached_sender_read("empty").is_none());
    }

    #[test]
    fn connect_phase_reset_classifies_as_refused() {
        let reset = HbonePoolError::Connect {
            addr: "127.0.0.1:15008".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset"),
        };
        assert_eq!(reset.error_class(), ErrorClass::ConnectionRefused);

        let timed_out = HbonePoolError::Connect {
            addr: "127.0.0.1:15008".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out"),
        };
        assert_eq!(timed_out.error_class(), ErrorClass::ConnectionTimeout);
    }
}
