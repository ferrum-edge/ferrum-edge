//! The bounded Sidecar-ingress Unix backend connection pool (issue #3731).
//!
//! Pooling is only acceptable if it cannot weaken the admission contract
//! `unix_backend_tests.rs` proves for a single dial. These tests therefore
//! assert the pool's *identity* behavior rather than its throughput:
//!
//! * a lease is exclusive while held and reusable only after check-in;
//! * a replaced socket file retires every connection admitted against the old
//!   `(dev, ino, owner)` — before any further request byte;
//! * an inadmissible path fails closed and never yields a lease;
//! * `http1` and `h2c` on ONE socket never share a physical connection;
//! * bounds (idle ceiling, idle timeout) and drain are honored.
//!
//! The peers here accept and hold the connection without speaking HTTP. That is
//! sufficient and deliberate: hyper's HTTP/1.1 client handshake is local (it
//! writes nothing and waits for nothing), so these tests exercise the pool's
//! admission/identity/lease logic without depending on an application protocol.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use chrono::Utc;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, Proxy};
use ferrum_edge::proxy::unix_backend::UnixBackendError;
use ferrum_edge::proxy::unix_backend_pool::UnixBackendConnectionPool;

/// Accepts every connection and holds it open, counting acceptances so a test
/// can tell "reused a pooled connection" from "dialed a new one".
struct HoldingPeer {
    accepts: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl HoldingPeer {
    fn bind(path: &Path) -> Self {
        let listener = tokio::net::UnixListener::bind(path).expect("bind unix socket");
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_task = Arc::clone(&accepts);
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        accepts_task.fetch_add(1, Ordering::SeqCst);
                        // Hold the accepted end so the client side stays open.
                        held.push(stream);
                    }
                    Err(_) => return,
                }
            }
        });
        Self { accepts, task }
    }

    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }
}

impl Drop for HoldingPeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// `connect(2)` on a Unix socket completes as soon as the connection is queued
/// in the listen backlog, so the peer's `accept()` is not synchronous with the
/// client's checkout. Wait for the exact expected count rather than sampling.
async fn expect_accepts(peer: &HoldingPeer, expected: usize, what: &str) {
    for _ in 0..200 {
        if peer.accepts() >= expected {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(peer.accepts(), expected, "{what}");
}

/// macOS temp dirs live behind `/var` → `/private/var`, so the configured root
/// must be the canonical one or containment rejects every path under it.
fn root_dir(temp: &tempfile::TempDir) -> PathBuf {
    temp.path().canonicalize().expect("canonicalize temp dir")
}

fn roots(root: &Path) -> Vec<String> {
    vec![root.to_str().expect("utf-8 root").to_string()]
}

fn test_proxy(id: &str) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: Some("/".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "127.0.0.1".to_string(),
        backend_port: 15006,
        backend_path: None,
        strip_listen_path: false,
        preserve_host_header: true,
        backend_connect_timeout_ms: 2_000,
        backend_read_timeout_ms: 30_000,
        backend_write_timeout_ms: 30_000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
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
        upstream_id: Some("unix-upstream".to_string()),
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
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
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn pool(pool_config: PoolConfig) -> Arc<UnixBackendConnectionPool> {
    Arc::new(UnixBackendConnectionPool::new(pool_config, 8))
}

fn default_pool() -> Arc<UnixBackendConnectionPool> {
    pool(PoolConfig::default())
}

/// The core reuse claim: a checked-in lease is handed back out instead of
/// costing another `connect(2)`, and the backend sees exactly one acceptance.
#[tokio::test]
async fn a_checked_in_http1_lease_is_reused_instead_of_redialed() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-reuse");

    let first = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("first checkout dials an admitted connection");
    assert!(
        !first.reused(),
        "the very first checkout cannot be a pool hit"
    );
    expect_accepts(&peer, 1, "one physical connection so far").await;
    pool.checkin_h1(first);

    let second = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("second checkout reuses the idle lease");
    assert!(
        second.reused(),
        "a checked-in, still-live connection must be reused"
    );
    expect_accepts(&peer, 1, "reuse must not open a second physical connection").await;

    let stats = pool.stats();
    assert_eq!(stats.physical_connects, 1);
    assert_eq!(stats.hits, 1);
    assert_eq!(stats.misses, 1);
}

/// A lease that is NOT checked in is not in the idle set, so a concurrent
/// checkout must dial its own connection. That exclusivity is what keeps two
/// requests from interleaving on one HTTP/1.1 connection.
#[tokio::test]
async fn an_outstanding_http1_lease_is_exclusive() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-exclusive");

    let held = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("first checkout");
    let concurrent = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("second checkout while the first is held");

    assert!(
        !concurrent.reused(),
        "an outstanding lease must never be handed to a second caller"
    );
    expect_accepts(
        &peer,
        2,
        "an exclusive lease forces a second physical connection",
    )
    .await;
    drop(held);
    drop(concurrent);
}

/// THE security claim. Replacing the socket file changes `(dev, ino)`, so every
/// connection admitted against the old object must be retired at the next
/// checkout — the caller gets a freshly admitted connection to the NEW object
/// and no request byte can reach the old peer.
#[tokio::test]
async fn replacing_the_socket_retires_every_connection_admitted_to_the_old_inode() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let original = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-swap");

    let lease = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("first checkout");
    pool.checkin_h1(lease);
    assert_eq!(pool.stats().idle_h1_connections, 1);

    // Swap the filesystem object at the same path: same name, new inode.
    drop(original);
    std::fs::remove_file(&socket).ok();
    let replacement = HoldingPeer::bind(&socket);

    let after_swap = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout after the swap re-admits and re-dials");
    assert!(
        !after_swap.reused(),
        "a connection admitted against the REPLACED inode must never be handed out"
    );
    expect_accepts(
        &replacement,
        1,
        "the post-swap request must reach the new object, dialed fresh",
    )
    .await;
    assert!(
        pool.stats().identity_retirements >= 1,
        "the swap must be recorded as an identity retirement"
    );
}

/// Fail closed: an inadmissible path yields no lease at all, so there is nothing
/// to pool and nothing to send bytes over.
#[tokio::test]
async fn an_out_of_root_socket_never_yields_a_lease() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let allowed = root.join("allowed");
    std::fs::create_dir_all(&allowed).expect("create allowed root");
    let outside = root.join("outside.sock");
    let _peer = HoldingPeer::bind(&outside);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-containment");

    let result = pool
        .checkout_h1(
            &proxy,
            outside.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&allowed),
            &[],
        )
        .await;
    assert!(
        matches!(result, Err(UnixBackendError::InadmissiblePath(_))),
        "a socket outside the containment allowlist must be refused, not pooled"
    );
    assert_eq!(
        pool.stats().idle_h1_connections,
        0,
        "a refused checkout must leave nothing pooled"
    );
}

/// Two proxies on ONE socket are different security identities, so they must not
/// share a physical connection even though the path, inode, and owner match.
#[tokio::test]
async fn distinct_proxy_identities_do_not_share_a_connection() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let first_proxy = test_proxy("unix-pool-proxy-a");
    let second_proxy = test_proxy("unix-pool-proxy-b");

    let lease = pool
        .checkout_h1(
            &first_proxy,
            socket.to_str().expect("utf-8"),
            first_proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("proxy A checkout");
    pool.checkin_h1(lease);

    let other = pool
        .checkout_h1(
            &second_proxy,
            socket.to_str().expect("utf-8"),
            second_proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("proxy B checkout");
    assert!(
        !other.reused(),
        "proxy B must not inherit proxy A's admitted connection"
    );
    expect_accepts(&peer, 2, "each proxy identity dials its own connection").await;
}

/// The idle set is bounded per identity. Exceeding the ceiling evicts rather
/// than growing without limit.
#[tokio::test]
async fn the_idle_set_is_bounded_by_max_idle_per_host() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = HoldingPeer::bind(&socket);
    let mut pool_config = PoolConfig::default();
    pool_config.max_idle_per_host = 2;
    let pool = pool(pool_config);
    let proxy = test_proxy("unix-pool-bounds");

    let mut leases = Vec::new();
    for _ in 0..4 {
        leases.push(
            pool.checkout_h1(
                &proxy,
                socket.to_str().expect("utf-8"),
                proxy.backend_connect_timeout_ms,
                &roots(&root),
                &[],
            )
            .await
            .expect("checkout"),
        );
    }
    for lease in leases {
        pool.checkin_h1(lease);
    }

    assert_eq!(
        pool.stats().idle_h1_connections,
        2,
        "the idle set must never exceed the configured per-identity ceiling"
    );
}

/// Shutdown / config replacement must be able to retire everything deterministically.
#[tokio::test]
async fn force_drain_retires_every_pooled_connection() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-drain");

    let lease = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout");
    pool.checkin_h1(lease);
    assert_eq!(pool.stats().idle_h1_connections, 1);

    pool.force_drain_all();
    assert_eq!(
        pool.stats().idle_h1_connections,
        0,
        "a drain must leave no pooled connection behind"
    );

    let after_drain = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout after drain");
    assert!(
        !after_drain.reused(),
        "every post-drain checkout must be a fresh, freshly admitted dial"
    );
    expect_accepts(&peer, 2, "a post-drain checkout dials a new connection").await;
}

/// An h2c checkout on a peer that never sends SETTINGS must fail inside the
/// establishment budget rather than pinning the caller — and must leave nothing
/// pooled, so the next request re-admits from scratch.
#[tokio::test]
async fn h2c_checkout_fails_closed_when_the_peer_never_speaks_http2() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let mut proxy = test_proxy("unix-pool-h2c");
    proxy.backend_connect_timeout_ms = 300;

    let started = std::time::Instant::now();
    let result = pool
        .checkout_h2c(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await;
    assert!(
        result.is_err(),
        "a peer that accepts but never sends SETTINGS must not yield a usable h2c carrier"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the h2c establishment must be bounded by the connect budget, not open-ended"
    );
    assert_eq!(
        pool.stats().active_h2c_connections,
        0,
        "a failed handshake must leave no carrier pooled"
    );
    assert!(
        pool.stats().setup_failures >= 1,
        "a failed establishment must be counted as a pool setup failure"
    );
}

/// Accepts every connection and immediately closes it, so the client side sees
/// a peer hangup on a connection it believes is idle.
struct ClosingPeer {
    accepts: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl ClosingPeer {
    fn bind(path: &Path) -> Self {
        let listener = tokio::net::UnixListener::bind(path).expect("bind unix socket");
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_task = Arc::clone(&accepts);
        let task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        accepts_task.fetch_add(1, Ordering::SeqCst);
                        drop(stream);
                    }
                    Err(_) => return,
                }
            }
        });
        Self { accepts, task }
    }

    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }
}

impl Drop for ClosingPeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Poll until `condition` holds or the bounded attempts run out.
async fn wait_until(mut condition: impl FnMut() -> bool, what: &str) {
    for _ in 0..200 {
        if condition() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("{what}");
}

/// A STREAMING response's carrier is returned to the idle pool when — and only
/// when — its body reaches clean end-of-stream. This is the #3731 contract the
/// `ProxyBody` terminal arm invokes.
#[tokio::test]
async fn a_streaming_lease_returns_the_carrier_on_clean_eof() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-streaming-eof");

    let checkout = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout");
    let lease = UnixBackendConnectionPool::streaming_lease(&pool, checkout);
    assert_eq!(
        pool.stats().idle_h1_connections,
        0,
        "a lease held by a streaming body must NOT be in the idle set"
    );

    lease.release_on_clean_eof();
    wait_until(
        || pool.stats().idle_h1_connections == 1,
        "a clean end-of-stream must return the carrier to the idle pool",
    )
    .await;

    let reused = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout after the streaming body completed");
    assert!(
        reused.reused(),
        "the carrier returned at end-of-stream must be the one handed to the next request"
    );
    expect_accepts(
        &peer,
        1,
        "streaming reuse must not open a second connection",
    )
    .await;
}

/// Every abnormal streaming terminal — body error, client disconnect, an early
/// body drop, a fired deadline, shutdown — reaches the pool as a DROPPED lease.
/// A dropped lease must retire its carrier, never pool it.
#[tokio::test]
async fn a_streaming_lease_dropped_before_eof_retires_the_carrier() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-streaming-abort");

    let checkout = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout");
    let lease = UnixBackendConnectionPool::streaming_lease(&pool, checkout);
    drop(lease);

    assert_eq!(
        pool.stats().idle_h1_connections,
        0,
        "a lease dropped before end-of-stream must never enter the idle set"
    );
    let next = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout after the aborted stream");
    assert!(
        !next.reused(),
        "an aborted streaming exchange must not leave a reusable connection behind"
    );
    expect_accepts(
        &peer,
        2,
        "the aborted carrier is retired, so the next request dials",
    )
    .await;
}

/// A peer that hangs up on an idle pooled connection must never have that
/// connection handed to a later request.
#[tokio::test]
async fn a_carrier_closed_by_the_peer_is_never_reused() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = ClosingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-peer-close");

    let lease = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout");
    pool.checkin_h1(lease);

    // The hangup is observed by hyper's connection driver, not synchronously by
    // the check-in, so converge on it: keep returning the lease to the pool
    // until a checkout stops reporting reuse. Once the driver marks the sender
    // closed, both `checkin_h1` and `take_idle_h1` drop it and the next checkout
    // is a freshly admitted dial.
    let mut observed_fresh_dial = false;
    for _ in 0..200 {
        let lease = pool
            .checkout_h1(
                &proxy,
                socket.to_str().expect("utf-8"),
                proxy.backend_connect_timeout_ms,
                &roots(&root),
                &[],
            )
            .await
            .expect("checkout while the peer hangup propagates");
        if !lease.reused() {
            observed_fresh_dial = true;
            break;
        }
        pool.checkin_h1(lease);
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        observed_fresh_dial,
        "a connection the peer closed must be evicted, not handed out"
    );
    wait_until(
        || peer.accepts() >= 2,
        "a closed carrier forces a freshly admitted dial",
    )
    .await;
}

/// Graceful shutdown is terminal: a response body that reaches end-of-stream
/// during the drain must retire its carrier rather than repopulate a pool that
/// nobody will drain again.
#[tokio::test]
async fn shutdown_drain_latches_the_pool_closed_against_a_late_checkin() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-shutdown");

    let inflight = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout");
    let lease = UnixBackendConnectionPool::streaming_lease(&pool, inflight);

    pool.shutdown_drain();
    lease.release_on_clean_eof();

    // Give a would-be check-in every chance to land before asserting it did not.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        pool.stats().idle_h1_connections,
        0,
        "a check-in racing the shutdown drain must not repopulate the pool"
    );
}

/// Config publication must retire carriers whose target no longer exists, and
/// must leave live ones alone. Exact identity comparison, never substring.
#[tokio::test]
async fn retain_live_targets_retires_only_withdrawn_unix_targets() {
    use ferrum_edge::proxy::unix_backend_pool::{UnixTargetIdentity, UnixWireProtocol};

    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let kept_socket = root.join("kept.sock");
    let withdrawn_socket = root.join("withdrawn.sock");
    let _kept_peer = HoldingPeer::bind(&kept_socket);
    let _withdrawn_peer = HoldingPeer::bind(&withdrawn_socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-reload");

    for socket in [&kept_socket, &withdrawn_socket] {
        let lease = pool
            .checkout_h1(
                &proxy,
                socket.to_str().expect("utf-8"),
                proxy.backend_connect_timeout_ms,
                &roots(&root),
                &[],
            )
            .await
            .expect("checkout");
        pool.checkin_h1(lease);
    }
    assert_eq!(pool.stats().idle_h1_connections, 2);

    let mut live = std::collections::HashSet::new();
    live.insert(UnixTargetIdentity {
        namespace: proxy.namespace.clone(),
        proxy_id: proxy.id.clone(),
        upstream_id: proxy.upstream_id.clone(),
        configured_path: kept_socket.to_str().expect("utf-8").to_string(),
        protocol: UnixWireProtocol::Http1,
    });
    pool.retain_live_targets(&live);

    assert_eq!(
        pool.stats().idle_h1_connections,
        1,
        "publication must retire exactly the carrier whose target was withdrawn"
    );
    let kept = pool
        .checkout_h1(
            &proxy,
            kept_socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout on the surviving target");
    assert!(
        kept.reused(),
        "a target that is still published must keep its pooled carrier"
    );
    let withdrawn = pool
        .checkout_h1(
            &proxy,
            withdrawn_socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout on the re-added target");
    assert!(
        !withdrawn.reused(),
        "a withdrawn target must not leave a reusable carrier behind"
    );
}

/// Build the live-target set for `proxy` over `socket`, the shape
/// `collect_live_unix_target_identities` produces for a published config that
/// still declares this HTTP/1.1 Unix target.
fn live_http1_set(
    proxy: &Proxy,
    socket: &Path,
) -> std::collections::HashSet<ferrum_edge::proxy::unix_backend_pool::UnixTargetIdentity> {
    use ferrum_edge::proxy::unix_backend_pool::{UnixTargetIdentity, UnixWireProtocol};

    let mut live = std::collections::HashSet::new();
    live.insert(UnixTargetIdentity {
        namespace: proxy.namespace.clone(),
        proxy_id: proxy.id.clone(),
        upstream_id: proxy.upstream_id.clone(),
        configured_path: socket.to_str().expect("utf-8").to_string(),
        protocol: UnixWireProtocol::Http1,
    });
    live
}

/// THE #3764 blocker. A checked-out HTTP/1.1 lease is deliberately absent from
/// the idle map, so `retain_live_targets` cannot see it. When the exchange
/// finishes — cleanly, on a healthy connection whose socket file was never
/// touched — the check-in must still refuse to repopulate the pool, because the
/// identity it would be pooled under no longer exists in configuration.
#[tokio::test]
async fn a_lease_held_across_a_withdrawal_cannot_repopulate_the_pool() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-withdrawal-fence");

    // In flight when the withdrawal lands: checked out, never checked in.
    let inflight = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout");
    assert_eq!(
        pool.stats().idle_h1_connections,
        0,
        "a checked-out lease is not in the idle map, which is exactly why \
         publication cannot retire it directly"
    );

    // The published config no longer declares this target at all.
    pool.retain_live_targets(&std::collections::HashSet::new());

    // The response reaches clean EOF only now. The socket object is unchanged
    // and the connection is live, so nothing but the fence can stop this.
    pool.checkin_h1(inflight);
    assert_eq!(
        pool.stats().idle_h1_connections,
        0,
        "a check-in from an exchange that outlived its target's withdrawal must \
         not repopulate the pool"
    );
    assert!(
        pool.stats().withdrawal_fenced_checkins >= 1,
        "the refusal must be attributed to the withdrawal fence"
    );

    // And nothing withdrawn is handed to the next request.
    let next = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout after the withdrawal");
    assert!(
        !next.reused(),
        "no carrier from the withdrawn incarnation may be reused"
    );
    expect_accepts(&peer, 2, "the post-withdrawal request dials fresh").await;
}

/// Same-key ABA. A withdrawal followed by a re-add of the EXACT same identity
/// restores set membership, so a membership test alone would let a lease from
/// the previous incarnation back in. The lease is bound to a publication
/// generation, not to a name, so it stays out.
#[tokio::test]
async fn a_lease_from_a_previous_incarnation_cannot_re_enter_after_a_same_identity_re_add() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-aba");

    let inflight = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout");

    // Withdraw, then re-add the identical tuple.
    pool.retain_live_targets(&std::collections::HashSet::new());
    pool.retain_live_targets(&live_http1_set(&proxy, &socket));

    pool.checkin_h1(inflight);
    assert_eq!(
        pool.stats().idle_h1_connections,
        0,
        "a lease from the incarnation that was withdrawn must not re-enter the \
         pool just because the same identity was published again"
    );
    assert!(pool.stats().withdrawal_fenced_checkins >= 1);

    let next = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout on the re-added target");
    assert!(
        !next.reused(),
        "the re-added target must start from a freshly admitted dial"
    );
    expect_accepts(&peer, 2, "the re-added target dials its own connection").await;
}

/// The fence must not break ordinary pooling: a lease taken AFTER a publication
/// and checked in with no intervening publication is the current generation, so
/// it is pooled and reused exactly as before.
#[tokio::test]
async fn a_current_generation_checkin_is_still_pooled_and_reused() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-current-generation");

    // Publication first: this target is live.
    pool.retain_live_targets(&live_http1_set(&proxy, &socket));
    let generation = pool.publication_generation();

    let lease = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout");
    assert_eq!(
        lease.generation(),
        generation,
        "a lease must be bound to the generation current at checkout"
    );
    pool.checkin_h1(lease);

    assert_eq!(
        pool.stats().idle_h1_connections,
        1,
        "an unfenced check-in must still pool its carrier"
    );
    assert_eq!(
        pool.stats().withdrawal_fenced_checkins,
        0,
        "no publication intervened, so nothing may be fenced"
    );
    let reused = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout");
    assert!(reused.reused(), "the pooled carrier must be handed back out");
    expect_accepts(&peer, 1, "reuse must not open a second physical connection").await;
}

/// The interleaving a single-shot fence cannot catch: the check-in reads a live
/// generation, publication then bumps it AND completes its retirement pass, and
/// only afterwards does the check-in insert. The post-insert half of the fence
/// has to withdraw exactly the entry it just inserted.
///
/// Driven through `_test_support`, which runs the publication inside the
/// production check-in's own pre-read/insert window — not a re-implementation
/// of it.
#[tokio::test]
async fn a_checkin_that_inserts_after_the_retirement_pass_withdraws_its_own_entry() {
    use ferrum_edge::_test_support::checkin_unix_h1_with_publication_between;

    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-fence-race");

    let inflight = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout");

    let racing_pool = Arc::clone(&pool);
    checkin_unix_h1_with_publication_between(&pool, inflight, || {
        // The whole publication — generation bump AND retirement pass — lands
        // here, after the check-in already decided its generation was current
        // and before it inserts anything for the pass to find.
        racing_pool.retain_live_targets(&std::collections::HashSet::new());
    });

    assert_eq!(
        pool.stats().idle_h1_connections,
        0,
        "an insert that lands after the retirement pass must be withdrawn by the \
         post-insert half of the fence"
    );
    assert!(
        pool.stats().withdrawal_fenced_checkins >= 1,
        "the withdrawn entry must be attributed to the fence"
    );
    let next = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout after the raced publication");
    assert!(
        !next.reused(),
        "the raced carrier must not survive as a reusable connection"
    );
    expect_accepts(&peer, 2, "the next request dials fresh").await;
}

/// A protocol flip on the SAME path is a different identity, so the previous
/// carrier must be retired by publication rather than silently kept alive.
#[tokio::test]
async fn retain_live_targets_retires_a_protocol_flip_on_the_same_path() {
    use ferrum_edge::proxy::unix_backend_pool::{UnixTargetIdentity, UnixWireProtocol};

    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-protocol-flip");

    let lease = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout");
    pool.checkin_h1(lease);

    // The same path, the same proxy — but the listener now declares h2c.
    let mut live = std::collections::HashSet::new();
    live.insert(UnixTargetIdentity {
        namespace: proxy.namespace.clone(),
        proxy_id: proxy.id.clone(),
        upstream_id: proxy.upstream_id.clone(),
        configured_path: socket.to_str().expect("utf-8").to_string(),
        protocol: UnixWireProtocol::H2c,
    });
    pool.retain_live_targets(&live);

    assert_eq!(
        pool.stats().idle_h1_connections,
        0,
        "an http -> http2 flip must retire the HTTP/1.1 carrier admitted under the old protocol"
    );
}

/// Accepts, completes the HTTP/2 connection preface with a well-formed empty
/// `SETTINGS` frame, holds the connection briefly, then closes it — the shape a
/// local app takes when it drains an h2c connection (GOAWAY / close) while the
/// gateway still has the multiplexed carrier pooled.
struct SettingsThenClosePeer {
    accepts: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl SettingsThenClosePeer {
    fn bind(path: &Path, hold: std::time::Duration) -> Self {
        let listener = tokio::net::UnixListener::bind(path).expect("bind unix socket");
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_task = Arc::clone(&accepts);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                accepts_task.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;

                    // RFC 9113 §6.5: length 0, type 0x4 (SETTINGS), no flags,
                    // stream 0. Structurally valid and semantically empty.
                    const EMPTY_SETTINGS: [u8; 9] = [0, 0, 0, 0x4, 0, 0, 0, 0, 0];
                    if stream.write_all(&EMPTY_SETTINGS).await.is_err() {
                        return;
                    }
                    let _ = stream.flush().await;
                    tokio::time::sleep(hold).await;
                    drop(stream);
                });
            }
        });
        Self { accepts, task }
    }

    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }
}

impl Drop for SettingsThenClosePeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// An h2c carrier that the application closed must be replaced on the next
/// checkout rather than handed out again. The multiplexed sender is shared, so
/// a dead one would otherwise fail every concurrent RPC riding it.
#[tokio::test]
async fn a_closed_h2c_carrier_is_replaced_on_the_next_checkout() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = SettingsThenClosePeer::bind(&socket, std::time::Duration::from_millis(400));
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-h2c-close");

    // Converge rather than assume timing: keep checking out until the pool has
    // had to establish a SECOND physical connection, which can only happen once
    // the first carrier is observed closed. A checkout that fails because the
    // peer closed mid-handshake is fine — the next accept opens a fresh window.
    let mut replaced = false;
    for _ in 0..300 {
        let _ = pool
            .checkout_h2c(
                &proxy,
                socket.to_str().expect("utf-8"),
                proxy.backend_connect_timeout_ms,
                &roots(&root),
                &[],
            )
            .await;
        if pool.stats().physical_connects >= 2 {
            replaced = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        replaced,
        "a closed h2c carrier must be evicted and re-established, not reused"
    );
    assert!(
        peer.accepts() >= 2,
        "the replacement must be a freshly admitted physical connection"
    );
}

/// The shared h2c carrier is published into the pool at the END of a dial that
/// can itself straddle a publication, so it carries the same fence. A
/// withdrawal must leave nothing multiplexable behind for the next RPC.
#[tokio::test]
async fn a_withdrawn_h2c_target_retains_no_shared_carrier() {
    use ferrum_edge::proxy::unix_backend_pool::{UnixTargetIdentity, UnixWireProtocol};

    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    // Long enough to hold the carrier open for the whole test.
    let _peer = SettingsThenClosePeer::bind(&socket, std::time::Duration::from_secs(30));
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-h2c-withdrawal");

    let sender = pool
        .checkout_h2c(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("h2c checkout against a peer that completed its preface");
    drop(sender);
    assert_eq!(
        pool.stats().active_h2c_connections,
        1,
        "a completed h2c establishment publishes exactly one shared carrier"
    );

    // The same path is now declared HTTP/1.1, so the h2c identity is withdrawn.
    let mut live = std::collections::HashSet::new();
    live.insert(UnixTargetIdentity {
        namespace: proxy.namespace.clone(),
        proxy_id: proxy.id.clone(),
        upstream_id: proxy.upstream_id.clone(),
        configured_path: socket.to_str().expect("utf-8").to_string(),
        protocol: UnixWireProtocol::Http1,
    });
    pool.retain_live_targets(&live);

    assert_eq!(
        pool.stats().active_h2c_connections,
        0,
        "a withdrawn h2c identity must retain no shared carrier for the next RPC"
    );
}
