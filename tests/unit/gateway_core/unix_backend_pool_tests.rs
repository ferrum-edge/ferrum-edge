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
use ferrum_edge::backend_conn_limit::BackendConnectionLimitExceeded;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, Proxy};
use ferrum_edge::proxy::unix_backend::{MAX_UNIX_CONNECT_TIMEOUT_MS, UnixBackendError};
use ferrum_edge::proxy::unix_backend_pool::{UnixBackendConnectionPool, UnixWireProtocol};
use ferrum_edge::retry::ErrorClass;
use ferrum_edge::util::unix_socket::{AdmittedUnixSocket, admit_socket_for_connect};

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
        pending_limit_scope: None,
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

/// A pool with the per-target physical-connection bound DISABLED (`0`), so a
/// test that is not about the bound never trips over it.
fn pool(pool_config: PoolConfig) -> Arc<UnixBackendConnectionPool> {
    Arc::new(UnixBackendConnectionPool::new(pool_config, 8, 0))
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
    let pool_config = PoolConfig {
        max_idle_per_host: 2,
        ..PoolConfig::default()
    };
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

    // Race the late check-in against the drain. `join!` polls the drain first,
    // so the latch and the carrier retirement are already done when the lease
    // is released — the exact interleaving the latch exists for. Releasing it
    // inside the join (rather than after) also lets the checked-out carrier's
    // driver end, so the drain's bounded reap resolves promptly instead of
    // spending its whole budget on a connection the test is still holding.
    tokio::join!(pool.shutdown_drain(), async {
        lease.release_on_clean_eof();
    });

    // Give a would-be check-in every chance to land before asserting it did not.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let stats = pool.stats();
    assert_eq!(
        stats.idle_h1_connections, 0,
        "a check-in racing the shutdown drain must not repopulate the pool"
    );
    assert_eq!(
        stats.open_physical_connections, 0,
        "the bounded drain must reap every physical connection driver it owns"
    );
}

/// Config publication must retire carriers whose target no longer exists, and
/// must leave live ones alone. Exact identity comparison, never substring.
#[tokio::test]
async fn retain_live_targets_retires_only_withdrawn_unix_targets() {
    use ferrum_edge::proxy::unix_backend_pool::UnixTargetIdentity;

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
    use ferrum_edge::proxy::unix_backend_pool::UnixTargetIdentity;

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
    assert!(
        reused.reused(),
        "the pooled carrier must be handed back out"
    );
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

/// Build the live-target set for `proxy` over `socket` as an h2c declaration.
fn live_h2c_set(
    proxy: &Proxy,
    socket: &Path,
) -> std::collections::HashSet<ferrum_edge::proxy::unix_backend_pool::UnixTargetIdentity> {
    use ferrum_edge::proxy::unix_backend_pool::UnixTargetIdentity;

    let mut live = std::collections::HashSet::new();
    live.insert(UnixTargetIdentity {
        namespace: proxy.namespace.clone(),
        proxy_id: proxy.id.clone(),
        upstream_id: proxy.upstream_id.clone(),
        configured_path: socket.to_str().expect("utf-8").to_string(),
        protocol: UnixWireProtocol::H2c,
    });
    live
}

/// THE #3764 round-3 blocker. A two-read check-in fence still makes the
/// old-generation entry VISIBLE between its insert and its own cleanup. A
/// checkout that lands in exactly that window used to pop it and hand it out
/// under the caller's generation — laundering a carrier out of a superseded
/// incarnation into a new request.
///
/// Driven through the production check-in's own seams: the publication lands in
/// the pre-insert window, and the checkout runs after the insert (with the
/// shard guard already released) and before the fence's cleanup.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_checkout_in_the_post_insert_window_refuses_the_stale_carrier() {
    use ferrum_edge::_test_support::checkin_unix_h1_with_checkout_after_insert;

    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-visibility-window");

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

    let publishing = Arc::clone(&pool);
    let publish_proxy = proxy.clone();
    let publish_socket = socket.clone();
    let racing = Arc::clone(&pool);
    let race_proxy = proxy.clone();
    let race_socket = socket.clone();
    let race_roots = roots(&root);
    let observed_reuse = Arc::new(AtomicUsize::new(usize::MAX));
    let observed_in_hook = Arc::clone(&observed_reuse);

    checkin_unix_h1_with_checkout_after_insert(
        &pool,
        inflight,
        move || {
            // A publication lands in the pre-insert window. The identity STAYS
            // declared, so the pass leaves this key in place:
            // the only thing standing between the racing checkout and a
            // superseded carrier is the entry's own publication token.
            publishing.retain_live_targets(&live_http1_set(&publish_proxy, &publish_socket));
        },
        move || {
            // The entry is in the idle map right now, still stamped with the
            // superseded generation, and the fence's cleanup has not run.
            let taken = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(racing.checkout_h1(
                    &race_proxy,
                    race_socket.to_str().expect("utf-8"),
                    race_proxy.backend_connect_timeout_ms,
                    &race_roots,
                    &[],
                ))
            })
            .expect("a checkout in the visibility window still succeeds, by dialing");
            observed_in_hook.store(usize::from(taken.reused()), Ordering::SeqCst);
        },
    );

    assert_eq!(
        observed_reuse.load(Ordering::SeqCst),
        0,
        "a checkout inside the after-insert/before-cleanup window must refuse the \
         superseded carrier instead of adopting it under its own generation"
    );
    assert_eq!(
        pool.stats().idle_h1_connections,
        0,
        "nothing from the superseded generation may be left pooled"
    );
    assert!(
        pool.stats().withdrawal_fenced_checkins >= 1,
        "the refusal must be attributed to the fence"
    );
    expect_accepts(
        &peer,
        2,
        "the racing request had to dial its own connection",
    )
    .await;
}

/// A withdraw/re-add of the SAME identity is a DISCONTINUITY, not continuity.
///
/// The withdrawal lands while this key has no slot at all, so only the
/// live-set snapshot moves. A check-in that already
/// passed its live-set read then creates the slot and inserts its
/// PRE-WITHDRAWAL carrier. The re-add that follows sees a byte-identical
/// identity tuple under a live key: treating "declared now" as proof of
/// continuity would restamp that entry to the current generation, and a
/// checkout racing the losing cleanup would then find a current token and reuse
/// a carrier from the previous incarnation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_same_identity_readd_refuses_a_carrier_inserted_during_the_absence() {
    use ferrum_edge::_test_support::checkin_unix_h1_with_checkout_after_insert;

    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-readd-discontinuity");

    // A fresh lease captured at the publication generation current now. Nothing
    // is pooled for this key, so no slot exists for the withdrawal pass to
    // inspect.
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
        "the slotless precondition: this key has no reusable entry"
    );

    let withdrawing = Arc::clone(&pool);
    let readding = Arc::clone(&pool);
    let readd_proxy = proxy.clone();
    let readd_socket = socket.clone();
    let racing = Arc::clone(&pool);
    let race_proxy = proxy.clone();
    let race_socket = socket.clone();
    let race_roots = roots(&root);
    let observed_reuse = Arc::new(AtomicUsize::new(usize::MAX));
    let observed_in_hook = Arc::clone(&observed_reuse);

    checkin_unix_h1_with_checkout_after_insert(
        &pool,
        inflight,
        move || {
            // The identity is withdrawn AFTER this check-in read the live set.
            // No slot exists, so the insert below creates one after the
            // withdrawal pass has finished.
            withdrawing.retain_live_targets(&std::collections::HashSet::new());
        },
        move || {
            // The exact same identity tuple is declared again while the
            // superseded entry is visible and the fence's cleanup has not run.
            readding.retain_live_targets(&live_http1_set(&readd_proxy, &readd_socket));
            let taken = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(racing.checkout_h1(
                    &race_proxy,
                    race_socket.to_str().expect("utf-8"),
                    race_proxy.backend_connect_timeout_ms,
                    &race_roots,
                    &[],
                ))
            })
            .expect("a checkout for the re-added incarnation still succeeds, by dialing");
            observed_in_hook.store(usize::from(taken.reused()), Ordering::SeqCst);
        },
    );

    assert_eq!(
        observed_reuse.load(Ordering::SeqCst),
        0,
        "a re-added incarnation must begin with a freshly admitted carrier: the entry \
         inserted during the absence may not be restamped into the new generation"
    );
    assert_eq!(
        pool.stats().idle_h1_connections,
        0,
        "nothing inserted across the withdraw/re-add discontinuity may stay pooled"
    );
    expect_accepts(
        &peer,
        2,
        "the re-added incarnation had to dial its own connection",
    )
    .await;
}

/// The exact-entry removal id still matters: the losing side of the fence must
/// withdraw ITS entry and never a newer sibling pooled for the same key while
/// it was racing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_losing_cleanup_withdraws_only_its_own_entry() {
    use ferrum_edge::_test_support::checkin_unix_h1_with_checkout_after_insert;

    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-sibling-entry");

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

    let publishing = Arc::clone(&pool);
    let publish_proxy = proxy.clone();
    let publish_socket = socket.clone();
    let sibling_pool = Arc::clone(&pool);
    let sibling_proxy = proxy.clone();
    let sibling_socket = socket.clone();
    let sibling_roots = roots(&root);

    checkin_unix_h1_with_checkout_after_insert(
        &pool,
        inflight,
        move || {
            publishing.retain_live_targets(&live_http1_set(&publish_proxy, &publish_socket));
        },
        move || {
            // A sibling carrier for the SAME key, dialed and pooled under the
            // CURRENT generation while the fenced entry is still visible.
            // `checkout_fresh_h1` bypasses the idle set, so this does not
            // consume the entry the cleanup is about to look for.
            let fresh = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(sibling_pool.checkout_fresh_h1(
                    &sibling_proxy,
                    sibling_socket.to_str().expect("utf-8"),
                    sibling_proxy.backend_connect_timeout_ms,
                    &sibling_roots,
                    &[],
                ))
            })
            .expect("a fresh dial for the same key");
            sibling_pool.checkin_h1(fresh);
        },
    );

    assert_eq!(
        pool.stats().idle_h1_connections,
        1,
        "the fence must withdraw exactly its own entry, leaving the newer sibling"
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
    assert!(
        reused.reused(),
        "the sibling carrier was pooled under the current generation and stays reusable"
    );
    expect_accepts(&peer, 2, "only the fenced entry's dial and the sibling's").await;
}

/// A publication that does NOT withdraw an identity must leave its idle
/// carriers reusable — the entry token is advanced by the pass, not discarded.
/// Without that, every unrelated reload would empty the whole pool.
#[tokio::test]
async fn a_publication_that_keeps_an_identity_preserves_its_idle_carrier() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-retained-carrier");

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

    // Three unrelated publications, each declaring this identity.
    for _ in 0..3 {
        pool.retain_live_targets(&live_http1_set(&proxy, &socket));
    }
    assert_eq!(
        pool.stats().idle_h1_connections,
        1,
        "a continuously-live identity keeps its idle carrier across publications"
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
    assert!(
        reused.reused(),
        "the retained carrier must still be handed out after the publications"
    );
    expect_accepts(&peer, 1, "no publication may force a redial here").await;
}

/// The withdraw/re-add discontinuity is decided PER IDENTITY. A neighbouring
/// identity churning through a withdrawal and a re-add must not cost a
/// continuously-live identity its pooled carrier — the repair may not degenerate
/// into draining the pool whenever any publication changes anything.
#[tokio::test]
async fn a_neighbours_withdraw_and_readd_leaves_a_continuously_live_carrier_pooled() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    // Two proxies over one socket are two distinct identities, so they get two
    // distinct pool keys and two independent liveness verdicts.
    let steady = test_proxy("unix-pool-steady-neighbour");
    let churning = test_proxy("unix-pool-churning-neighbour");
    let both = {
        let mut set = live_http1_set(&steady, &socket);
        set.extend(live_http1_set(&churning, &socket));
        set
    };

    for proxy in [&steady, &churning] {
        let lease = pool
            .checkout_h1(
                proxy,
                socket.to_str().expect("utf-8"),
                proxy.backend_connect_timeout_ms,
                &roots(&root),
                &[],
            )
            .await
            .expect("checkout");
        pool.checkin_h1(lease);
    }
    pool.retain_live_targets(&both);
    assert_eq!(pool.stats().idle_h1_connections, 2);

    // The neighbour is withdrawn and then re-added under the same tuple.
    pool.retain_live_targets(&live_http1_set(&steady, &socket));
    pool.retain_live_targets(&both);

    assert_eq!(
        pool.stats().idle_h1_connections,
        1,
        "the churning identity loses its carrier; the steady one keeps its own"
    );
    let reused = pool
        .checkout_h1(
            &steady,
            socket.to_str().expect("utf-8"),
            steady.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout");
    assert!(
        reused.reused(),
        "a continuously-live identity must still hand out its pooled carrier after a \
         neighbour's withdrawal and re-add"
    );
    let redialed = pool
        .checkout_h1(
            &churning,
            socket.to_str().expect("utf-8"),
            churning.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout");
    assert!(
        !redialed.reused(),
        "the re-added incarnation must dial afresh rather than inherit the carrier it \
         held before the withdrawal"
    );
    expect_accepts(
        &peer,
        3,
        "two initial dials plus the re-added incarnation's fresh dial",
    )
    .await;
}

/// A request routed by a SUPERSEDED request epoch can still dial a withdrawn
/// target, and its lease is bound to the CURRENT generation — so neither half
/// of the generation fence sees anything wrong with it. The published live-set
/// snapshot is what refuses it.
#[tokio::test]
async fn a_checkin_for_a_withdrawn_identity_is_refused_after_the_withdrawal() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-live-set-withdrawal");

    // Something is pooled for this identity when the withdrawal lands, so the
    // retirement pass can see and remove the key.
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
    pool.retain_live_targets(&std::collections::HashSet::new());
    assert_eq!(pool.stats().idle_h1_connections, 0);

    // A late request from the superseded epoch: dialed AFTER the withdrawal, so
    // its lease carries the current generation.
    let late = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("a superseded-epoch request may still dial");
    assert_eq!(
        late.generation(),
        pool.publication_generation(),
        "this lease is NOT fenced by generation — config liveness is the guard"
    );
    pool.checkin_h1(late);

    assert_eq!(
        pool.stats().idle_h1_connections,
        0,
        "an identity the published config no longer declares must retain no \
         reusable carrier, even from a dial that started after the withdrawal"
    );
    expect_accepts(&peer, 2, "two dials, neither of them pooled").await;
}

/// A long-lived application socket must not pin one empty map slot for every
/// logical proxy identity that configuration has ever withdrawn. The live-set
/// snapshot and generation fence reject late check-ins without retaining that
/// duplicated per-key state.
#[tokio::test]
async fn withdrawals_reclaim_empty_key_slots_while_the_socket_stays_live() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = default_pool();

    for generation in 0..8 {
        let proxy = test_proxy(&format!("unix-pool-retired-identity-{generation}"));
        pool.retain_live_targets(&live_http1_set(&proxy, &socket));
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
        assert_eq!(pool.resident_key_slots(), (1, 0));

        pool.retain_live_targets(&std::collections::HashSet::new());
        assert_eq!(
            pool.resident_key_slots(),
            (0, 0),
            "withdrawing generation {generation} must reclaim its empty key even though the \
             admitted socket inode is still live"
        );
    }

    expect_accepts(&peer, 8, "one fresh dial for each logical identity").await;
}

/// A withdrawal with no carrier and therefore no per-key slot still has to be
/// authoritative. A late request pinned to the superseded request epoch may
/// finish on its freshly admitted connection, but that connection must not
/// become reusable under an identity absent from the current config.
#[tokio::test]
async fn a_withdrawal_without_an_existing_slot_still_refuses_a_late_checkin() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-slotless-withdrawal");

    // No checkout has occurred, so neither pool map has a key to inspect.
    pool.retain_live_targets(&std::collections::HashSet::new());
    let late = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("a superseded-epoch request may finish its admitted dial");
    pool.checkin_h1(late);

    assert_eq!(
        pool.stats().idle_h1_connections,
        0,
        "the published live-set snapshot must refuse the late carrier even \
         though the withdrawal found no slot"
    );
    assert!(pool.stats().withdrawal_fenced_checkins >= 1);
}

/// Post-swap pool maintenance may overlap even though config swaps themselves
/// are serialized. Once generation 2 has withdrawn the target, generation 1
/// resuming late must not restore generation 1's older live-set verdict.
#[tokio::test]
async fn an_older_config_reconcile_cannot_overwrite_a_newer_live_set() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-ordered-publication");

    pool.retain_live_targets_for_publication(2, &std::collections::HashSet::new());
    pool.retain_live_targets_for_publication(1, &live_http1_set(&proxy, &socket));

    let late = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("a stale request may finish its admitted dial");
    pool.checkin_h1(late);

    assert_eq!(
        pool.stats().idle_h1_connections,
        0,
        "the older reconcile must be ignored after a newer withdrawal"
    );
}

/// The h2c half of the slotless-withdrawal rule: even when no key existed for
/// the retirement pass to inspect, a shared carrier established for a
/// withdrawn identity serves the RPC it was dialed for and nothing after it.
#[tokio::test]
async fn an_h2c_carrier_dialed_after_a_slotless_withdrawal_is_not_published() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = SettingsThenClosePeer::bind(&socket, std::time::Duration::from_secs(30));
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-h2c-live-set-withdrawal");

    // No checkout has occurred, so there is no h2c key to inspect.
    pool.retain_live_targets(&std::collections::HashSet::new());
    assert_eq!(pool.stats().active_h2c_connections, 0);

    let late = pool
        .checkout_h2c(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("a superseded-epoch RPC may still dial");
    drop(late);
    assert_eq!(
        pool.stats().active_h2c_connections,
        0,
        "a withdrawn h2c identity must retain nothing multiplexable"
    );
}

/// The h2c equivalent of the H1 visibility window: a publication lands during
/// the dial, the carrier is published carrying the superseded token, and the
/// PRODUCTION selector must refuse it while it is still visible.
#[tokio::test]
async fn the_h2c_selector_refuses_a_carrier_published_under_a_superseded_generation() {
    use ferrum_edge::_test_support::{
        checkout_unix_h2c_with_publication_hooks, unix_pool_shared_h2c_selector_yields_carrier,
    };

    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = SettingsThenClosePeer::bind(&socket, std::time::Duration::from_secs(30));
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-h2c-visibility-window");

    let publishing = Arc::clone(&pool);
    let publish_proxy = proxy.clone();
    let publish_socket = socket.clone();
    let observing = Arc::clone(&pool);
    let observe_proxy = proxy.clone();
    let observe_socket = socket.clone();
    let observe_roots = roots(&root);
    let visible_but_refused = Arc::new(AtomicUsize::new(usize::MAX));
    let observed_in_hook = Arc::clone(&visible_but_refused);

    let sender = checkout_unix_h2c_with_publication_hooks(
        &pool,
        &proxy,
        socket.to_str().expect("utf-8"),
        proxy.backend_connect_timeout_ms,
        &roots(&root),
        &[],
        (
            move || {
                // A publication lands during the dial. The identity stays
                // declared and — because nothing is pooled for this key yet —
                // there is no entry to re-stamp.
                publishing.retain_live_targets(&live_h2c_set(&publish_proxy, &publish_socket));
            },
            move || {
                // The carrier IS in the shared map at this instant.
                let visible = observing.stats().active_h2c_connections;
                let yielded = unix_pool_shared_h2c_selector_yields_carrier(
                    &observing,
                    &observe_proxy,
                    observe_socket.to_str().expect("utf-8"),
                    &observe_roots,
                    &[],
                );
                observed_in_hook.store(usize::from(visible == 1 && !yielded), Ordering::SeqCst);
            },
        ),
    )
    .await
    .expect("h2c checkout still returns the sender it dialed");
    drop(sender);

    assert_eq!(
        visible_but_refused.load(Ordering::SeqCst),
        1,
        "the carrier is visible in the shared map but the production selector must \
         refuse to multiplex a new RPC onto a superseded-generation carrier"
    );
    assert_eq!(
        pool.stats().active_h2c_connections,
        0,
        "and the fence's cleanup removes it"
    );
}

/// The h2c half of the withdraw/re-add discontinuity. The withdrawal lands
/// after this publish read the live set and while no h2c slot exists for the
/// key, so the superseded carrier still reaches the
/// shared map. A re-add of the byte-identical identity must not adopt it: the
/// production selector may not multiplex a new RPC onto a carrier that predates
/// the absence.
#[tokio::test]
async fn the_h2c_publish_is_not_adopted_by_a_same_identity_readd() {
    use ferrum_edge::_test_support::{
        checkout_unix_h2c_with_publication_hooks, unix_pool_shared_h2c_selector_yields_carrier,
    };

    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = SettingsThenClosePeer::bind(&socket, std::time::Duration::from_secs(30));
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-h2c-readd-discontinuity");

    let withdrawing = Arc::clone(&pool);
    let readding = Arc::clone(&pool);
    let readd_proxy = proxy.clone();
    let readd_socket = socket.clone();
    let observing = Arc::clone(&pool);
    let observe_proxy = proxy.clone();
    let observe_socket = socket.clone();
    let observe_roots = roots(&root);
    let yielded_after_readd = Arc::new(AtomicUsize::new(usize::MAX));
    let observed_in_hook = Arc::clone(&yielded_after_readd);

    let sender = checkout_unix_h2c_with_publication_hooks(
        &pool,
        &proxy,
        socket.to_str().expect("utf-8"),
        proxy.backend_connect_timeout_ms,
        &roots(&root),
        &[],
        (
            move || {
                // Withdrawn after this checkout's live-set read, and with no
                // h2c slot for the key, so the publish below still creates a
                // slot after the withdrawal pass has finished and inserts.
                withdrawing.retain_live_targets(&std::collections::HashSet::new());
            },
            move || {
                // The same identity tuple is declared again while the
                // superseded carrier is visible and the fence cleanup has not
                // run. It must not become multiplexable.
                readding.retain_live_targets(&live_h2c_set(&readd_proxy, &readd_socket));
                let yielded = unix_pool_shared_h2c_selector_yields_carrier(
                    &observing,
                    &observe_proxy,
                    observe_socket.to_str().expect("utf-8"),
                    &observe_roots,
                    &[],
                );
                observed_in_hook.store(usize::from(yielded), Ordering::SeqCst);
            },
        ),
    )
    .await
    .expect("h2c checkout still returns the sender it dialed");
    drop(sender);

    assert_eq!(
        yielded_after_readd.load(Ordering::SeqCst),
        0,
        "a re-added h2c incarnation must not inherit a carrier published during its \
         absence, however byte-identical the identity tuple is"
    );
    assert_eq!(
        pool.stats().active_h2c_connections,
        0,
        "and nothing from the previous incarnation is left multiplexable"
    );
}

/// A protocol flip on the SAME path is a different identity, so the previous
/// carrier must be retired by publication rather than silently kept alive.
#[tokio::test]
async fn retain_live_targets_retires_a_protocol_flip_on_the_same_path() {
    use ferrum_edge::proxy::unix_backend_pool::UnixTargetIdentity;

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
    use ferrum_edge::proxy::unix_backend_pool::UnixTargetIdentity;

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

// ---------------------------------------------------------------------------
// Issue #3731/#3764: the per-target physical-connection bound, driver
// ownership, the single establishment deadline, and the exported metric
// surface.
// ---------------------------------------------------------------------------

/// A pool whose per-target physical-connection bound is `max`
/// (`FERRUM_MESH_UNIX_INGRESS_MAX_CONNECTIONS`).
fn bounded_pool(max: u32) -> Arc<UnixBackendConnectionPool> {
    let pool = UnixBackendConnectionPool::new(PoolConfig::default(), 8, max);
    Arc::new(pool)
}

/// Resolve the admitted identity of `socket` the way a checkout does, so a test
/// can read the pool's per-target slot count for the exact lane a dial used.
fn admitted(socket: &Path, root: &Path) -> AdmittedUnixSocket {
    admit_socket_for_connect(socket.to_str().expect("utf-8"), &roots(root), &[])
        .expect("the fixture socket is admissible")
}

/// A new physical connection is admitted against the target's bound, and the
/// refusal is decided BEFORE `connect(2)` — the backend never accepts a socket
/// for the request that was refused.
#[tokio::test]
async fn a_new_physical_connection_is_refused_at_the_target_bound() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = bounded_pool(1);
    let proxy = test_proxy("unix-pool-bound");

    let held = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("the first physical connection is under the bound");
    expect_accepts(&peer, 1, "one physical connection so far").await;
    assert_eq!(
        pool.open_connections_for_target(
            &proxy,
            socket.to_str().expect("utf-8"),
            &admitted(&socket, &root),
            UnixWireProtocol::Http1,
        ),
        1,
        "the pooled carrier must hold exactly one slot on its target's lane"
    );

    // The lease is exclusive, so a concurrent checkout is a MISS and needs a
    // second physical connection — which the bound must refuse.
    let refused = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await;
    let err = expect_refusal(
        refused,
        "an over-bound dial must be refused with the typed limit error",
    );
    let UnixBackendError::BackendConnectionLimit(limit) = err else {
        panic!("an over-bound dial must be refused with the typed limit error, got {err:?}");
    };
    assert_eq!(limit.cap, 1);
    assert_eq!(limit.current, 1);
    let typed = UnixBackendError::BackendConnectionLimit(BackendConnectionLimitExceeded {
        current: 1,
        cap: 1,
    });
    assert_eq!(
        typed.error_class(),
        ErrorClass::BackendConnectionLimit,
        "an over-bound refusal stays pre-wire and health-neutral"
    );
    // Refused BEFORE connect: the peer never saw a second acceptance.
    expect_accepts(&peer, 1, "an over-bound refusal must not open a socket").await;
    assert!(
        pool.stats().checkout_failures >= 1,
        "a pre-dial refusal is a checkout failure, not a setup failure"
    );

    drop(held);
}

/// `0` is the explicit opt-out: nothing is bounded and no lane is ever
/// allocated, so an operator who disables the bound pays nothing for it.
#[tokio::test]
async fn a_zero_bound_admits_every_connection_and_allocates_no_lane() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = bounded_pool(0);
    let proxy = test_proxy("unix-pool-unbounded");

    let mut held = Vec::new();
    for _ in 0..3 {
        let checkout = pool
            .checkout_h1(
                &proxy,
                socket.to_str().expect("utf-8"),
                proxy.backend_connect_timeout_ms,
                &roots(&root),
                &[],
            )
            .await
            .expect("a disabled bound refuses nothing");
        held.push(checkout);
    }
    expect_accepts(&peer, 3, "three exclusive leases are three connections").await;
    assert_eq!(
        pool.resident_connection_lanes(),
        0,
        "a disabled bound must not touch the lane map at all"
    );
    assert_eq!(pool.stats().checkout_failures, 0);
}

/// Reuse of an already-admitted carrier takes NO second slot, so a target
/// pinned at a bound of 1 still serves an unbounded number of sequential
/// requests.
#[tokio::test]
async fn reusing_a_pooled_carrier_takes_no_second_connection_slot() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = bounded_pool(1);
    let proxy = test_proxy("unix-pool-bound-reuse");
    let identity = admitted(&socket, &root);

    for _ in 0..3 {
        let checkout = pool
            .checkout_h1(
                &proxy,
                socket.to_str().expect("utf-8"),
                proxy.backend_connect_timeout_ms,
                &roots(&root),
                &[],
            )
            .await
            .expect("a reused carrier is never re-admitted against the bound");
        assert_eq!(
            pool.open_connections_for_target(
                &proxy,
                socket.to_str().expect("utf-8"),
                &identity,
                UnixWireProtocol::Http1,
            ),
            1,
            "reuse must never grow the target's open-connection count"
        );
        pool.checkin_h1(checkout);
    }

    expect_accepts(
        &peer,
        1,
        "three sequential requests share one admitted socket",
    )
    .await;
    let stats = pool.stats();
    assert_eq!(stats.physical_connects, 1);
    assert_eq!(stats.hits, 2);
    assert_eq!(stats.misses, 1);
}

/// Retiring a carrier releases its slot AND evicts the lane, and the target can
/// immediately be re-dialed. The slot is owned by the CONNECTION's driver, not
/// by the request, so this also proves the driver ends when the last sender is
/// dropped.
#[tokio::test]
async fn retiring_a_carrier_releases_its_slot_for_a_later_dial() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = bounded_pool(1);
    let proxy = test_proxy("unix-pool-bound-release");

    let checkout = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("first dial");
    // Dropping the lease without checking it in retires the connection.
    drop(checkout);

    // The driver observes the closed connection asynchronously, so wait for the
    // lane rather than sampling once.
    for _ in 0..200 {
        if pool.resident_connection_lanes() == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        pool.resident_connection_lanes(),
        0,
        "a retired connection must release its slot and evict the now-empty lane"
    );
    assert_eq!(
        pool.stats().open_physical_connections,
        0,
        "the physical-connection gauge must follow the driver's lifetime"
    );

    pool.checkout_h1(
        &proxy,
        socket.to_str().expect("utf-8"),
        proxy.backend_connect_timeout_ms,
        &roots(&root),
        &[],
    )
    .await
    .expect("the freed slot must admit a replacement connection");
    expect_accepts(&peer, 2, "the replacement is a second physical connection").await;
}

/// Two Sidecar `ingress[]` listeners on one workload are distinct pool
/// identities, so they get distinct lanes: one listener at its bound can
/// neither steal the other's capacity nor be refused because of it.
#[tokio::test]
async fn sibling_ingress_listeners_do_not_share_a_connection_lane() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = bounded_pool(1);
    // Sibling materialized ingress proxies: same namespace and same socket,
    // different listener-derived proxy ids.
    let first = test_proxy("__mesh-ingress-checkout-8080");
    let second = test_proxy("__mesh-ingress-checkout-9090");

    let _first_held = pool
        .checkout_h1(
            &first,
            socket.to_str().expect("utf-8"),
            first.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("the first listener is under its own bound");
    let _second_held = pool
        .checkout_h1(
            &second,
            socket.to_str().expect("utf-8"),
            second.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("a sibling listener must not be refused by another listener's lane");
    expect_accepts(&peer, 2, "each listener opened its own connection").await;
    assert_eq!(
        pool.resident_connection_lanes(),
        2,
        "sibling listeners must key separate lanes"
    );

    // Each lane is still enforced on its own.
    let refused = pool
        .checkout_h1(
            &first,
            socket.to_str().expect("utf-8"),
            first.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await;
    assert!(
        matches!(refused, Err(UnixBackendError::BackendConnectionLimit(_))),
        "a listener at its bound must still be refused"
    );
}

/// An `http`-declared and an `http2`-declared listener on ONE socket are
/// different wire protocols, so they never share a lane either — the bound is
/// keyed by the complete transport identity, not by the path.
#[tokio::test]
async fn the_wire_protocol_is_part_of_the_connection_lane() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = HoldingPeer::bind(&socket);
    let pool = bounded_pool(1);
    let proxy = test_proxy("unix-pool-bound-protocol");
    let identity = admitted(&socket, &root);

    let _held = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("http1 dial");

    assert_eq!(
        pool.open_connections_for_target(
            &proxy,
            socket.to_str().expect("utf-8"),
            &identity,
            UnixWireProtocol::Http1,
        ),
        1
    );
    assert_eq!(
        pool.open_connections_for_target(
            &proxy,
            socket.to_str().expect("utf-8"),
            &identity,
            UnixWireProtocol::H2c,
        ),
        0,
        "an h2c listener on the same socket must have its own lane"
    );
}

/// `pool_enable_http_keep_alive = false` is honored literally on HTTP/1.1:
/// nothing is pooled and nothing is reused, so every request is its own
/// admitted connection.
#[tokio::test]
async fn disabling_keep_alive_stops_http1_connection_reuse() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let mut proxy = test_proxy("unix-pool-no-keepalive");
    proxy.pool_enable_http_keep_alive = Some(false);

    for _ in 0..2 {
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
        assert!(
            !checkout.reused(),
            "with keep-alive disabled no checkout may come from the idle set"
        );
        pool.checkin_h1(checkout);
        assert_eq!(
            pool.stats().idle_h1_connections,
            0,
            "a check-in must not pool a carrier when keep-alive is disabled"
        );
    }

    expect_accepts(&peer, 2, "each request gets its own admitted connection").await;
    assert_eq!(pool.stats().hits, 0);
}

/// The default (`None` on the proxy, `true` globally) still reuses, so the flag
/// is a real switch rather than a permanent downgrade.
#[tokio::test]
async fn keep_alive_enabled_by_default_still_reuses() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-default-keepalive");
    assert!(proxy.pool_enable_http_keep_alive.is_none());

    let first = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("first checkout");
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
        .expect("second checkout");
    assert!(second.reused());
    expect_accepts(&peer, 1, "the default posture keeps reusing").await;
}

/// The exported gauges track the maps they describe across check-out, check-in,
/// and a config withdrawal — without scanning anything.
#[tokio::test]
async fn the_exported_gauges_follow_checkout_checkin_and_withdrawal() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-gauges");

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
    let checked_out = pool.stats();
    assert_eq!(
        checked_out.idle_h1_connections, 0,
        "a checked-out carrier is deliberately absent from the idle set"
    );
    assert_eq!(
        checked_out.open_physical_connections, 1,
        "but it is still an OPEN physical connection"
    );

    pool.checkin_h1(checkout);
    let pooled = pool.stats();
    assert_eq!(pooled.idle_h1_connections, 1);
    assert_eq!(pooled.open_physical_connections, 1);

    // Withdraw the identity entirely: the idle gauge must return to zero.
    pool.retain_live_targets(&std::collections::HashSet::new());
    assert_eq!(
        pool.stats().idle_h1_connections,
        0,
        "a withdrawn identity retains no idle carrier, and the gauge must say so"
    );
}

/// Admission, connect, protocol handshake, and the peer's SETTINGS preface all
/// draw on ONE `backend_connect_timeout_ms` budget. A peer that accepts and then
/// goes silent must therefore fail inside roughly one budget, not two or three.
#[tokio::test]
async fn h2c_establishment_spends_one_budget_end_to_end() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    // Accepts and holds the connection without ever speaking h2c.
    let _peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let mut proxy = test_proxy("unix-pool-one-budget");
    let budget_ms = 400u64;
    proxy.backend_connect_timeout_ms = budget_ms;

    let started = std::time::Instant::now();
    let outcome = pool
        .checkout_h2c(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await;
    let elapsed = started.elapsed();

    assert!(
        matches!(outcome, Err(UnixBackendError::H2HandshakeTimeout { .. })),
        "a peer that never sends SETTINGS must time out, got {outcome:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_millis(budget_ms * 2),
        "admission + connect + handshake + preface must share ONE budget; \
         {elapsed:?} exceeds two budgets of {budget_ms}ms"
    );
    assert!(
        pool.stats().setup_failures >= 1,
        "a failed establishment is a setup failure"
    );
}

/// The WebSocket dial hands back what REMAINS of the one establishment budget,
/// so the upgrade exchange cannot start a second full timer.
#[tokio::test]
async fn the_websocket_dial_returns_the_remainder_of_one_budget() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = HoldingPeer::bind(&socket);
    let pool = default_pool();
    let proxy = test_proxy("unix-websocket-one-budget");

    let budget = std::time::Duration::from_millis(750);
    let before = tokio::time::Instant::now();
    let dial = pool
        .dial_websocket_stream(
            &proxy,
            socket.to_str().expect("utf-8"),
            750,
            &roots(&root),
            &[],
        )
        .await
        .expect("an admitted websocket carrier");

    let after = tokio::time::Instant::now();
    let deadline = dial.deadline;

    assert_eq!(dial.timeout_ms, 750);
    // The deadline was opened at SOME instant inside this call — production
    // necessarily reads the clock after `before` — so it lands in
    // `[before + budget, after + budget]` and nowhere else. The upper bound is
    // the load-bearing half: a second timer started once admission and connect
    // had finished would push the deadline past `after + budget`. The lower
    // bound proves the budget was not shortened. Both are exact orderings of
    // monotonic instants, so neither depends on how much wall-clock time the
    // dial actually spent.
    assert!(
        deadline >= before + budget,
        "the ONE budget may not be shortened: {deadline:?} precedes the earliest \
         end the dial could have opened"
    );
    assert!(
        deadline <= after + budget,
        "the returned deadline must be the end of the budget opened INSIDE the dial, \
         not a fresh one started after admission and connect completed"
    );
    // Restated from the upgrade's point of view: what it inherits is the
    // REMAINDER — one budget minus whatever the dial already spent — so it can
    // never be handed more than `budget` no matter how fast the dial was.
    let remaining = deadline.saturating_duration_since(after);
    assert!(
        remaining <= budget,
        "the upgrade exchange may never receive more than the ONE original budget, \
         got {remaining:?} of {budget:?}"
    );
}

/// A dedicated WebSocket bypasses only the idle carrier maps. It must consume
/// the same per-target PHYSICAL connection lane as cold H1/h2c connections,
/// and its lease must keep that lane charged through the whole session.
#[tokio::test]
async fn dedicated_websocket_holds_the_per_target_physical_connection_lane() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = HoldingPeer::bind(&socket);
    let pool = Arc::new(UnixBackendConnectionPool::new(PoolConfig::default(), 8, 1));
    let proxy = test_proxy("unix-websocket-bound");

    let first = pool
        .dial_websocket_stream(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("first websocket dial");
    assert_eq!(
        pool.open_connections_for_target(
            &proxy,
            socket.to_str().expect("utf-8"),
            &first.admitted,
            UnixWireProtocol::Http1,
        ),
        1,
        "the dedicated websocket must hold the target's only lane"
    );
    assert_eq!(pool.stats().open_physical_connections, 1);

    let second = pool
        .dial_websocket_stream(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await;
    assert!(
        matches!(second, Err(UnixBackendError::BackendConnectionLimit(_))),
        "a second dedicated websocket must be refused before connect"
    );

    drop(first);
    assert_eq!(
        pool.stats().open_physical_connections,
        0,
        "dropping the websocket releases its physical-connection gauge"
    );
    assert_eq!(
        pool.resident_connection_lanes(),
        0,
        "the last websocket lease must remove its empty target lane"
    );
}

// ---------------------------------------------------------------------------
// Issue #3764: bounded, terminal driver shutdown.
// ---------------------------------------------------------------------------

/// The forced path: a driver whose carrier is still held by in-flight work
/// cannot end on its own, so the graceful budget expires and the drain must
/// CANCEL it, JOIN it, and return with the pool's accounting settled.
///
/// Cancelling alone is not enough — a cancelled task releases its
/// physical-connection slot and its share of the open-connections gauge only
/// when the runtime drops it — so this asserts the post-drain state directly
/// rather than sleeping and hoping.
#[tokio::test]
async fn a_forced_drain_cancels_reaps_and_settles_every_driver() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = HoldingPeer::bind(&socket);
    let pool = bounded_pool(4);
    let proxy = test_proxy("unix-pool-forced-drain");

    // Held for the whole test: the carrier's sender never drops, so its driver
    // is still running when the graceful budget expires.
    let _held = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout");
    assert_eq!(pool.stats().open_physical_connections, 1);
    assert_eq!(pool.resident_connection_lanes(), 1);

    // A graceful budget too small to matter forces the cancellation branch.
    pool.shutdown_drain_with_budgets(
        std::time::Duration::from_millis(1),
        std::time::Duration::from_secs(5),
    )
    .await;

    let stats = pool.stats();
    assert_eq!(
        stats.open_physical_connections, 0,
        "a cancelled driver must be joined, so the gauge is settled when the drain returns"
    );
    assert_eq!(
        pool.resident_connection_lanes(),
        0,
        "a cancelled driver must release its target's connection slot"
    );
    assert_eq!(
        pool.tracked_drivers(),
        0,
        "the forced path must leave no tracked driver behind"
    );
}

/// The graceful path leaves nothing behind either: a driver that ends while the
/// drain is awaiting it must not re-register a completion sentinel that would
/// survive the drain forever.
#[tokio::test]
async fn a_graceful_drain_leaves_no_tracked_driver_behind() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = HoldingPeer::bind(&socket);
    let pool = bounded_pool(4);
    let proxy = test_proxy("unix-pool-graceful-drain");

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
    // Dropping the lease closes the connection; the driver ends asynchronously,
    // so the drain below races it — deliberately, since that race is what used
    // to strand a completion sentinel in the tracker.
    drop(checkout);

    pool.shutdown_drain().await;

    assert_eq!(
        pool.tracked_drivers(),
        0,
        "a driver that finishes while the drain awaits it must not leave a sentinel"
    );
    assert_eq!(pool.stats().open_physical_connections, 0);
    assert_eq!(pool.resident_connection_lanes(), 0);
}

/// `UnixH1Checkout` and the shared h2c sender are deliberately not `Debug`
/// (they wrap live senders), so a refusal is asserted by consuming the `Ok`
/// arm rather than through `expect_err`.
fn expect_refusal<T>(result: Result<T, UnixBackendError>, what: &str) -> UnixBackendError {
    match result {
        Ok(_) => panic!("{what}"),
        Err(err) => err,
    }
}

/// An HTTP/1.1 checkout that STARTS after the drain is refused before it can
/// dial: the socket is never connected, the target's lane is never reserved,
/// and the caller gets the typed, health-neutral shutdown outcome.
#[tokio::test]
async fn a_post_drain_h1_checkout_is_refused_before_any_connect() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let pool = bounded_pool(4);
    let proxy = test_proxy("unix-pool-post-drain-h1");

    pool.shutdown_drain().await;
    let before = pool.stats().checkout_failures;

    let result = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await;
    let err = expect_refusal(result, "a checkout after the drain must fail closed");

    assert!(
        matches!(err, UnixBackendError::PoolShuttingDown),
        "expected the typed shutdown refusal, got {err}"
    );
    assert_eq!(
        err.error_class(),
        ErrorClass::DispatchPolicyRejected,
        "the gateway shutting down is not evidence about the application, so the \
         refusal must stay health-neutral and unretried"
    );
    assert_eq!(
        peer.accepts(),
        0,
        "the refusal happens before connect(2), so the app never sees a connection"
    );
    assert_eq!(
        pool.resident_connection_lanes(),
        0,
        "a refused checkout must not reserve a slot on the target's bound"
    );
    let stats = pool.stats();
    assert_eq!(stats.open_physical_connections, 0);
    assert_eq!(stats.physical_connects, 0, "nothing was established");
    assert_eq!(
        stats.checkout_failures,
        before + 1,
        "a shutdown refusal is a gateway-side checkout failure, not a setup failure"
    );
    assert_eq!(
        stats.setup_failures, 0,
        "no establishment was attempted, so the app is not charged a setup failure"
    );
    assert_eq!(pool.tracked_drivers(), 0);
}

/// The h2c half of the same gate: the shared-carrier cold path is refused at
/// the same point, so neither wire protocol can dial after the drain.
#[tokio::test]
async fn a_post_drain_h2c_checkout_is_refused_before_any_connect() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = SettingsThenClosePeer::bind(&socket, std::time::Duration::from_secs(30));
    let pool = bounded_pool(4);
    let proxy = test_proxy("unix-pool-post-drain-h2c");

    pool.shutdown_drain().await;

    let result = pool
        .checkout_h2c(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await;
    let err = expect_refusal(result, "an h2c checkout after the drain must fail closed");

    assert!(
        matches!(err, UnixBackendError::PoolShuttingDown),
        "expected the typed shutdown refusal, got {err}"
    );
    assert_eq!(err.error_class(), ErrorClass::DispatchPolicyRejected);
    assert_eq!(
        peer.accepts(),
        0,
        "the refusal happens before connect(2) on this path too"
    );
    assert_eq!(pool.resident_connection_lanes(), 0);
    let stats = pool.stats();
    assert_eq!(stats.active_h2c_connections, 0);
    assert_eq!(stats.open_physical_connections, 0);
    assert_eq!(stats.physical_connects, 0);
    assert_eq!(pool.tracked_drivers(), 0);
}

/// The latch/registration race, driven deterministically rather than polled: a
/// checkout that passed the shutdown gate while the pool was open is parked at
/// the driver-registration boundary, the drain runs to completion, and only
/// then is the checkout released.
///
/// It must refuse — no sender may be handed back for a connection the drain can
/// no longer reap — and every piece of accounting it touched must already be
/// zero when it returns. No sleeping, no retry loop: the assertions run on the
/// instant the racing call returns.
#[tokio::test]
async fn an_h1_checkout_racing_the_shutdown_latch_refuses_and_settles_exactly() {
    use ferrum_edge::_test_support::checkout_unix_h1_with_registration_seam;

    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = HoldingPeer::bind(&socket);
    let pool = bounded_pool(4);
    let proxy = test_proxy("unix-pool-h1-latch-race");
    // Bound, not a temporary: the checkout future below borrows it across the
    // `join!`, so it must outlive the statement that creates the future.
    let allowed_roots = roots(&root);

    let (reached_tx, reached_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let lanes_while_parked = AtomicUsize::new(usize::MAX);
    let gauge_while_parked = AtomicUsize::new(usize::MAX);
    let tracked_after_drain = AtomicUsize::new(usize::MAX);

    let racing_checkout = checkout_unix_h1_with_registration_seam(
        &pool,
        &proxy,
        socket.to_str().expect("utf-8"),
        proxy.backend_connect_timeout_ms,
        &allowed_roots,
        &[],
        || async move {
            let _ = reached_tx.send(());
            let _ = release_rx.await;
        },
    );
    let shutdown = async {
        reached_rx
            .await
            .expect("the racing checkout reaches the registration boundary");
        // Parked AFTER the dial and BEFORE registration: the connection exists
        // and its slot is reserved, but no driver is tracked or charged yet.
        let gauge = pool.stats().open_physical_connections as usize;
        lanes_while_parked.store(pool.resident_connection_lanes(), Ordering::SeqCst);
        gauge_while_parked.store(gauge, Ordering::SeqCst);
        pool.shutdown_drain().await;
        tracked_after_drain.store(pool.tracked_drivers(), Ordering::SeqCst);
        let _ = release_tx.send(());
    };
    let (result, ()) = tokio::join!(racing_checkout, shutdown);

    assert_eq!(
        lanes_while_parked.load(Ordering::SeqCst),
        1,
        "the racing establishment holds its target's connection slot while parked"
    );
    assert_eq!(
        gauge_while_parked.load(Ordering::SeqCst),
        0,
        "registration is what charges the open-connection gauge, and it has not run"
    );
    assert_eq!(
        tracked_after_drain.load(Ordering::SeqCst),
        0,
        "the drain owned no driver for the racing connection"
    );

    let err = expect_refusal(
        result,
        "a checkout that reaches registration after the tracker closed must not hand back a \
         sender whose connection has no driver",
    );
    assert!(
        matches!(err, UnixBackendError::PoolShuttingDown),
        "expected the typed shutdown refusal, got {err}"
    );
    assert_eq!(err.error_class(), ErrorClass::DispatchPolicyRejected);

    let stats = pool.stats();
    assert_eq!(
        stats.open_physical_connections, 0,
        "the losing side never spawned a driver, so the gauge was never charged"
    );
    assert_eq!(
        pool.resident_connection_lanes(),
        0,
        "the refusal releases the target's connection slot before it returns"
    );
    assert_eq!(
        pool.tracked_drivers(),
        0,
        "a closed tracker adopts nothing, and leaves no sentinel or aborted handle"
    );
    assert_eq!(
        stats.physical_connects, 0,
        "an established-then-refused connection is not a completed establishment"
    );
    assert_eq!(
        stats.idle_h1_connections, 0,
        "the pool stays latched: nothing may be pooled after the drain"
    );
}

/// The h2c half of the same race, through the same single registration
/// boundary: the carrier is never published and the sender is never returned.
#[tokio::test]
async fn an_h2c_checkout_racing_the_shutdown_latch_refuses_and_settles_exactly() {
    use ferrum_edge::_test_support::checkout_unix_h2c_with_registration_seam;

    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = SettingsThenClosePeer::bind(&socket, std::time::Duration::from_secs(30));
    let pool = bounded_pool(4);
    let proxy = test_proxy("unix-pool-h2c-latch-race");
    let allowed_roots = roots(&root);

    let (reached_tx, reached_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let lanes_while_parked = AtomicUsize::new(usize::MAX);

    let racing_checkout = checkout_unix_h2c_with_registration_seam(
        &pool,
        &proxy,
        socket.to_str().expect("utf-8"),
        proxy.backend_connect_timeout_ms,
        &allowed_roots,
        &[],
        || async move {
            let _ = reached_tx.send(());
            let _ = release_rx.await;
        },
    );
    let shutdown = async {
        reached_rx
            .await
            .expect("the racing h2c checkout reaches the registration boundary");
        lanes_while_parked.store(pool.resident_connection_lanes(), Ordering::SeqCst);
        pool.shutdown_drain().await;
        let _ = release_tx.send(());
    };
    let (result, ()) = tokio::join!(racing_checkout, shutdown);

    assert_eq!(
        lanes_while_parked.load(Ordering::SeqCst),
        1,
        "the racing h2c establishment holds its target's connection slot while parked"
    );
    let err = expect_refusal(
        result,
        "the h2c race must fail closed rather than return a carrier",
    );
    assert!(
        matches!(err, UnixBackendError::PoolShuttingDown),
        "expected the typed shutdown refusal, got {err}"
    );
    assert_eq!(err.error_class(), ErrorClass::DispatchPolicyRejected);

    let stats = pool.stats();
    assert_eq!(
        stats.active_h2c_connections, 0,
        "a refused registration must never publish a multiplexable carrier"
    );
    assert_eq!(stats.open_physical_connections, 0);
    assert_eq!(stats.physical_connects, 0);
    assert_eq!(pool.resident_connection_lanes(), 0);
    assert_eq!(pool.tracked_drivers(), 0);
}

/// The former force-drain interval, closed: a checkout parked at the
/// registration boundary is released while shutdown is stopped between its
/// latches and the retirement work that follows, and it must STILL refuse.
///
/// Before the repair, `shutdown_drain` set the pool's latch, ran
/// `force_drain_all`, and only then reached the tracker, whose own `closed`
/// flag was set as the FIRST step of the tracker drain rather than with the pool
/// latch. A checkout that had already passed the entry gate could therefore win
/// the tracker mutex inside that interval,
/// register successfully, and go on toward returning a sender while shutdown
/// was in progress. Both latches now land before any retirement runs, so the
/// interval no longer exists. Their ORDER — tracker first, pool store second —
/// is what the sibling test below pins; this one pins the retirement boundary.
///
/// Driven entirely by channel handoffs: the checkout parks at the existing
/// pre-registration seam, shutdown parks at the post-latch seam, and each side
/// releases the other. No sleeping and no polling — the assertions run on the
/// instant the racing call returns.
#[tokio::test]
async fn a_checkout_released_inside_the_former_force_drain_interval_still_refuses() {
    use ferrum_edge::_test_support::{
        checkout_unix_h1_with_registration_seam, shutdown_unix_pool_with_latch_seam,
    };

    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = HoldingPeer::bind(&socket);
    let pool = bounded_pool(4);
    let proxy = test_proxy("unix-pool-force-drain-interval");
    let allowed_roots = roots(&root);

    let (reached_tx, reached_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let (settled_tx, settled_rx) = tokio::sync::oneshot::channel::<()>();
    let tracked_inside = AtomicUsize::new(usize::MAX);
    let gauge_inside = AtomicUsize::new(usize::MAX);
    let idle_inside = AtomicUsize::new(usize::MAX);

    let racing_checkout = async {
        let result = checkout_unix_h1_with_registration_seam(
            &pool,
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &allowed_roots,
            &[],
            || async move {
                let _ = reached_tx.send(());
                let _ = release_rx.await;
            },
        )
        .await;
        // Hands control back to the seam below, which is still holding shutdown
        // inside the interval under test.
        let _ = settled_tx.send(());
        result
    };
    let shutdown = async {
        reached_rx
            .await
            .expect("the racing checkout reaches the registration boundary");
        shutdown_unix_pool_with_latch_seam(
            &pool,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            || async {
                // Both latches are set; nothing has been retired or drained yet.
                // This is exactly where the racing registration used to succeed.
                let _ = release_tx.send(());
                let _ = settled_rx.await;
                let stats = pool.stats();
                tracked_inside.store(pool.tracked_drivers(), Ordering::SeqCst);
                gauge_inside.store(stats.open_physical_connections as usize, Ordering::SeqCst);
                idle_inside.store(stats.idle_h1_connections as usize, Ordering::SeqCst);
            },
        )
        .await;
    };
    let (result, ()) = tokio::join!(racing_checkout, shutdown);

    assert_eq!(
        tracked_inside.load(Ordering::SeqCst),
        0,
        "a registration inside the force-drain interval must be refused, so the tracker adopts \
         nothing there"
    );
    assert_eq!(
        gauge_inside.load(Ordering::SeqCst),
        0,
        "a refused registration never charges the open-connection gauge"
    );
    assert_eq!(
        idle_inside.load(Ordering::SeqCst),
        0,
        "the refusal publishes nothing, so there is nothing for the retirement pass to find"
    );

    let err = expect_refusal(
        result,
        "a checkout released inside the former force-drain interval must not hand back a sender",
    );
    assert!(
        matches!(err, UnixBackendError::PoolShuttingDown),
        "expected the typed shutdown refusal, got {err}"
    );
    assert_eq!(err.error_class(), ErrorClass::DispatchPolicyRejected);

    let stats = pool.stats();
    assert_eq!(stats.open_physical_connections, 0);
    assert_eq!(stats.physical_connects, 0, "nothing was established");
    assert_eq!(stats.idle_h1_connections, 0);
    assert_eq!(stats.active_h2c_connections, 0);
    assert_eq!(
        pool.resident_connection_lanes(),
        0,
        "the refusal releases the target's connection slot before it returns"
    );
    assert_eq!(pool.tracked_drivers(), 0);
}

/// The ORDER of the two shutdown latches, pinned at the only point that can
/// distinguish it from its reverse: inside the interval between them.
///
/// The pool's `shutting_down` flag and the driver tracker's `closed` flag are
/// independent state and cannot be stored atomically, so the boundary rests
/// entirely on which one becomes observable first. Registration is closed
/// FIRST, under the tracker's map lock; the pool's Release store follows. That
/// is what makes "once the pool reads as closed, nothing more can be adopted"
/// true.
///
/// Under the reverse (pool-first) order this test fails twice over: the seam
/// would observe the pool already latched, and the racing checkout — released
/// while the tracker was still open — would win the tracker mutex, register,
/// and return a sender.
///
/// Driven entirely by channel handoffs, with no sleeping and no polling: the
/// checkout parks at the production pre-registration seam and is released from
/// inside the production inter-latch seam, which then waits for it to settle
/// before the pool flag is ever published.
#[tokio::test]
async fn registration_is_already_closed_before_the_pool_latch_is_published() {
    use ferrum_edge::_test_support::{
        checkout_unix_h1_with_registration_seam, shutdown_unix_pool_with_inter_latch_seam,
    };

    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let _peer = HoldingPeer::bind(&socket);
    let pool = bounded_pool(4);
    let proxy = test_proxy("unix-pool-latch-order");
    let allowed_roots = roots(&root);

    let (reached_tx, reached_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let (settled_tx, settled_rx) = tokio::sync::oneshot::channel::<()>();
    // `usize::MAX` is an unreachable sentinel: a seam that never ran cannot be
    // mistaken for one that observed a legitimate zero. The two latch readings
    // record `bool` as 0/1 through the same mechanism.
    let latch_published_on_entry = AtomicUsize::new(usize::MAX);
    let latch_published_after_settle = AtomicUsize::new(usize::MAX);
    let tracked_between = AtomicUsize::new(usize::MAX);
    let gauge_between = AtomicUsize::new(usize::MAX);
    let lanes_between = AtomicUsize::new(usize::MAX);
    let connects_between = AtomicUsize::new(usize::MAX);

    let racing_checkout = async {
        let result = checkout_unix_h1_with_registration_seam(
            &pool,
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &allowed_roots,
            &[],
            || async move {
                let _ = reached_tx.send(());
                let _ = release_rx.await;
            },
        )
        .await;
        // Hands control back to the inter-latch seam, which is still holding
        // shutdown between the two latches.
        let _ = settled_tx.send(());
        result
    };
    let shutdown = async {
        reached_rx
            .await
            .expect("the racing checkout reaches the registration boundary");
        shutdown_unix_pool_with_inter_latch_seam(
            &pool,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            || async {
                // The tracker is closed; the pool flag is NOT stored yet.
                latch_published_on_entry.store(
                    usize::from(pool.shutdown_latch_published()),
                    Ordering::SeqCst,
                );
                let _ = release_tx.send(());
                let _ = settled_rx.await;
                // Still inside the interval: whatever refused the checkout was
                // the tracker's latch, because this one is still unpublished.
                latch_published_after_settle.store(
                    usize::from(pool.shutdown_latch_published()),
                    Ordering::SeqCst,
                );
                let stats = pool.stats();
                tracked_between.store(pool.tracked_drivers(), Ordering::SeqCst);
                gauge_between.store(stats.open_physical_connections as usize, Ordering::SeqCst);
                lanes_between.store(pool.resident_connection_lanes(), Ordering::SeqCst);
                connects_between.store(stats.physical_connects as usize, Ordering::SeqCst);
            },
        )
        .await;
    };
    let (result, ()) = tokio::join!(racing_checkout, shutdown);

    assert_eq!(
        latch_published_on_entry.load(Ordering::SeqCst),
        0,
        "the tracker's registration latch must be closed BEFORE the pool's flag is published"
    );
    assert_eq!(
        latch_published_after_settle.load(Ordering::SeqCst),
        0,
        "the racing checkout settled while the pool flag was still unpublished, so its refusal \
         came from the tracker's latch and not from the pool's entry gate"
    );
    assert_eq!(
        tracked_between.load(Ordering::SeqCst),
        0,
        "a registration released inside the inter-latch interval must adopt nothing"
    );
    assert_eq!(
        gauge_between.load(Ordering::SeqCst),
        0,
        "nothing was spawned, so the open-connection gauge was never charged"
    );
    assert_eq!(
        lanes_between.load(Ordering::SeqCst),
        0,
        "the refusal releases the target's connection slot before the checkout returns"
    );
    assert_eq!(
        connects_between.load(Ordering::SeqCst),
        0,
        "an established-then-refused connection is not a completed establishment"
    );

    let err = expect_refusal(
        result,
        "a checkout released after the tracker closed but before the pool flag is published must \
         still be refused",
    );
    assert!(
        matches!(err, UnixBackendError::PoolShuttingDown),
        "expected the typed shutdown refusal, got {err}"
    );
    assert_eq!(err.error_class(), ErrorClass::DispatchPolicyRejected);

    let stats = pool.stats();
    assert_eq!(stats.open_physical_connections, 0);
    assert_eq!(stats.physical_connects, 0);
    assert_eq!(stats.idle_h1_connections, 0);
    assert_eq!(stats.active_h2c_connections, 0);
    assert_eq!(pool.resident_connection_lanes(), 0);
    assert_eq!(pool.tracked_drivers(), 0);
    assert!(
        pool.shutdown_latch_published(),
        "the drain publishes the pool latch once it leaves the inter-latch interval"
    );
}

/// The one establishment budget is opened at the OUTERMOST checkout entry —
/// before the pool's amortized idle sweep, which scans the pool's maps and
/// `stat`s socket paths (issue #3764).
///
/// Proved by ordering rather than by timing: a `connect_timeout_ms` beyond the
/// defensive `MAX_UNIX_CONNECT_TIMEOUT_MS` ceiling fails deadline creation
/// closed on every platform, and the sweep — which would otherwise have evicted
/// the closed idle carrier this test plants — must therefore not have run.
#[tokio::test]
async fn the_establishment_budget_opens_before_the_idle_sweep() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    // `idle_timeout_seconds: 1` gives the sweep the shortest interval it
    // accepts, so the test waits ~1s rather than the 60s default.
    let pool = pool(PoolConfig {
        idle_timeout_seconds: 1,
        ..PoolConfig::default()
    });
    let proxy = test_proxy("unix-pool-budget-order");

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
    pool.checkin_h1(checkout);
    assert_eq!(pool.stats().idle_h1_connections, 1);

    // Wait past the sweep interval so the NEXT checkout would sweep, and long
    // enough that the pooled entry is idle-expired and would be evicted. Idle
    // age is stored in whole Unix seconds and expires only when age is strictly
    // greater than the configured timeout, so anything below two full seconds
    // is boundary-dependent for a one-second timeout.
    tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;

    let refused = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            MAX_UNIX_CONNECT_TIMEOUT_MS + 1,
            &roots(&root),
            &[],
        )
        .await;
    let err = expect_refusal(
        refused,
        "an establishment budget past the defensive ceiling must fail closed",
    );
    assert!(
        matches!(err, UnixBackendError::ConnectTimeout { .. }),
        "expected the typed connect-timeout refusal, got {err}"
    );
    assert_eq!(
        pool.stats().idle_h1_connections,
        1,
        "the idle sweep must run INSIDE the establishment budget, so a checkout that \
         never opened one cannot have spent time on pool maintenance"
    );

    // Sanity: the expired carrier is not reused once a checkout opens a budget.
    let _replacement = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("checkout");
    expect_accepts(
        &peer,
        2,
        "the expired idle carrier must not have been reused",
    )
    .await;
}

// ---------------------------------------------------------------------------
// Issue #3764: publication must retire idle H1 carriers when effective
// keep-alive/reuse flips off, so a full idle set cannot pin the physical cap.
// ---------------------------------------------------------------------------

/// Wait until retired idle carriers have released their physical-connection
/// slots (driver futures complete after their senders are dropped).
async fn wait_for_open_physical(pool: &UnixBackendConnectionPool, expected: u64) {
    for _ in 0..200 {
        if pool.stats().open_physical_connections == expected {
            return;
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert_eq!(
        pool.stats().open_physical_connections,
        expected,
        "retired carriers must release their physical-connection slots"
    );
}

/// A pool filled to the physical cap under keep-alive=true must retire those
/// idle H1 carriers when publication omits the identity (effective reuse off).
/// The next fresh H1 checkout under reuse-disabled policy is admitted rather
/// than `BackendConnectionLimit`.
#[tokio::test]
async fn publishing_keep_alive_false_retires_a_full_idle_set_and_admits_a_fresh_dial() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let socket = root.join("app.sock");
    let peer = HoldingPeer::bind(&socket);
    let cap = 2u32;
    let pool = bounded_pool(cap);
    let mut proxy = test_proxy("unix-pool-ka-retire-cap");
    // Fill under reuse-enabled (default).
    assert!(proxy.pool_enable_http_keep_alive.is_none());

    let mut leases = Vec::with_capacity(cap as usize);
    for _ in 0..cap {
        let lease = pool
            .checkout_h1(
                &proxy,
                socket.to_str().expect("utf-8"),
                proxy.backend_connect_timeout_ms,
                &roots(&root),
                &[],
            )
            .await
            .expect("fill under the physical cap");
        assert!(!lease.reused());
        leases.push(lease);
    }
    // Keep every checkout live until the cap is full; checking each one in
    // inside the loop would let the next checkout reuse the same carrier and
    // would never construct the full idle set this regression needs.
    for lease in leases {
        pool.checkin_h1(lease);
    }
    assert_eq!(pool.stats().idle_h1_connections, cap as u64);
    assert_eq!(pool.stats().open_physical_connections, cap as u64);

    // Control: with carriers still live, a reuse-disabled miss needs a fresh
    // dial and must hit the bound.
    proxy.pool_enable_http_keep_alive = Some(false);
    let refused = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await;
    assert!(
        matches!(refused, Err(UnixBackendError::BackendConnectionLimit(_))),
        "without publication retirement a full idle set pins every slot"
    );

    // Publication omits the H1 identity (effective keep-alive/reuse off) —
    // the shape `collect_live_unix_target_identities` produces.
    pool.retain_live_targets_for_publication(1, &std::collections::HashSet::new());
    assert_eq!(
        pool.stats().idle_h1_connections,
        0,
        "publication must synchronously retire resident idle H1 carriers"
    );
    wait_for_open_physical(&pool, 0).await;

    let admitted = pool
        .checkout_h1(
            &proxy,
            socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("fresh H1 dial under reuse-disabled must be admitted after retirement");
    assert!(
        !admitted.reused(),
        "reuse-disabled checkout must never come from the idle set"
    );
    assert!(!admitted.keep_alive());
    pool.checkin_h1(admitted);
    assert_eq!(
        pool.stats().idle_h1_connections,
        0,
        "reuse-disabled check-in must never repool the carrier"
    );
    expect_accepts(
        &peer,
        (cap as usize) + 1,
        "fill dials plus the post-retirement fresh dial",
    )
    .await;
}

/// An H1-only reuse disable must not retire a healthy h2c carrier on a sibling
/// identity: protocol is part of the live-identity tuple.
#[tokio::test]
async fn an_h1_reuse_disable_publication_leaves_a_live_h2c_carrier() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let root = root_dir(&temp);
    let h1_socket = root.join("h1.sock");
    let h2c_socket = root.join("h2c.sock");
    let _h1_peer = HoldingPeer::bind(&h1_socket);
    let _h2c_peer = SettingsThenClosePeer::bind(&h2c_socket, std::time::Duration::from_secs(30));
    let pool = default_pool();
    let proxy = test_proxy("unix-pool-ka-h2c-preserved");

    let h1 = pool
        .checkout_h1(
            &proxy,
            h1_socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("h1 checkout");
    pool.checkin_h1(h1);
    let h2c = pool
        .checkout_h2c(
            &proxy,
            h2c_socket.to_str().expect("utf-8"),
            proxy.backend_connect_timeout_ms,
            &roots(&root),
            &[],
        )
        .await
        .expect("h2c checkout");
    drop(h2c);
    assert_eq!(pool.stats().idle_h1_connections, 1);
    assert_eq!(pool.stats().active_h2c_connections, 1);

    // Only the h2c identity remains reusable — H1 keep-alive/reuse off.
    pool.retain_live_targets(&live_h2c_set(&proxy, &h2c_socket));
    assert_eq!(
        pool.stats().idle_h1_connections,
        0,
        "H1 must be retired when omitted from the reusable live set"
    );
    assert_eq!(
        pool.stats().active_h2c_connections,
        1,
        "an H1-only reuse flip must not retire a continuously-live h2c carrier"
    );
}
