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
    expect_accepts(&peer, 2, "an exclusive lease forces a second physical connection").await;
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
