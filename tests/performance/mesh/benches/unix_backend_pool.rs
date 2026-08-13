//! Sidecar-ingress Unix backend connection pooling (issue #3731).
//!
//! The question the issue asks is narrow and measurable: what does the gateway
//! pay, per request, for dialing a co-located application's Unix-domain socket
//! and running an HTTP/1.1 client handshake — and how much of that does pooling
//! remove?
//!
//! Both arms call the SAME production entry point,
//! `UnixBackendConnectionPool::checkout_h1`, so the comparison isolates exactly
//! one variable: whether the carrier is returned to the idle set afterwards.
//!
//! * `dial_per_request` never checks the lease back in, so every iteration pays
//!   a fresh admission (`stat` of the path, directory-chain ownership walk,
//!   file type/owner/mode check), a `connect(2)`, a post-connect `(dev, ino)`
//!   re-check, a peer-UID `getsockopt`, a hyper HTTP/1.1 client handshake, and
//!   one spawned connection-driver task. That is the pre-#3731 behaviour, and
//!   it is still the behaviour of any exchange that ends abnormally.
//! * `pooled_reuse` checks the lease back in, so every iteration after the
//!   first is a re-admission plus a `DashMap` hit.
//!
//! Beyond criterion's latency numbers, the harness prints the counters that
//! describe the resource side of the same comparison — physical connections
//! (one file descriptor, one driver task, and one accepted socket on the
//! application each), pool hits/misses, and the backend's own accept count.
//! Those are the FD / task / accept figures the issue asks for; criterion does
//! not model them.
//!
//! NOT part of CI: this crate is standalone and manually driven
//! (`./run.sh unix_backend_pool`), so nothing here can make a required job
//! flaky. There is deliberately no budget/threshold assertion — the point is to
//! record the shape of the win, not to gate on a wall-clock number that depends
//! on the host's filesystem and scheduler.
//!
//! Unix-only. On a non-Unix host the benches are registered but immediately
//! report that there is nothing to measure.

use criterion::{Criterion, criterion_group, criterion_main};

#[cfg(unix)]
mod unix_bench {
    use std::collections::VecDeque;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use chrono::Utc;
    use criterion::{Criterion, black_box};
    use ferrum_edge::config::PoolConfig;
    use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, Proxy};
    use ferrum_edge::proxy::unix_backend_pool::UnixBackendConnectionPool;

    /// A backend that accepts connections and retains at most `retain` of them.
    ///
    /// The cap matters: the dial-per-request arm opens thousands of sockets, and
    /// an unbounded hold would exhaust the process FD limit rather than measure
    /// anything. Retaining the most recent few is also what a real application
    /// does — it closes a peer that went away.
    pub struct BenchPeer {
        accepts: Arc<AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }

    impl BenchPeer {
        pub fn bind(path: &Path, retain: usize) -> Self {
            let listener = tokio::net::UnixListener::bind(path).expect("bind unix socket");
            let accepts = Arc::new(AtomicUsize::new(0));
            let accepts_task = Arc::clone(&accepts);
            let task = tokio::spawn(async move {
                let mut held: VecDeque<tokio::net::UnixStream> = VecDeque::new();
                loop {
                    match listener.accept().await {
                        Ok((stream, _)) => {
                            accepts_task.fetch_add(1, Ordering::Relaxed);
                            held.push_back(stream);
                            while held.len() > retain {
                                held.pop_front();
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
            Self { accepts, task }
        }

        pub fn accepts(&self) -> usize {
            self.accepts.load(Ordering::Relaxed)
        }
    }

    impl Drop for BenchPeer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    /// A minimal `http`-declared sidecar ingress proxy. Field-for-field explicit
    /// rather than serde-defaulted so the bench keeps compiling loudly when the
    /// config model changes.
    fn bench_proxy(id: &str) -> Proxy {
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

    fn roots(root: &Path) -> Vec<String> {
        vec![root.to_str().expect("utf-8 root").to_string()]
    }

    /// macOS temp dirs live behind `/var` → `/private/var`, so the configured
    /// containment root has to be the canonical one.
    fn canonical_root(temp: &tempfile::TempDir) -> PathBuf {
        temp.path().canonicalize().expect("canonicalize temp dir")
    }

    pub fn run(c: &mut Criterion) {
        // `criterion`'s `to_async` needs the `async_tokio` feature, which this
        // crate deliberately does not enable; `block_on` is applied identically
        // to both arms, so it cancels out of the comparison.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("bench runtime");

        let temp = tempfile::TempDir::new().expect("temp dir");
        let root = canonical_root(&temp);
        let dial_socket = root.join("dial.sock");
        let pooled_socket = root.join("pooled.sock");
        let allowed_roots = roots(&root);

        let _guard = runtime.enter();
        // The dial arm churns connections, so its peer retains only a small
        // window. The pooled arm should only ever open one.
        let dial_peer = BenchPeer::bind(&dial_socket, 16);
        let pooled_peer = BenchPeer::bind(&pooled_socket, 4);

        // Per-target physical-connection bound disabled (`0`): this harness
        // measures dial-versus-reuse cost, and the dial arm deliberately opens
        // a fresh connection per iteration.
        let dial_pool = Arc::new(UnixBackendConnectionPool::new(PoolConfig::default(), 8, 0));
        let pooled_pool = Arc::new(UnixBackendConnectionPool::new(PoolConfig::default(), 8, 0));
        let proxy = bench_proxy("unix-ingress-bench");
        let dial_path = dial_socket.to_str().expect("utf-8").to_string();
        let pooled_path = pooled_socket.to_str().expect("utf-8").to_string();

        let mut group = c.benchmark_group("unix_backend_pool");

        group.bench_function("dial_per_request", |b| {
            b.iter(|| {
                runtime.block_on(async {
                    let lease = dial_pool
                        .checkout_h1(
                            &proxy,
                            &dial_path,
                            proxy.backend_connect_timeout_ms,
                            &allowed_roots,
                            &[],
                        )
                        .await
                        .expect("checkout");
                    // Dropped without check-in: exactly what an unpooled
                    // dispatch (or any abnormally-terminated exchange) does.
                    black_box(lease.reused());
                });
            });
        });

        group.bench_function("pooled_reuse", |b| {
            b.iter(|| {
                runtime.block_on(async {
                    let lease = pooled_pool
                        .checkout_h1(
                            &proxy,
                            &pooled_path,
                            proxy.backend_connect_timeout_ms,
                            &allowed_roots,
                            &[],
                        )
                        .await
                        .expect("checkout");
                    black_box(lease.reused());
                    pooled_pool.checkin_h1(lease);
                });
            });
        });

        group.finish();

        // The resource side of the same comparison. One physical connection is
        // one file descriptor on the gateway, one spawned hyper driver task, and
        // one accepted socket on the application.
        let dial_stats = dial_pool.stats();
        let pooled_stats = pooled_pool.stats();
        eprintln!(
            "\n[unix_backend_pool] dial_per_request: physical_connects={} hits={} misses={} \
             backend_accepts={}",
            dial_stats.physical_connects,
            dial_stats.hits,
            dial_stats.misses,
            dial_peer.accepts()
        );
        eprintln!(
            "[unix_backend_pool] pooled_reuse:      physical_connects={} hits={} misses={} \
             backend_accepts={}\n",
            pooled_stats.physical_connects,
            pooled_stats.hits,
            pooled_stats.misses,
            pooled_peer.accepts()
        );

        // The drain is async: it does not merely drop carriers, it awaits the
        // physical connection drivers it owns under a bounded budget.
        runtime.block_on(async {
            dial_pool.shutdown_drain().await;
            pooled_pool.shutdown_drain().await;
        });
    }
}

#[cfg(unix)]
fn unix_backend_pool_benches(c: &mut Criterion) {
    unix_bench::run(c);
}

#[cfg(not(unix))]
fn unix_backend_pool_benches(_c: &mut Criterion) {
    eprintln!("[unix_backend_pool] skipped: this platform has no Unix-domain sockets");
}

criterion_group!(benches, unix_backend_pool_benches);
criterion_main!(benches);
