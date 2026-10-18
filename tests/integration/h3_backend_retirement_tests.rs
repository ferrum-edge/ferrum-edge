//! Native-H3 backend stream ownership across backend TLS retirement.
//!
//! Each split stream half owns a sender, so a retired pooled connection keeps
//! serving its in-flight streams while new requests dial with rotated
//! material. The physical connection slot stays with the H3 driver until the
//! peer connection really ends: force-drain, split-half survival, and
//! cancellation must not release it early or leak it.
//!
//! Tenant TLS file roots, the hold barrier, and the TLS event log are
//! process-global, so the matrix always runs in its own child process.
#![cfg(unix)]

use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::http3::{bind_quinn_client_endpoint, bind_quinn_server_endpoint};
use crate::scaffolding::ports::reserve_port;

use bytes::Buf;
use ferrum_edge::admin::jwt_auth::{JwtConfig, JwtManager};
use ferrum_edge::backend_conn_limit::BackendConnectionLimiter;
use ferrum_edge::config::types::{
    BackendScheme, BackendTlsConfig, DispatchKind, GatewayConfig, Proxy, ResolvedPortOverride,
};
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::http3::client::{H3PoolResult, H3StreamingResponse, Http3ConnectionPool};
use ferrum_edge::modes::file::{ServeOptions, serve};
use ferrum_edge::proxy::ProxyState;
use ferrum_edge::tls::events::{TlsEventFilter, TlsSourceEvent, global_event_log};
use ferrum_edge::tls::source::{MaterialKind, install_mesh_tenant_tls_file_roots};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::{RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::{Notify, watch};

const CHILD_ENV: &str = "INTEGRATION_TEST_H3_BACKEND_RETIREMENT_CHILD";
const TEST_NAME: &str =
    "integration::h3_backend_retirement_tests::h3_stream_ownership_retirement_matrix";

#[derive(Clone, Debug)]
struct Observation {
    conn: u64,
    identity: String,
    event: String,
    path: String,
}

fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn first_cert(pem: &str) -> CertificateDer<'static> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .next()
        .expect("PEM certificate")
        .expect("parse PEM certificate")
}

fn cert_hash(pem: &str) -> String {
    hex(first_cert(pem).as_ref())
}

fn combined(pair: &(String, String)) -> String {
    format!("{}\n{}", pair.0, pair.1)
}

fn tagged(path: &Path, kind: MaterialKind) -> String {
    ferrum_edge::_test_support::bind_tenant_tls_file_for_test(path.to_str().unwrap(), kind)
        .unwrap()
        .unwrap()
}

fn proxy(id: &str, port: u16, path: &Path, ca: &Path) -> Proxy {
    let mut p: Proxy = serde_json::from_value(serde_json::json!({
        "id": id,
        "namespace": "default",
        "listen_path": format!("/{id}"),
        "strip_listen_path": true,
        "backend_scheme": "https",
        "backend_host": "127.0.0.1",
        "backend_port": port,
        "pool_enable_http2": false,
        "backend_tls_verify_server_cert": true,
        "backend_tls_client_cert_path": tagged(path, MaterialKind::Cert),
        "backend_tls_client_key_path": tagged(path, MaterialKind::Key),
        "backend_tls_server_ca_cert_path": tagged(ca, MaterialKind::CaBundle),
        "backend_connect_timeout_ms": 1000,
        "backend_read_timeout_ms": 3000,
        "backend_write_timeout_ms": 3000
    }))
    .unwrap();
    p.dispatch_kind = DispatchKind::from(BackendScheme::Https);
    p.resolved_tls = BackendTlsConfig::from_proxy(&p);
    p
}

fn rotations() -> Vec<TlsSourceEvent> {
    global_event_log().list(&TlsEventFilter {
        surface: Some("backend_tls".into()),
        outcome: Some("rotated".into()),
        ..Default::default()
    })
}

fn latest_rotation() -> u64 {
    rotations().iter().map(|e| e.id).max().unwrap_or(0)
}

async fn await_rotation(after: u64) -> u64 {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    loop {
        if let Some(id) = rotations()
            .iter()
            .map(|e| e.id)
            .filter(|id| *id > after)
            .max()
        {
            return id;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "production watcher rotation missing; events={:?}",
            global_event_log().list(&TlsEventFilter::default())
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn decode(body: &str) -> (String, u64) {
    let (h, c) = body.split_once('|').unwrap();
    (h.to_string(), c.parse().unwrap())
}

fn replace_file(path: &Path, bytes: &str) {
    let next = path.with_extension("next");
    std::fs::write(&next, bytes).unwrap();
    std::fs::rename(&next, path).unwrap();
}

fn replace_link(path: &Path, target: &Path) {
    let next = path.with_extension("link-next");
    let _ = std::fs::remove_file(&next);
    std::os::unix::fs::symlink(target, &next).unwrap();
    std::fs::rename(&next, path).unwrap();
}

/// Holds `/hold` and `/bidi` responses after their head until released.
static HOLD: OnceLock<Notify> = OnceLock::new();

fn release_hold() {
    HOLD.get().expect("hold barrier installed").notify_one();
}

struct H3Origin {
    port: u16,
    observed: Arc<Mutex<Vec<Observation>>>,
    shutdown: watch::Sender<bool>,
    endpoint: quinn::Endpoint,
    join: tokio::task::JoinHandle<()>,
}

impl H3Origin {
    async fn start(server: &(String, String), ca: &str) -> Self {
        let mut roots = RootCertStore::empty();
        roots.add(first_cert(ca)).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
        .build()
        .unwrap();
        let chain = CertificateDer::pem_slice_iter(server.0.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_slice(server.1.as_bytes()).unwrap();
        let mut tls = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key)
            .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.max_early_data_size = 0;
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let endpoint = bind_quinn_server_endpoint(
            quinn::ServerConfig::with_crypto(Arc::new(crypto)),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let port = endpoint.local_addr().unwrap().port();
        let runner = endpoint.clone();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let obs = observed.clone();
        let (shutdown, mut stop) = watch::channel(false);
        let next = Arc::new(AtomicU64::new(1));
        let join = tokio::spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = stop.changed() => break,
                    accepted = runner.accept() => {
                        let Some(incoming) = accepted else { break };
                        children.spawn(serve_origin_connection(
                            incoming,
                            obs.clone(),
                            next.clone(),
                            stop.clone(),
                        ));
                    }
                    Some(_) = children.join_next(), if !children.is_empty() => {}
                }
            }
            runner.close(0u32.into(), b"fixture shutdown");
            while children.join_next().await.is_some() {}
        });
        Self {
            port,
            observed,
            shutdown,
            endpoint,
            join,
        }
    }

    fn observed(&self) -> Vec<Observation> {
        self.observed.lock().unwrap().clone()
    }

    fn saw(&self, conn: u64, event: &str, path: &str) -> bool {
        self.observed()
            .iter()
            .any(|e| e.conn == conn && e.event == event && e.path == path)
    }

    async fn stop(self) {
        let _ = self.shutdown.send(true);
        self.endpoint.close(0u32.into(), b"fixture shutdown");
        tokio::time::timeout(Duration::from_secs(6), self.join)
            .await
            .unwrap()
            .unwrap();
    }
}

/// Serve one mTLS H3 connection: record the client identity, answer each
/// request with `<identity>|<conn>` plus a completion trailer, and hold
/// `/hold` and `/bidi` after the response head until released.
async fn serve_origin_connection(
    incoming: quinn::Incoming,
    obs: Arc<Mutex<Vec<Observation>>>,
    next: Arc<AtomicU64>,
    mut stop: watch::Receiver<bool>,
) {
    let Ok(connection) = incoming.await else {
        return;
    };
    let certs = connection
        .peer_identity()
        .unwrap()
        .downcast::<Vec<CertificateDer<'static>>>()
        .unwrap();
    let identity = hex(certs[0].as_ref());
    let conn = next.fetch_add(1, Ordering::SeqCst);
    let record = |event: String, path: String| {
        obs.lock().unwrap().push(Observation {
            conn,
            identity: identity.clone(),
            event,
            path,
        });
    };
    record("handshake".into(), String::new());
    let h3_connection = h3_quinn::Connection::new(connection.clone());
    let Ok(mut h3) = h3::server::Connection::new(h3_connection).await else {
        return;
    };
    loop {
        let resolver = tokio::select! {
            _ = stop.changed() => {
                connection.close(0u32.into(), b"fixture shutdown");
                break;
            }
            accepted = h3.accept() => match accepted {
                Ok(Some(resolver)) => resolver,
                _ => break,
            },
        };
        let Ok((req, mut stream)) = resolver.resolve_request().await else {
            break;
        };
        let path = req.uri().path().to_string();
        record("request".into(), path.clone());
        let body = format!("{identity}|{conn}");
        let reply = http::Response::builder()
            .status(200)
            .header("content-length", body.len())
            .body(())
            .unwrap();
        if stream.send_response(reply).await.is_err() {
            break;
        }
        if path == "/hold" || path == "/bidi" {
            tokio::select! {
                _ = HOLD.get().expect("hold barrier installed").notified() => {}
                _ = stop.changed() => break,
            }
        }
        if path == "/bidi" {
            let mut upload = Vec::new();
            while let Ok(Some(mut data)) = stream.recv_data().await {
                let n = data.remaining();
                upload.extend_from_slice(&data.copy_to_bytes(n));
            }
            record("upload".into(), String::from_utf8(upload).unwrap());
        }
        if stream.send_data(bytes::Bytes::from(body)).await.is_err() {
            break;
        }
        let mut trailers = http::HeaderMap::new();
        trailers.insert(
            "x-retirement-proof",
            http::HeaderValue::from_static("complete"),
        );
        if stream.send_trailers(trailers).await.is_err() {
            break;
        }
    }
    let reason = connection
        .close_reason()
        .map(|e| e.to_string())
        .unwrap_or_else(|| "H3 driver ended".into());
    record(format!("closed:{reason}"), String::new());
}

/// A direct mTLS handshake proves the origin accepts the out-of-root identity,
/// so the gateway's later refusal of it is the confinement, not the origin.
async fn h3_direct_handshake_control(origin: &H3Origin, ca: &TestCa, client: &(String, String)) {
    let mut roots = RootCertStore::empty();
    roots.add(first_cert(&ca.cert_pem)).unwrap();
    let chain = CertificateDer::pem_slice_iter(client.0.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(client.1.as_bytes()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut endpoint = bind_quinn_client_endpoint("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let origin_addr = SocketAddr::from(([127, 0, 0, 1], origin.port));
    let connecting = endpoint.connect(origin_addr, "127.0.0.1").unwrap();
    let connection = tokio::time::timeout(Duration::from_secs(4), connecting)
        .await
        .unwrap()
        .unwrap();
    let hash = cert_hash(&client.0);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    while !origin
        .observed()
        .iter()
        .any(|e| e.event == "handshake" && e.identity == hash)
    {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    connection.close(0u32.into(), b"validity control complete");
    endpoint.close(0u32.into(), b"validity control complete");
}

fn host_header(port: u16) -> [(http::header::HeaderName, http::HeaderValue); 1] {
    let value = http::HeaderValue::from_str(&format!("127.0.0.1:{port}")).unwrap();
    [(http::header::HOST, value)]
}

async fn open(
    state: &ProxyState,
    pool: &Http3ConnectionPool,
    p: &Proxy,
    path: &str,
) -> H3PoolResult<H3StreamingResponse> {
    ferrum_edge::_test_support::h3_pool_streaming_request_with_target_for_test(
        pool,
        p,
        ("127.0.0.1", p.backend_port, p.backend_port),
        "GET",
        &format!("https://127.0.0.1:{}{path}", p.backend_port),
        &host_header(p.backend_port),
        bytes::Bytes::new(),
        state.connection_pool.get_tls_config_for_backend(p),
    )
    .await
}

async fn consume(mut r: H3StreamingResponse) -> (String, u64) {
    assert_eq!(r.status, 200);
    let mut all = Vec::new();
    loop {
        let chunk = tokio::time::timeout(Duration::from_secs(5), r.recv_stream.recv_data())
            .await
            .unwrap()
            .unwrap();
        let Some(mut chunk) = chunk else { break };
        let n = chunk.remaining();
        all.extend_from_slice(&chunk.copy_to_bytes(n));
    }
    let trailers = r.recv_stream.recv_trailers().await.unwrap().unwrap();
    assert_eq!(trailers["x-retirement-proof"], "complete");
    decode(std::str::from_utf8(&all).unwrap())
}

async fn ordinary(state: &ProxyState, pool: &Http3ConnectionPool, p: &Proxy) -> (String, u64) {
    consume(open(state, pool, p, "/probe").await.unwrap()).await
}

async fn await_count(limiter: &BackendConnectionLimiter, port: u16, want: u64) {
    let end = tokio::time::Instant::now() + Duration::from_secs(5);
    while limiter.current("127.0.0.1", port) != want {
        assert!(
            tokio::time::Instant::now() < end,
            "physical connection slot did not settle"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_stream_ownership_retirement_matrix() {
    if std::env::var_os(CHILD_ENV).is_none() {
        let output = std::process::Command::new(
            std::env::current_exe().expect("resolve integration test executable"),
        )
        .env(CHILD_ENV, "1")
        .args(["--exact", TEST_NAME, "--nocapture"])
        .output()
        .expect("run isolated H3 retirement matrix");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "isolated H3 retirement matrix failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        println!("{stdout}");
        return;
    }
    run_retirement_matrix().await;
}

async fn run_retirement_matrix() {
    assert!(HOLD.set(Notify::new()).is_ok(), "hold installs once");
    let _ = rustls::crypto::ring::default_provider().install_default();
    let work = tempfile::tempdir().unwrap();
    let ra = work.path().join("tenant-a");
    let rb = work.path().join("tenant-b");
    let outside = work.path().join("outside");
    for root in [&ra, &rb, &outside] {
        std::fs::create_dir(root).unwrap();
    }
    install_mesh_tenant_tls_file_roots(vec![ra.clone(), rb.clone()]).unwrap();
    let ca = TestCa::new("synthetic-h3-ca").unwrap();
    let server = ca.valid().unwrap();
    let a0 = ca.client_auth().unwrap();
    let a1 = ca.client_auth().unwrap();
    let b0 = ca.client_auth().unwrap();
    let b1 = ca.client_auth().unwrap();
    let alien = ca.client_auth().unwrap();
    let ha0 = cert_hash(&a0.0);
    let ha1 = cert_hash(&a1.0);
    let hb0 = cert_hash(&b0.0);
    let hb1 = cert_hash(&b1.0);
    let hx = cert_hash(&alien.0);
    let a0file = ra.join("a0.pem");
    std::fs::write(&a0file, combined(&a0)).unwrap();
    let apath = ra.join("current.pem");
    replace_link(&apath, &a0file);
    let bpath = rb.join("current.pem");
    std::fs::write(&bpath, combined(&b0)).unwrap();
    let outside_identity = outside.join("alien.pem");
    std::fs::write(&outside_identity, combined(&alien)).unwrap();
    let acafile = ra.join("inside-ca.pem");
    std::fs::write(&acafile, &ca.cert_pem).unwrap();
    let acapath = ra.join("ca.pem");
    replace_link(&acapath, &acafile);
    let bcapath = rb.join("ca.pem");
    std::fs::write(&bcapath, &ca.cert_pem).unwrap();
    std::fs::write(outside.join("ca.pem"), &ca.cert_pem).unwrap();
    let oa = H3Origin::start(&server, &ca.cert_pem).await;
    let ob = H3Origin::start(&server, &ca.cert_pem).await;
    h3_direct_handshake_control(&oa, &ca, &alien).await;
    let pa = proxy("h3-a", oa.port, &apath, &acapath);
    let pb = proxy("h3-b", ob.port, &bpath, &bcapath);
    let cfg = GatewayConfig {
        proxies: vec![pa.clone(), pb.clone()],
        ..Default::default()
    };
    let listener = reserve_port().await.unwrap().into_listener();
    let gateway_port = listener.local_addr().unwrap().port();
    let secret = "synthetic-h3-jwt-not-an-external-credential".to_string();
    let jwt = JwtManager::new(JwtConfig {
        secret: secret.clone(),
        issuer: "local-h3".into(),
        audience: None,
        max_ttl_seconds: 300,
        algorithm: jsonwebtoken::Algorithm::HS256,
    });
    let env = EnvConfig {
        mode: OperatingMode::File,
        proxy_http_port: gateway_port,
        proxy_https_port: 0,
        admin_http_port: 0,
        admin_https_port: 0,
        admin_jwt_secret: Some(secret),
        admin_jwt_issuer: "local-h3".into(),
        pool_warmup_enabled: false,
        pool_http1_direct: false,
        backend_tls_live_reload_enabled: true,
        backend_tls_watch_interval_seconds: 1,
        shutdown_drain_seconds: 0,
        http3_connections_per_backend: 1,
        proxy_bind_address: "127.0.0.1".into(),
        ..Default::default()
    };
    let (stop, _) = ferrum_edge::overload::ShutdownSender::channel(Duration::from_secs(
        env.shutdown_drain_seconds,
    ));
    let handles = serve(
        env,
        cfg,
        ServeOptions {
            proxy_http: Some(listener),
            admin_jwt_manager: Some(jwt),
            skip_initial_capability_refresh: true,
            background_drain_timeout: Some(Duration::from_secs(2)),
            ..Default::default()
        },
        stop.clone(),
    )
    .await
    .unwrap();
    let config_before = serde_json::to_value(handles.proxy_state.config.load().as_ref()).unwrap();

    let state = &handles.proxy_state;
    let mut proofs = Vec::new();
    assert_eq!(ordinary(state, &state.h3_pool, &pa).await.0, ha0);
    assert_eq!(ordinary(state, &state.h3_pool, &pb).await.0, hb0);
    // Let the backend TLS watcher take its baseline before the first rotation.
    tokio::time::sleep(Duration::from_millis(2250)).await;
    for (name, hold_a, escape) in [
        ("held-A healthy", true, false),
        ("held-B healthy", false, false),
        ("held-A confined refusal", true, true),
        ("held-B A-confined refusal", false, true),
    ] {
        let p = if hold_a { &pa } else { &pb };
        let origin = if hold_a { &oa } else { &ob };
        let held = open(state, &state.h3_pool, p, "/hold").await.unwrap();
        let old = origin
            .observed()
            .iter()
            .rev()
            .find(|e| e.path == "/hold")
            .unwrap()
            .clone();
        let before = latest_rotation();
        if escape {
            replace_link(&apath, &outside_identity);
        } else if hold_a {
            let f = ra.join("healthy.pem");
            replace_file(&f, &combined(&a1));
            replace_link(&apath, &f);
        } else {
            replace_file(&bpath, &combined(&b1));
        }
        let revision = await_rotation(before).await;
        if escape {
            assert!(open(state, &state.h3_pool, &pa, "/probe").await.is_err());
        } else {
            let fresh = ordinary(state, &state.h3_pool, p).await;
            assert_ne!(fresh.1, old.conn);
            assert_eq!(fresh.0, if hold_a { ha1.clone() } else { hb1.clone() });
        }
        if !hold_a && escape {
            let f = ordinary(state, &state.h3_pool, &pb).await;
            assert_ne!(f.1, old.conn);
        }
        release_hold();
        assert_eq!(consume(held).await, (old.identity.clone(), old.conn));
        proofs.push(serde_json::json!({
            "case": name,
            "revision": revision,
            "old_stream_completed": true,
            "old_identity": old.identity,
            "old_connection": old.conn,
            "fresh_retired_material_reuse": false
        }));
        if escape {
            let f = ra.join("restored.pem");
            replace_file(&f, &combined(&a1));
            let before = latest_rotation();
            replace_link(&apath, &f);
            await_rotation(before).await;
            assert_eq!(ordinary(state, &state.h3_pool, &pa).await.0, ha1);
        }
    }

    let mut capped = pa.clone();
    let cap = ResolvedPortOverride {
        max_connections: Some(1),
        ..Default::default()
    };
    capped.dispatch_port_overrides = Some(std::collections::HashMap::from([(oa.port, cap)]));
    let cap_env = EnvConfig {
        http3_connections_per_backend: 1,
        ..Default::default()
    };
    let dns = ferrum_edge::dns::DnsCache::new(ferrum_edge::dns::DnsConfig::default());
    let cap_pool = Http3ConnectionPool::new(Arc::new(cap_env), dns);
    let limiter = Arc::new(BackendConnectionLimiter::new());
    cap_pool.attach_backend_conn_limit(limiter.clone());
    let held = open(state, &cap_pool, &capped, "/hold").await.unwrap();
    await_count(&limiter, oa.port, 1).await;
    cap_pool.force_drain_all();
    assert_eq!(limiter.current("127.0.0.1", oa.port), 1);
    let refused = open(state, &cap_pool, &capped, "/probe")
        .await
        .err()
        .unwrap();
    assert_eq!(
        ferrum_edge::http3::client::classify_http3_error(&refused),
        ferrum_edge::retry::ErrorClass::BackendConnectionLimit
    );
    release_hold();
    consume(held).await;
    await_count(&limiter, oa.port, 0).await;
    ordinary(state, &cap_pool, &capped).await;
    cap_pool.force_drain_all();
    await_count(&limiter, oa.port, 0).await;
    proofs.push(serde_json::json!({
        "case": "cap accounting",
        "active_retired_count": 1,
        "replacement_refused_before_dial": true,
        "released_after_completion": true
    }));

    for drop_receive in [false, true] {
        let mut bidi = ferrum_edge::_test_support::h3_pool_open_bidi_with_target_for_test(
            &cap_pool,
            &capped,
            ("127.0.0.1", oa.port, oa.port),
            "POST",
            &format!("https://127.0.0.1:{}/bidi", oa.port),
            &host_header(oa.port),
            state.connection_pool.get_tls_config_for_backend(&capped),
        )
        .await
        .unwrap();
        let head = ferrum_edge::http3::client::recv_h3_backend_response_head(&mut bidi.recv)
            .await
            .unwrap();
        assert_eq!(head.status, 200);
        let conn = oa
            .observed()
            .iter()
            .rev()
            .find(|e| e.path == "/bidi")
            .unwrap()
            .conn;
        bidi.send
            .send_data(bytes::Bytes::from_static(b"before-"))
            .await
            .unwrap();
        cap_pool.force_drain_all();
        assert_eq!(limiter.current("127.0.0.1", oa.port), 1);
        if drop_receive {
            drop(bidi.recv);
            bidi.send
                .send_data(bytes::Bytes::from_static(b"after"))
                .await
                .unwrap();
            assert_eq!(limiter.current("127.0.0.1", oa.port), 1);
            bidi.send.finish().await.unwrap();
            release_hold();
            let end = tokio::time::Instant::now() + Duration::from_secs(5);
            while !oa.saw(conn, "upload", "before-after") {
                assert!(tokio::time::Instant::now() < end);
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            // The peer may close after its response direction was cancelled;
            // the driver must release the physical slot on that close.
            drop(bidi.send);
        } else {
            bidi.send
                .send_data(bytes::Bytes::from_static(b"after"))
                .await
                .unwrap();
            bidi.send.finish().await.unwrap();
            drop(bidi.send);
            assert_eq!(limiter.current("127.0.0.1", oa.port), 1);
            release_hold();
            let mut all = Vec::new();
            loop {
                let d = tokio::time::timeout(Duration::from_secs(5), bidi.recv.recv_data())
                    .await
                    .unwrap()
                    .unwrap();
                let Some(mut d) = d else { break };
                let n = d.remaining();
                all.extend_from_slice(&d.copy_to_bytes(n));
            }
            assert_eq!(decode(std::str::from_utf8(&all).unwrap()).1, conn);
            let trailers = bidi.recv.recv_trailers().await.unwrap().unwrap();
            assert_eq!(trailers["x-retirement-proof"], "complete");
            drop(bidi.recv);
        }
        assert!(oa.saw(conn, "upload", "before-after"));
        await_count(&limiter, oa.port, 0).await;
        proofs.push(serde_json::json!({
            "case": "split bidi",
            "dropped_receive_first": drop_receive,
            "remaining_half_alive": true,
            "actual_upload": "before-after",
            "physical_slot_matches_peer_lifetime": true,
            "peer_may_close_after_cancelled_response": drop_receive
        }));
    }

    let cancelled = open(state, &cap_pool, &capped, "/hold").await.unwrap();
    cap_pool.force_drain_all();
    assert_eq!(limiter.current("127.0.0.1", oa.port), 1);
    drop(cancelled);
    release_hold();
    await_count(&limiter, oa.port, 0).await;
    assert_eq!(ordinary(state, &cap_pool, &capped).await.0, ha1);
    cap_pool.force_drain_all();
    await_count(&limiter, oa.port, 0).await;
    proofs.push(serde_json::json!({
        "case": "cancel/drop",
        "physical_slot_released": true,
        "ordinary_recovery": true
    }));
    assert_eq!(
        serde_json::to_value(state.config.load().as_ref()).unwrap(),
        config_before
    );
    let alien_reached_origin = oa
        .observed()
        .iter()
        .any(|e| e.path == "/probe" && e.identity == hx);
    assert!(!alien_reached_origin);
    stop.shutdown();
    tokio::time::timeout(Duration::from_secs(8), handles.join())
        .await
        .unwrap()
        .unwrap();
    oa.stop().await;
    ob.stop().await;
    let evidence = serde_json::json!({
        "proofs": proofs,
        "synthetic_backend_only": true,
        "trailers_checked": true,
        "source_config_unchanged": true
    });
    println!("H3_OWNERSHIP_EVIDENCE={evidence}");
}
