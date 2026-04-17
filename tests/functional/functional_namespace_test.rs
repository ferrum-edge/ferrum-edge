//! End-to-end functional tests for the multi-namespace feature.
//!
//! Exercises the running `ferrum-edge` binary via the Admin API against each
//! supported database backend with the `X-Ferrum-Namespace` header, covering:
//!
//! - namespace-scoped CRUD for proxies / consumers / upstreams
//! - per-namespace uniqueness constraints (listen_path, listen_port, name,
//!   username, custom_id) — same value allowed across namespaces, denied
//!   within one
//! - `X-Ferrum-Namespace` header defaulting to `ferrum`
//! - invalid namespace header rejection
//! - `GET /namespaces` returning the full set regardless of the current header
//! - delete isolation (deleting a namespace's resource by id from another
//!   namespace returns 404)
//!
//! Backends:
//! - `sqlite`: runs unconditionally (tempdir-backed file DB)
//! - `postgres`: runs when `FERRUM_TEST_POSTGRES_URL` is set
//! - `mysql`: runs when `FERRUM_TEST_MYSQL_URL` is set
//! - `mongodb`: runs when `FERRUM_TEST_MONGO_URL` is set (or default
//!   `mongodb://localhost:27017/ferrum_test` is reachable, matching
//!   `functional_mongodb_test` conventions)
//!
//! All tests are `#[ignore]` — invoke with `cargo test --test functional_tests
//! -- --ignored namespace`.

use serde_json::Value;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime};
use tempfile::TempDir;

use super::namespace_helpers::{
    JWT_ISSUER, JWT_SECRET, admin_request, assert_only_namespace, ephemeral_port,
    gateway_binary_path, list_len, sample_consumer, sample_proxy, sample_proxy_with_name,
    sample_stream_proxy, sample_upstream,
};

// ---------------------------------------------------------------------------
// Backend selection
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Backend {
    Sqlite,
    Postgres,
    Mysql,
    Mongodb,
}

impl Backend {
    fn db_type(self) -> &'static str {
        match self {
            Backend::Sqlite => "sqlite",
            Backend::Postgres => "postgres",
            Backend::Mysql => "mysql",
            Backend::Mongodb => "mongodb",
        }
    }
}

/// Resolve the DB URL for the requested backend. Returns `None` when an
/// external backend's env var is unset and no default is reachable — the
/// calling test should skip in that case.
async fn resolve_db_url(backend: Backend, tmp: &TempDir) -> Option<String> {
    match backend {
        Backend::Sqlite => {
            let path = tmp.path().join("ns_test.db");
            Some(format!("sqlite:{}?mode=rwc", path.display()))
        }
        Backend::Postgres => std::env::var("FERRUM_TEST_POSTGRES_URL").ok(),
        Backend::Mysql => std::env::var("FERRUM_TEST_MYSQL_URL").ok(),
        Backend::Mongodb => {
            let url = std::env::var("FERRUM_TEST_MONGO_URL")
                .unwrap_or_else(|_| "mongodb://localhost:27017/ferrum_test".to_string());
            // Probe TCP reachability before returning the URL.
            let host_port = url
                .strip_prefix("mongodb://")
                .or_else(|| url.strip_prefix("mongodb+srv://"))
                .and_then(|s| s.split('/').next())
                .and_then(|s| {
                    if s.contains('@') {
                        s.split('@').next_back()
                    } else {
                        Some(s)
                    }
                })
                .unwrap_or("localhost:27017")
                .to_string();
            if tokio::net::TcpStream::connect(&host_port).await.is_ok() {
                Some(url)
            } else {
                None
            }
        }
    }
}

/// For external backends that share a server across test runs, wipe any
/// resources left over from a previous run. SQLite is a fresh tempfile per
/// run so nothing to clean.
async fn reset_backend(_backend: Backend, _db_url: &str) {
    // Intentional no-op today: the suite uses randomized resource ids per run
    // (see `mk_id`) so prior state cannot collide with new test resources.
    // If future assertions grow to require an empty starting state, add a
    // per-backend truncate here.
}

/// Unique-per-run id suffix so external backends (postgres/mysql/mongodb) can
/// be reused across test invocations without clashing on fresh inserts.
fn mk_id(prefix: &str) -> String {
    format!("{}-{}", prefix, uuid::Uuid::new_v4())
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct NsHarness {
    _tmp: TempDir,
    gateway: Option<Child>,
    admin_base_url: String,
    proxy_base_url: String,
}

impl NsHarness {
    async fn start(backend: Backend) -> Option<Self> {
        Self::start_with_namespace(backend, None).await
    }

    /// Like `start` but pins the gateway's own `FERRUM_NAMESPACE` env var so
    /// runtime isolation (routing) can be verified independently of the
    /// admin-API header behavior.
    async fn start_with_namespace(
        backend: Backend,
        gateway_namespace: Option<&str>,
    ) -> Option<Self> {
        const MAX_ATTEMPTS: u32 = 3;
        let mut last_err = String::new();
        for attempt in 1..=MAX_ATTEMPTS {
            // Fresh tempdir (and fresh SQLite file) per attempt to avoid a
            // half-initialized DB from a prior failed start.
            let tmp = TempDir::new().expect("tempdir");
            let db_url = match resolve_db_url(backend, &tmp).await {
                Some(u) => u,
                None => return None,
            };
            reset_backend(backend, &db_url).await;

            let admin_port = ephemeral_port().await;
            let proxy_port = ephemeral_port().await;

            let mut cmd = Command::new(gateway_binary_path());
            cmd.env("FERRUM_MODE", "database")
                .env("FERRUM_ADMIN_JWT_SECRET", JWT_SECRET)
                .env("FERRUM_ADMIN_JWT_ISSUER", JWT_ISSUER)
                .env("FERRUM_DB_TYPE", backend.db_type())
                .env("FERRUM_DB_URL", &db_url)
                .env("FERRUM_DB_POLL_INTERVAL", "1")
                .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
                .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
                .env("FERRUM_LOG_LEVEL", "warn")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());

            if matches!(backend, Backend::Mongodb) {
                // Matches the convention in functional_mongodb_test.
                cmd.env("FERRUM_MONGO_DATABASE", "ferrum_test");
            }

            if let Some(ns) = gateway_namespace {
                cmd.env("FERRUM_NAMESPACE", ns);
            }

            let child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    last_err = format!("spawn: {e}");
                    continue;
                }
            };

            let admin_base_url = format!("http://127.0.0.1:{admin_port}");
            let proxy_base_url = format!("http://127.0.0.1:{proxy_port}");

            let mut harness = Self {
                _tmp: tmp,
                gateway: Some(child),
                admin_base_url,
                proxy_base_url,
            };

            if harness.wait_for_health().await {
                return Some(harness);
            }

            last_err = format!("health timeout (attempt {attempt})");
            harness.kill_gateway();
            eprintln!("namespace harness retry {attempt}/{MAX_ATTEMPTS}: {last_err}");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        panic!("namespace harness failed to start: {last_err}");
    }

    async fn wait_for_health(&self) -> bool {
        let health_url = format!("{}/health", self.admin_base_url);
        let deadline = SystemTime::now() + Duration::from_secs(30);
        let client = reqwest::Client::new();
        while SystemTime::now() < deadline {
            if let Ok(r) = client.get(&health_url).send().await
                && r.status().is_success()
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        false
    }

    fn kill_gateway(&mut self) {
        if let Some(mut c) = self.gateway.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for NsHarness {
    fn drop(&mut self) {
        self.kill_gateway();
    }
}

// ---------------------------------------------------------------------------
// Core test suite — parameterized per backend
// ---------------------------------------------------------------------------

async fn run_namespace_suite(backend: Backend) {
    let Some(harness) = NsHarness::start(backend).await else {
        eprintln!(
            "Skipping namespace suite for {} — backend unavailable",
            backend.db_type()
        );
        return;
    };

    let client = reqwest::Client::new();
    let base = harness.admin_base_url.clone();

    // Each run uses unique ids so reused external DBs don't collide.
    let ns_a = format!("ns-a-{}", uuid::Uuid::new_v4().simple());
    let ns_b = format!("ns-b-{}", uuid::Uuid::new_v4().simple());

    let proxy_a_id = mk_id("proxy-a");
    let proxy_b_id = mk_id("proxy-b");

    // Both namespaces try to claim the same listen_path — must succeed because
    // uniqueness is (namespace, listen_path).
    let shared_path = format!("/ns-shared/{}", uuid::Uuid::new_v4().simple());

    // --- invalid header --------------------------------------------------
    let bad = admin_request(
        &client,
        reqwest::Method::GET,
        &format!("{base}/proxies"),
        Some("bad space!"),
        None,
    )
    .await;
    assert_eq!(
        bad.status().as_u16(),
        400,
        "invalid namespace header must yield 400"
    );

    // --- header defaulting (no X-Ferrum-Namespace header) ---------------
    // Create a proxy with no namespace header; it must land in 'ferrum'.
    let default_proxy_id = mk_id("default-proxy");
    let default_path = format!("/ns-default/{}", uuid::Uuid::new_v4().simple());
    let resp = admin_request(
        &client,
        reqwest::Method::POST,
        &format!("{base}/proxies"),
        None,
        Some(&sample_proxy(&default_proxy_id, &default_path, 9)),
    )
    .await;
    assert!(
        resp.status().is_success(),
        "default-namespace POST failed: {}",
        resp.status()
    );

    // GET with no header returns it.
    let resp = admin_request(
        &client,
        reqwest::Method::GET,
        &format!("{base}/proxies/{default_proxy_id}"),
        None,
        None,
    )
    .await;
    assert!(
        resp.status().is_success(),
        "default-namespace GET failed: {}",
        resp.status()
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["namespace"].as_str(), Some("ferrum"));

    // GET with a different namespace must 404 — default proxy is invisible.
    let resp = admin_request(
        &client,
        reqwest::Method::GET,
        &format!("{base}/proxies/{default_proxy_id}"),
        Some(&ns_a),
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 404);

    // --- CRUD scoping ----------------------------------------------------
    // Create proxy A in ns_a and proxy B in ns_b, both with the same listen_path.
    let resp = admin_request(
        &client,
        reqwest::Method::POST,
        &format!("{base}/proxies"),
        Some(&ns_a),
        Some(&sample_proxy(&proxy_a_id, &shared_path, 9)),
    )
    .await;
    assert!(
        resp.status().is_success(),
        "create ns_a proxy failed: {}",
        resp.status()
    );

    let resp = admin_request(
        &client,
        reqwest::Method::POST,
        &format!("{base}/proxies"),
        Some(&ns_b),
        Some(&sample_proxy(&proxy_b_id, &shared_path, 9)),
    )
    .await;
    assert!(
        resp.status().is_success(),
        "same listen_path in ns_b must succeed (per-namespace uniqueness): {}",
        resp.status()
    );

    // --- per-namespace uniqueness (listen_path denied within same ns) ---
    let dup = admin_request(
        &client,
        reqwest::Method::POST,
        &format!("{base}/proxies"),
        Some(&ns_a),
        Some(&sample_proxy(&mk_id("dup"), &shared_path, 9)),
    )
    .await;
    assert_eq!(
        dup.status().as_u16(),
        409,
        "duplicate listen_path within same namespace must be rejected"
    );

    // --- list scoping ----------------------------------------------------
    let resp = admin_request(
        &client,
        reqwest::Method::GET,
        &format!("{base}/proxies"),
        Some(&ns_a),
        None,
    )
    .await;
    assert!(resp.status().is_success());
    let body: Value = resp.json().await.unwrap();
    assert_only_namespace(&body, &ns_a);
    assert!(list_len(&body) >= 1);

    // --- GET-by-id wrong-namespace → 404 --------------------------------
    let resp = admin_request(
        &client,
        reqwest::Method::GET,
        &format!("{base}/proxies/{proxy_a_id}"),
        Some(&ns_b),
        None,
    )
    .await;
    assert_eq!(
        resp.status().as_u16(),
        404,
        "cross-namespace GET by id must be 404"
    );

    // --- proxy name uniqueness ------------------------------------------
    let shared_name = format!("shared-{}", uuid::Uuid::new_v4().simple());
    let resp = admin_request(
        &client,
        reqwest::Method::POST,
        &format!("{base}/proxies"),
        Some(&ns_a),
        Some(&sample_proxy_with_name(
            &mk_id("named-a"),
            &shared_name,
            &format!("/name-test/{}", uuid::Uuid::new_v4().simple()),
            9,
        )),
    )
    .await;
    assert!(resp.status().is_success());

    let resp = admin_request(
        &client,
        reqwest::Method::POST,
        &format!("{base}/proxies"),
        Some(&ns_b),
        Some(&sample_proxy_with_name(
            &mk_id("named-b"),
            &shared_name,
            &format!("/name-test/{}", uuid::Uuid::new_v4().simple()),
            9,
        )),
    )
    .await;
    assert!(
        resp.status().is_success(),
        "same name in different namespaces must succeed: {}",
        resp.status()
    );

    let dup = admin_request(
        &client,
        reqwest::Method::POST,
        &format!("{base}/proxies"),
        Some(&ns_a),
        Some(&sample_proxy_with_name(
            &mk_id("named-a-dup"),
            &shared_name,
            &format!("/name-test/{}", uuid::Uuid::new_v4().simple()),
            9,
        )),
    )
    .await;
    assert_eq!(
        dup.status().as_u16(),
        409,
        "duplicate proxy name within same namespace must be rejected"
    );

    // --- stream listen_port uniqueness ----------------------------------
    let shared_port = ephemeral_port().await;
    let resp = admin_request(
        &client,
        reqwest::Method::POST,
        &format!("{base}/proxies"),
        Some(&ns_a),
        Some(&sample_stream_proxy(&mk_id("tcp-a"), shared_port, 9)),
    )
    .await;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        panic!("create stream proxy in ns_a failed: {status} body={body}");
    }

    let resp = admin_request(
        &client,
        reqwest::Method::POST,
        &format!("{base}/proxies"),
        Some(&ns_b),
        Some(&sample_stream_proxy(&mk_id("tcp-b"), shared_port, 9)),
    )
    .await;
    assert!(
        resp.status().is_success(),
        "same listen_port in different namespaces must succeed: {}",
        resp.status()
    );

    let dup = admin_request(
        &client,
        reqwest::Method::POST,
        &format!("{base}/proxies"),
        Some(&ns_a),
        Some(&sample_stream_proxy(&mk_id("tcp-a-dup"), shared_port, 9)),
    )
    .await;
    assert_eq!(
        dup.status().as_u16(),
        409,
        "duplicate listen_port within same namespace must be rejected"
    );

    // --- consumer identity uniqueness -----------------------------------
    let shared_user = format!("shared-user-{}", uuid::Uuid::new_v4().simple());
    let shared_custom = format!("shared-custom-{}", uuid::Uuid::new_v4().simple());
    for ns in [&ns_a, &ns_b] {
        let resp = admin_request(
            &client,
            reqwest::Method::POST,
            &format!("{base}/consumers"),
            Some(ns),
            Some(&sample_consumer(
                &mk_id("consumer"),
                &shared_user,
                Some(&shared_custom),
            )),
        )
        .await;
        assert!(
            resp.status().is_success(),
            "create consumer in {ns} with shared username+custom_id must succeed: {}",
            resp.status()
        );
    }
    let dup = admin_request(
        &client,
        reqwest::Method::POST,
        &format!("{base}/consumers"),
        Some(&ns_a),
        Some(&sample_consumer(&mk_id("consumer-dup"), &shared_user, None)),
    )
    .await;
    assert_eq!(
        dup.status().as_u16(),
        409,
        "duplicate username within same namespace must be rejected"
    );

    // --- upstream name uniqueness ---------------------------------------
    let shared_up = format!("shared-up-{}", uuid::Uuid::new_v4().simple());
    for ns in [&ns_a, &ns_b] {
        let resp = admin_request(
            &client,
            reqwest::Method::POST,
            &format!("{base}/upstreams"),
            Some(ns),
            Some(&sample_upstream(&mk_id("up"), &shared_up, 9)),
        )
        .await;
        assert!(
            resp.status().is_success(),
            "create upstream in {ns} must succeed: {}",
            resp.status()
        );
    }
    let dup = admin_request(
        &client,
        reqwest::Method::POST,
        &format!("{base}/upstreams"),
        Some(&ns_a),
        Some(&sample_upstream(&mk_id("up-dup"), &shared_up, 9)),
    )
    .await;
    assert_eq!(
        dup.status().as_u16(),
        409,
        "duplicate upstream name within same namespace must be rejected"
    );

    // --- GET /namespaces ------------------------------------------------
    // The list is unaffected by whichever namespace header the request carries.
    for header_ns in [None, Some(ns_a.as_str()), Some(ns_b.as_str())] {
        let resp = admin_request(
            &client,
            reqwest::Method::GET,
            &format!("{base}/namespaces"),
            header_ns,
            None,
        )
        .await;
        assert!(resp.status().is_success(), "GET /namespaces failed");
        let body: Value = resp.json().await.unwrap();
        let names: Vec<&str> = body
            .as_array()
            .expect("namespaces array")
            .iter()
            .map(|v| v.as_str().unwrap_or(""))
            .collect();
        assert!(
            names.contains(&ns_a.as_str()),
            "namespaces missing ns_a: {names:?}"
        );
        assert!(
            names.contains(&ns_b.as_str()),
            "namespaces missing ns_b: {names:?}"
        );
    }

    // --- delete isolation -----------------------------------------------
    let resp = admin_request(
        &client,
        reqwest::Method::DELETE,
        &format!("{base}/proxies/{proxy_a_id}"),
        Some(&ns_b), // wrong namespace
        None,
    )
    .await;
    assert_eq!(
        resp.status().as_u16(),
        404,
        "wrong-namespace DELETE must 404 without affecting the resource"
    );

    // confirm proxy A still exists
    let resp = admin_request(
        &client,
        reqwest::Method::GET,
        &format!("{base}/proxies/{proxy_a_id}"),
        Some(&ns_a),
        None,
    )
    .await;
    assert!(resp.status().is_success(), "proxy A must still exist");

    // delete with correct namespace
    let resp = admin_request(
        &client,
        reqwest::Method::DELETE,
        &format!("{base}/proxies/{proxy_a_id}"),
        Some(&ns_a),
        None,
    )
    .await;
    assert!(
        resp.status().is_success(),
        "correct-namespace DELETE failed: {}",
        resp.status()
    );

    // proxy B (same listen_path, different namespace) survives.
    let resp = admin_request(
        &client,
        reqwest::Method::GET,
        &format!("{base}/proxies/{proxy_b_id}"),
        Some(&ns_b),
        None,
    )
    .await;
    assert!(
        resp.status().is_success(),
        "proxy in other namespace must survive sibling delete: {}",
        resp.status()
    );
}

// ---------------------------------------------------------------------------
// Entry points per backend
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn namespace_suite_sqlite() {
    run_namespace_suite(Backend::Sqlite).await;
}

#[tokio::test]
#[ignore]
async fn namespace_suite_postgres() {
    run_namespace_suite(Backend::Postgres).await;
}

#[tokio::test]
#[ignore]
async fn namespace_suite_mysql() {
    run_namespace_suite(Backend::Mysql).await;
}

#[tokio::test]
#[ignore]
async fn namespace_suite_mongodb() {
    run_namespace_suite(Backend::Mongodb).await;
}

// ---------------------------------------------------------------------------
// Runtime / data-plane isolation per backend
//
// The admin API is `X-Ferrum-Namespace`-scoped (tested above). The proxy data
// plane is a different surface: it's scoped by the gateway's own
// `FERRUM_NAMESPACE` env var at load time. `load_full_config(namespace)` and
// the incremental poller both filter by namespace, so the RouterCache /
// PluginCache / ConsumerIndex only ever hold entries for one namespace —
// even when the underlying DB holds many.
//
// This test pins that end-to-end: a gateway booted with FERRUM_NAMESPACE=A
// against a DB that also contains B's proxies must serve A's listen_path
// and return 404 for B's listen_path, even though B is fully intact in the
// DB and still visible via the admin API with an `X-Ferrum-Namespace: B`
// header override.
// ---------------------------------------------------------------------------

/// Minimal always-200 echo HTTP server on a held listener. Used to assert
/// the gateway actually proxied the request through (vs returning a
/// gateway-local error).
async fn start_ns_echo_backend() -> (u16, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (reader, mut writer) = stream.into_split();
                let mut buf_reader = tokio::io::BufReader::new(reader);
                let mut line = String::new();
                if buf_reader.read_line(&mut line).await.is_err() {
                    return;
                }
                loop {
                    line.clear();
                    if buf_reader.read_line(&mut line).await.is_err() {
                        return;
                    }
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                }
                let body = r#"{"ok":true,"hit":"ns-echo"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = writer.write_all(resp.as_bytes()).await;
            });
        }
    });
    (port, handle)
}

async fn run_runtime_isolation_suite(backend: Backend) {
    // Unique namespace names so a reused external DB can't leak state from
    // prior runs.
    let active_ns = format!("active-{}", uuid::Uuid::new_v4().simple());
    let other_ns = format!("other-{}", uuid::Uuid::new_v4().simple());

    let Some(harness) = NsHarness::start_with_namespace(backend, Some(&active_ns)).await else {
        eprintln!(
            "Skipping runtime isolation suite for {} — backend unavailable",
            backend.db_type()
        );
        return;
    };

    let (backend_port, backend_task) = start_ns_echo_backend().await;

    let client = reqwest::Client::new();
    let base = harness.admin_base_url.clone();

    let active_path = format!("/active-{}", uuid::Uuid::new_v4().simple());
    let other_path = format!("/other-{}", uuid::Uuid::new_v4().simple());

    // Seed both namespaces via the admin API, using the header override to
    // reach the OTHER namespace even though the gateway itself is scoped to
    // `active_ns`.
    let r = admin_request(
        &client,
        reqwest::Method::POST,
        &format!("{base}/proxies"),
        Some(&active_ns),
        Some(&sample_proxy(
            &mk_id("active-proxy"),
            &active_path,
            backend_port,
        )),
    )
    .await;
    assert!(
        r.status().is_success(),
        "create active-namespace proxy failed: {}",
        r.status()
    );

    let r = admin_request(
        &client,
        reqwest::Method::POST,
        &format!("{base}/proxies"),
        Some(&other_ns),
        Some(&sample_proxy(
            &mk_id("other-proxy"),
            &other_path,
            backend_port,
        )),
    )
    .await;
    assert!(
        r.status().is_success(),
        "create other-namespace proxy via admin header failed: {}",
        r.status()
    );

    // Wait for the DB polling loop (FERRUM_DB_POLL_INTERVAL=1 in NsHarness)
    // to pick up the new rows. Poll the proxy port actively rather than
    // sleeping a fixed interval.
    let deadline = SystemTime::now() + Duration::from_secs(15);
    let active_url = format!("{}{}", harness.proxy_base_url, active_path);
    loop {
        if SystemTime::now() >= deadline {
            panic!("active namespace proxy never became routable within 15s");
        }
        match client.get(&active_url).send().await {
            Ok(r) if r.status().as_u16() != 404 => break,
            _ => tokio::time::sleep(Duration::from_millis(300)).await,
        }
    }

    // 1. Active namespace's listen_path must route through to the backend.
    let r = client
        .get(&active_url)
        .send()
        .await
        .expect("active route request");
    assert!(
        r.status().is_success(),
        "active-namespace proxy must route to backend: got {}",
        r.status()
    );
    let body: Value = r.json().await.expect("active response JSON");
    assert_eq!(
        body.get("hit").and_then(|v| v.as_str()),
        Some("ns-echo"),
        "response did not come from echo backend — gateway returned something else"
    );

    // 2. Other namespace's listen_path must be 404 — the gateway never
    //    loaded that proxy because FERRUM_NAMESPACE scopes config loading.
    let other_url = format!("{}{}", harness.proxy_base_url, other_path);
    let r = client
        .get(&other_url)
        .send()
        .await
        .expect("other route request");
    assert_eq!(
        r.status().as_u16(),
        404,
        "other-namespace listen_path must not resolve on a gateway scoped to {active_ns}"
    );

    // 3. The other namespace's proxy is still intact in the DB — confirm it
    //    via the admin API header override. This is the data-plane vs
    //    control-plane asymmetry the feature advertises: admin CRUD is
    //    header-scoped across all namespaces, but routing is env-scoped.
    let r = admin_request(
        &client,
        reqwest::Method::GET,
        &format!("{base}/proxies"),
        Some(&other_ns),
        None,
    )
    .await;
    assert!(
        r.status().is_success(),
        "admin GET /proxies in other namespace must still work"
    );
    let body: Value = r.json().await.expect("other ns list JSON");
    assert_only_namespace(&body, &other_ns);
    assert!(
        list_len(&body) >= 1,
        "other namespace should still contain its proxy"
    );

    backend_task.abort();
}

#[tokio::test]
#[ignore]
async fn runtime_isolation_sqlite() {
    run_runtime_isolation_suite(Backend::Sqlite).await;
}

#[tokio::test]
#[ignore]
async fn runtime_isolation_postgres() {
    run_runtime_isolation_suite(Backend::Postgres).await;
}

#[tokio::test]
#[ignore]
async fn runtime_isolation_mysql() {
    run_runtime_isolation_suite(Backend::Mysql).await;
}

#[tokio::test]
#[ignore]
async fn runtime_isolation_mongodb() {
    run_runtime_isolation_suite(Backend::Mongodb).await;
}
