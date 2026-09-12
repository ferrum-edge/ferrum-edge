//! End-to-end functional tests for the multi-namespace feature.
//!
//! Exercises the running `ferrum-edge` binary via the Admin API against each
//! supported database backend with the `X-Ferrum-Namespace` header, covering:
//!
//! - namespace-scoped CRUD for proxies / consumers / upstreams
//! - per-namespace uniqueness constraints (listen_path, name, username,
//!   custom_id) and stream-listener group admission — the same port is allowed
//!   across namespaces, while an invalid duplicate group is denied within one
//! - `X-Ferrum-Namespace` header defaulting to `ferrum`
//! - invalid namespace header rejection
//! - `GET /namespaces` returning the full set as a paginated envelope,
//!   regardless of the current header
//! - delete isolation (deleting a namespace's resource by id from another
//!   namespace returns 404)
//! - cross-process mTLS DNS-identity admission against a shared persistent
//!   backend
//! - cross-process MongoDB TCP-throttle graph admission under the durable
//!   namespace fence
//!
//! Backends:
//! - `sqlite`: runs unconditionally (tempdir-backed file DB)
//! - `postgres`: runs when `FERRUM_TEST_POSTGRES_URL` is set
//! - `mysql`: runs when `FERRUM_TEST_MYSQL_URL` is set
//! - `mongodb`: runs when `FERRUM_TEST_MONGO_URL` is set (or default
//!   `mongodb://localhost:27017/ferrum_test` is reachable, matching
//!   `functional_mongodb_test` conventions)
//!
//! Hosted CI sets `FERRUM_DB_BACKENDS_REQUIRED=1` so a missing expected
//! backend fails instead of silently skipping. Local developers keep the
//! historical opt-out by leaving that variable unset.
//!
//! All tests are `#[ignore]` — invoke with `cargo test --test functional_tests
//! -- --ignored namespace`.

use crate::scaffolding::port_registry::TestSocket;

use crate::common::{
    DbType, IsolatedSqlDatabase, TestGateway, continue_if_backend_available,
    ensure_shared_sql_containers_resumed, host_port_from_db_url, mysql_test_url, postgres_test_url,
    provision_isolated_sql_database, tcp_endpoint_reachable,
};
use serde_json::Value;
use std::time::{Duration, Instant};

use super::namespace_helpers::{
    JWT_ISSUER, JWT_SECRET, admin_request, assert_only_namespace, ephemeral_port, list_len,
    sample_consumer, sample_proxy, sample_proxy_with_name, sample_stream_proxy, sample_upstream,
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
/// external backend is unavailable and backends are not required — the
/// calling test should skip in that case. When `FERRUM_DB_BACKENDS_REQUIRED`
/// is set, missing/unreachable backends panic instead of returning `None`.
///
/// SQL backends also return an optional isolation guard so each cell uses a
/// dedicated database on the shared CI container.
async fn resolve_db(backend: Backend) -> Option<(DbType, Option<IsolatedSqlDatabase>)> {
    match backend {
        Backend::Sqlite => Some((DbType::Sqlite, None)),
        Backend::Postgres => {
            ensure_shared_sql_containers_resumed();
            let url = postgres_test_url()?;
            let host_port = host_port_from_db_url(&url);
            if !continue_if_backend_available(
                "postgres",
                tcp_endpoint_reachable(&host_port).await,
                &format!("not reachable at {host_port}"),
            ) {
                return None;
            }
            let (url, isolated) = provision_isolated_sql_database(&url);
            Some((DbType::Postgres(url), isolated))
        }
        Backend::Mysql => {
            ensure_shared_sql_containers_resumed();
            let url = mysql_test_url()?;
            let host_port = host_port_from_db_url(&url);
            if !continue_if_backend_available(
                "mysql",
                tcp_endpoint_reachable(&host_port).await,
                &format!("not reachable at {host_port}"),
            ) {
                return None;
            }
            let (url, isolated) = provision_isolated_sql_database(&url);
            Some((DbType::MySql(url), isolated))
        }
        Backend::Mongodb => {
            let url = std::env::var("FERRUM_TEST_MONGO_URL")
                .unwrap_or_else(|_| "mongodb://localhost:27017/ferrum_test".to_string());
            let host_port = host_port_from_db_url(&url);
            if !continue_if_backend_available(
                "mongodb",
                tcp_endpoint_reachable(&host_port).await,
                &format!("not reachable at {host_port}"),
            ) {
                return None;
            }
            Some((DbType::Mongo(url), None))
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
    _gw: TestGateway,
    admin_base_url: String,
    proxy_base_url: String,
    // Struct fields drop in declaration order. Keep this after the gateway so
    // its pool releases every DB connection before DROP DATABASE.
    _isolated_db: Option<IsolatedSqlDatabase>,
}

/// Two independent gateway processes sharing one persistent backend. The
/// optional tempdir owns the shared SQLite file for the lifetime of both
/// processes; external backends use a randomized namespace instead.
struct SharedAdminHarness {
    _gateway_a: TestGateway,
    _gateway_b: TestGateway,
    _sqlite_dir: Option<tempfile::TempDir>,
    admin_a: String,
    admin_b: String,
    // Struct fields drop in declaration order. Keep this after both gateways
    // so their pools release every DB connection before DROP DATABASE.
    _isolated_db: Option<IsolatedSqlDatabase>,
}

impl SharedAdminHarness {
    async fn start(backend: Backend) -> Option<Self> {
        let (db, sqlite_dir, isolated_db) = match backend {
            Backend::Sqlite => {
                let temp_dir = tempfile::TempDir::new().expect("shared SQLite tempdir");
                let db_path = temp_dir.path().join("shared-admin.db");
                let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
                (
                    DbType::Custom {
                        db_type: "sqlite".to_string(),
                        db_url,
                    },
                    Some(temp_dir),
                    None,
                )
            }
            _ => {
                let (db, isolated) = resolve_db(backend).await?;
                (db, None, isolated)
            }
        };

        let builder = || {
            let mut builder = TestGateway::builder()
                .mode_database(db.clone())
                .jwt_secret(JWT_SECRET)
                .jwt_issuer(JWT_ISSUER)
                .db_poll_interval_seconds(1)
                .max_attempts(3)
                .log_level("warn");
            if matches!(backend, Backend::Mongodb) {
                builder = builder.env("FERRUM_MONGO_DATABASE", "ferrum_test");
            }
            builder
        };

        let gateway_a = builder()
            .spawn()
            .await
            .unwrap_or_else(|error| panic!("first shared admin gateway failed: {error}"));
        let gateway_b = builder()
            .spawn()
            .await
            .unwrap_or_else(|error| panic!("second shared admin gateway failed: {error}"));
        Some(Self {
            admin_a: gateway_a.admin_base_url.clone(),
            admin_b: gateway_b.admin_base_url.clone(),
            _gateway_a: gateway_a,
            _gateway_b: gateway_b,
            _sqlite_dir: sqlite_dir,
            _isolated_db: isolated_db,
        })
    }
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
            let (db, isolated_db) = match resolve_db(backend).await {
                Some(db) => db,
                None => return None,
            };
            if let Some(db_url) = match &db {
                DbType::Sqlite => None,
                DbType::Postgres(url)
                | DbType::MySql(url)
                | DbType::Mongo(url)
                | DbType::Custom { db_url: url, .. } => Some(url.as_str()),
            } {
                reset_backend(backend, db_url).await;
            }

            let mut builder = TestGateway::builder()
                .mode_database(db)
                .jwt_secret(JWT_SECRET)
                .jwt_issuer(JWT_ISSUER)
                .db_poll_interval_seconds(1)
                // The outer loop resets the backing store between attempts,
                // so each harness attempt should be a single fresh spawn.
                .max_attempts(1)
                .log_level("warn");
            if matches!(backend, Backend::Mongodb) {
                builder = builder.env("FERRUM_MONGO_DATABASE", "ferrum_test");
            }
            if let Some(ns) = gateway_namespace {
                builder = builder.namespace(ns);
            }

            let gw = match builder.spawn().await {
                Ok(gw) => gw,
                Err(e) => {
                    last_err = format!("spawn: {e}");
                    eprintln!("namespace harness retry {attempt}/{MAX_ATTEMPTS}: {last_err}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            return Some(Self {
                admin_base_url: gw.admin_base_url.clone(),
                proxy_base_url: gw.proxy_base_url.clone(),
                _gw: gw,
                _isolated_db: isolated_db,
            });
        }
        panic!("namespace harness failed to start: {last_err}");
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

    // --- stream listener-group namespace isolation -----------------------
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
        "an invalid same-namespace listener group must be rejected"
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
        let names: Vec<&str> = body["data"]
            .as_array()
            .expect("namespaces data array")
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

/// Reproduces the original cross-process race: one admin process activates a
/// proxy-scoped `san_dns` policy while a second rotates another Consumer onto
/// a case variant of an existing DNS identity. Exactly one transaction may
/// commit, and the loser must receive a conflict from every persistent backend.
async fn run_mtls_dns_cross_process_admission_suite(backend: Backend) {
    let Some(harness) = SharedAdminHarness::start(backend).await else {
        eprintln!(
            "Skipping mTLS DNS cross-process suite for {} — backend unavailable",
            backend.db_type()
        );
        return;
    };
    let client = reqwest::Client::new();
    let namespace = format!("mtls-dns-{}", uuid::Uuid::new_v4().simple());
    let owner_id = mk_id("mtls-owner");
    let rotating_id = mk_id("mtls-rotating");
    let proxy_id = mk_id("mtls-proxy");
    let plugin_id = mk_id("mtls-policy");

    let owner = serde_json::json!({
        "id": owner_id,
        "username": mk_id("owner-user"),
        "credentials": {
            "mtls_auth": [{"identity": "API.Example.COM"}]
        }
    });
    let rotating = serde_json::json!({
        "id": rotating_id,
        "username": mk_id("rotating-user")
    });
    for consumer in [&owner, &rotating] {
        let response = admin_request(
            &client,
            reqwest::Method::POST,
            &format!("{}/consumers", harness.admin_a),
            Some(&namespace),
            Some(consumer),
        )
        .await;
        assert!(
            response.status().is_success(),
            "{} consumer setup failed with {}",
            backend.db_type(),
            response.status()
        );
    }

    let proxy = serde_json::json!({
        "id": proxy_id,
        "hosts": [format!("{}.test", uuid::Uuid::new_v4().simple())],
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 9
    });
    let response = admin_request(
        &client,
        reqwest::Method::POST,
        &format!("{}/proxies", harness.admin_a),
        Some(&namespace),
        Some(&proxy),
    )
    .await;
    assert!(response.status().is_success(), "proxy setup failed");

    let policy = serde_json::json!({
        "id": plugin_id,
        "plugin_name": "mtls_auth",
        "scope": "proxy",
        "proxy_id": proxy_id,
        "enabled": true,
        "config": {"cert_field": "san_dns"}
    });
    let response = admin_request(
        &client,
        reqwest::Method::POST,
        &format!("{}/plugins/config", harness.admin_a),
        Some(&namespace),
        Some(&policy),
    )
    .await;
    assert!(response.status().is_success(), "policy setup failed");

    let mut associated_proxy = proxy.clone();
    associated_proxy["plugins"] = serde_json::json!([{"plugin_config_id": plugin_id}]);
    let mut rotated_consumer = rotating.clone();
    rotated_consumer["credentials"] = serde_json::json!({
        "mtls_auth": [{"identity": "api.example.com"}]
    });
    let association_url = format!("{}/proxies/{}", harness.admin_a, proxy_id);
    let rotation_url = format!("{}/consumers/{}", harness.admin_b, rotating_id);

    let (association_response, rotation_response) = tokio::join!(
        admin_request(
            &client,
            reqwest::Method::PUT,
            &association_url,
            Some(&namespace),
            Some(&associated_proxy),
        ),
        admin_request(
            &client,
            reqwest::Method::PUT,
            &rotation_url,
            Some(&namespace),
            Some(&rotated_consumer),
        )
    );
    let statuses = [association_response.status(), rotation_response.status()];
    assert_eq!(
        statuses.iter().filter(|status| status.is_success()).count(),
        1,
        "{} must admit exactly one concurrent candidate: {statuses:?}",
        backend.db_type()
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| status.as_u16() == 409)
            .count(),
        1,
        "{} loser must fail closed with 409: {statuses:?}",
        backend.db_type()
    );

    let stored_proxy: Value = admin_request(
        &client,
        reqwest::Method::GET,
        &format!("{}/proxies/{}", harness.admin_a, proxy_id),
        Some(&namespace),
        None,
    )
    .await
    .json()
    .await
    .unwrap();
    let stored_consumer: Value = admin_request(
        &client,
        reqwest::Method::GET,
        &format!("{}/consumers/{}", harness.admin_b, rotating_id),
        Some(&namespace),
        None,
    )
    .await
    .json()
    .await
    .unwrap();
    let policy_active = stored_proxy["plugins"]
        .as_array()
        .is_some_and(|plugins| !plugins.is_empty());
    let rotation_active = stored_consumer["credentials"].get("mtls_auth").is_some();
    assert_ne!(policy_active, rotation_active);
}

/// Exercise the Mongo durable-fence ordering behaviorally with two independent
/// admin processes. A global TCP throttle and an HTTP proxy are each valid
/// against the initial empty graph, but their aggregate graph is invalid. The
/// lease owner must re-read and validate after acquisition, before mutation, so
/// exactly one write commits and the other fails closed.
async fn run_tcp_throttle_cross_process_admission_mongodb() {
    let Some(harness) = SharedAdminHarness::start(Backend::Mongodb).await else {
        eprintln!("Skipping TCP-throttle Mongo admission suite — backend unavailable");
        return;
    };
    let client = reqwest::Client::new();
    let namespace = format!("tcp-throttle-{}", uuid::Uuid::new_v4().simple());
    let proxy_id = mk_id("http-only");
    let plugin_id = mk_id("global-tcp-throttle");
    let proxy = serde_json::json!({
        "id": proxy_id,
        "hosts": [format!("{}.test", uuid::Uuid::new_v4().simple())],
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 9
    });
    let throttle = serde_json::json!({
        "id": plugin_id,
        "plugin_name": "tcp_connection_throttle",
        "scope": "global",
        "enabled": true,
        "config": {"max_connections_per_key": 1}
    });
    let proxy_url = format!("{}/proxies", harness.admin_a);
    let throttle_url = format!("{}/plugins/config", harness.admin_b);

    let (proxy_response, throttle_response) = tokio::join!(
        admin_request(
            &client,
            reqwest::Method::POST,
            &proxy_url,
            Some(&namespace),
            Some(&proxy),
        ),
        admin_request(
            &client,
            reqwest::Method::POST,
            &throttle_url,
            Some(&namespace),
            Some(&throttle),
        )
    );
    let statuses = [proxy_response.status(), throttle_response.status()];
    assert_eq!(
        statuses.iter().filter(|status| status.is_success()).count(),
        1,
        "Mongo durable admission must commit exactly one individually-valid write: {statuses:?}"
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| status.as_u16() == 400)
            .count(),
        1,
        "Mongo durable admission loser must fail closed with 400: {statuses:?}"
    );

    let stored_proxy = admin_request(
        &client,
        reqwest::Method::GET,
        &format!("{}/proxies/{}", harness.admin_a, proxy_id),
        Some(&namespace),
        None,
    )
    .await;
    let stored_throttle = admin_request(
        &client,
        reqwest::Method::GET,
        &format!("{}/plugins/config/{}", harness.admin_b, plugin_id),
        Some(&namespace),
        None,
    )
    .await;
    assert_ne!(
        stored_proxy.status().is_success(),
        stored_throttle.status().is_success(),
        "the persisted Mongo graph must contain only the winning resource"
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

#[tokio::test]
#[ignore]
async fn mtls_dns_cross_process_admission_sqlite() {
    run_mtls_dns_cross_process_admission_suite(Backend::Sqlite).await;
}

#[tokio::test]
#[ignore]
async fn mtls_dns_cross_process_admission_postgres() {
    run_mtls_dns_cross_process_admission_suite(Backend::Postgres).await;
}

#[tokio::test]
#[ignore]
async fn mtls_dns_cross_process_admission_mysql() {
    run_mtls_dns_cross_process_admission_suite(Backend::Mysql).await;
}

#[tokio::test]
#[ignore]
async fn mtls_dns_cross_process_admission_mongodb() {
    run_mtls_dns_cross_process_admission_suite(Backend::Mongodb).await;
}

#[tokio::test]
#[ignore]
async fn tcp_throttle_cross_process_admission_mongodb() {
    run_tcp_throttle_cross_process_admission_mongodb().await;
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

    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .unwrap();
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
    let deadline = Instant::now() + Duration::from_secs(30);
    let active_url = format!("{}{}", harness.proxy_base_url, active_path);
    loop {
        if Instant::now() >= deadline {
            panic!("active namespace proxy never became routable within 30s");
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
