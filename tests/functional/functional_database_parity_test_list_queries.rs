//! Admin list `q` / `ids` / `applies_to_proxy` / `pagination.revision` /
//! `if_revision` parity across every store and the cached-config path.
//!
//! One scenario runs, through the real binary's Admin API, against SQLite,
//! PostgreSQL, MySQL, standalone MongoDB, a MongoDB replica set, and file mode
//! (served from the in-memory config). The same fixture must produce the same
//! answers everywhere, including the case-folding edge cases (the Kelvin sign
//! `U+212A`, which Unicode folding maps to `k`, and `É`/`é`) and the `LIKE`
//! metacharacters `%` and `_`.
//!
//! The module name extends `functional_database_parity_test` so the
//! `data-plane-runtime` functional shard (which provisions PostgreSQL, MySQL
//! and both MongoDB topologies and sets `FERRUM_DB_BACKENDS_REQUIRED=1`)
//! selects it through that filter's substring match.

use crate::common::{
    DbType, TestGateway, continue_if_backend_available, ensure_shared_sql_containers_resumed,
    host_port_from_db_url, mysql_test_url, postgres_test_url, provision_isolated_sql_database,
    tcp_endpoint_reachable,
};
use reqwest::{Client, Method, StatusCode};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use uuid::Uuid;

const DEFAULT_MONGO_URL: &str = "mongodb://localhost:27017/ferrum_test";

/// Drops a per-test MongoDB database on exit.
struct MongoDatabaseCleanup {
    url: String,
    database: String,
}

impl Drop for MongoDatabaseCleanup {
    fn drop(&mut self) {
        let url = self.url.clone();
        let database = self.database.clone();
        let handle = std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            runtime.block_on(async move {
                if let Ok(client) = mongodb::Client::with_uri_str(&url).await {
                    let _ = client.database(&database).drop().await;
                }
            });
        });
        let _ = handle.join();
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

const KELVIN_NAME: &str = "\u{212A}ey service";

fn proxy_body(id: &str, name: &str, listen_path: &str, hosts: &[&str], plugins: &[&str]) -> Value {
    json!({
        "id": id,
        "name": name,
        "listen_path": listen_path,
        "hosts": hosts,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 9,
        "plugins": plugins
            .iter()
            .map(|id| json!({"plugin_config_id": id}))
            .collect::<Vec<_>>(),
    })
}

fn upstreams() -> Vec<Value> {
    ["u-alpha:Alpha Pool", "u-beta:beta-pool", "u-gamma:Gamma"]
        .iter()
        .map(|spec| {
            let (id, name) = spec.split_once(':').unwrap();
            json!({"id": id, "name": name, "targets": [{"host": "127.0.0.1", "port": 9}]})
        })
        .collect()
}

fn consumers() -> Vec<Value> {
    vec![
        json!({"id": "c-alice", "username": "Alice", "custom_id": "CRM-1"}),
        json!({"id": "c-bob", "username": "bob"}),
        json!({"id": "c-accent", "username": "café"}),
    ]
}

/// Proxies with their final association lists.
fn proxies() -> Vec<Value> {
    vec![
        proxy_body(
            "px-orders",
            "Orders API",
            "/orders",
            &["orders.example.com"],
            &["grp-rl", "p-cors-a", "p-rsl-a"],
        ),
        proxy_body("px-users", "Users", "/users", &[], &[]),
        proxy_body("px-kelvin", KELVIN_NAME, "/kelvin", &[], &[]),
        proxy_body("px-pct", "50% off", "/pct", &[], &[]),
        proxy_body("px-under", "a_b", "/under", &[], &[]),
        proxy_body("px-axb", "axb", "/axb", &[], &[]),
    ]
}

fn plugin_configs() -> Vec<Value> {
    let pc = |id: &str, name: &str, config: Value, scope: &str, proxy_id: Option<&str>| {
        json!({
            "id": id,
            "plugin_name": name,
            "config": config,
            "scope": scope,
            "proxy_id": proxy_id,
            "enabled": true,
        })
    };
    let rate = json!({"limits": [{"scope": "default", "window_seconds": 60, "max_requests": 100}]});
    let size = json!({"max_bytes": 1048576});
    vec![
        pc(
            "g-cors",
            "cors",
            json!({"allowed_origins": ["*"]}),
            "global",
            None,
        ),
        pc("g-rl", "rate_limiting", rate.clone(), "global", None),
        pc(
            "g-rsl",
            "request_size_limiting",
            size.clone(),
            "global",
            None,
        ),
        pc(
            "g-ip",
            "ip_restriction",
            json!({"allow": ["0.0.0.0/0"]}),
            "global",
            None,
        ),
        pc(
            "p-cors-a",
            "cors",
            json!({"allowed_origins": ["https://orders.example.com"]}),
            "proxy",
            Some("px-orders"),
        ),
        pc(
            "p-rsl-a",
            "request_size_limiting",
            size,
            "proxy",
            Some("px-orders"),
        ),
        pc("grp-rl", "rate_limiting", rate, "proxy_group", None),
    ]
}

fn file_mode_config() -> String {
    // JSON is valid YAML for the file loader. Intentionally keep collections
    // unsorted (reverse id order) to prove the cached-config list path sorts
    // canonically by `id` just like every database backend.
    let reversed = |mut items: Vec<Value>| {
        items.sort_by(|left, right| right["id"].as_str().cmp(&left["id"].as_str()));
        items
    };
    let mut proxies = reversed(proxies());
    for proxy in &mut proxies {
        proxy["namespace"] = json!("ferrum");
    }
    let consumers = reversed(consumers());
    let upstreams = reversed(upstreams());
    let plugin_configs = reversed(plugin_configs());
    serde_json::to_string(&json!({
        "version": "1",
        "proxies": proxies,
        "consumers": consumers,
        "upstreams": upstreams,
        "plugin_configs": plugin_configs,
    }))
    .unwrap()
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

struct Admin<'a> {
    gateway: &'a TestGateway,
    client: Client,
}

impl<'a> Admin<'a> {
    fn new(gateway: &'a TestGateway) -> Self {
        Self {
            gateway,
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
        }
    }

    async fn send(&self, method: Method, path: &str, body: Option<&Value>) -> (StatusCode, Value) {
        let mut request = self
            .client
            .request(method, self.gateway.admin_url(path))
            .header("Authorization", self.gateway.auth_header());
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.expect("admin request");
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        (status, body)
    }

    async fn get(&self, path: &str) -> (StatusCode, Value) {
        self.send(Method::GET, path, None).await
    }

    async fn ok(&self, path: &str) -> Value {
        let (status, body) = self.get(path).await;
        assert_eq!(status, StatusCode::OK, "GET {path}: {body}");
        body
    }

    async fn write(&self, method: Method, path: &str, body: Option<&Value>) {
        let (status, response) = self.send(method.clone(), path, body).await;
        assert!(
            status.is_success(),
            "{method} {path} failed with {status}: {response}"
        );
    }
}

fn ids(body: &Value) -> Vec<String> {
    body["data"]
        .as_array()
        .unwrap_or_else(|| panic!("list envelope: {body}"))
        .iter()
        .map(|item| item["id"].as_str().unwrap().to_string())
        .collect()
}

fn revision(body: &Value) -> String {
    body["pagination"]["revision"]
        .as_str()
        .unwrap_or_else(|| panic!("pagination.revision: {body}"))
        .to_string()
}

fn q(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

async fn seed_through_admin(admin: &Admin<'_>) {
    for upstream in upstreams() {
        admin
            .write(Method::POST, "/upstreams?apply=async", Some(&upstream))
            .await;
    }
    for consumer in consumers() {
        admin
            .write(Method::POST, "/consumers?apply=async", Some(&consumer))
            .await;
    }
    // Proxies first without associations (proxy-scoped plugin configs need
    // their proxy), then the plugin configs, then the associations.
    for proxy in proxies() {
        let mut bare = proxy.clone();
        bare["plugins"] = json!([]);
        admin
            .write(Method::POST, "/proxies?apply=async", Some(&bare))
            .await;
    }
    for plugin_config in plugin_configs() {
        admin
            .write(
                Method::POST,
                "/plugins/config?apply=async",
                Some(&plugin_config),
            )
            .await;
    }
    let orders = proxies()
        .into_iter()
        .find(|proxy| proxy["id"] == "px-orders")
        .unwrap();
    admin
        .write(Method::PUT, "/proxies/px-orders?apply=async", Some(&orders))
        .await;
}

// ---------------------------------------------------------------------------
// Scenario
// ---------------------------------------------------------------------------

async fn assert_search_ids_and_applies_to(admin: &Admin<'_>, label: &str) {
    let list = |path: &str, query: &str| format!("{path}?q={}", q(query));
    let cases: &[(&str, &str, &[&str])] = &[
        // name, listen_path and host all reach px-orders.
        ("/proxies", "ORDERS", &["px-orders"]),
        ("/proxies", "Example.COM", &["px-orders"]),
        ("/proxies", "/USERS", &["px-users"]),
        // Kelvin sign is not folded to `k`; the literal suffix still matches.
        ("/proxies", "key serv", &[]),
        ("/proxies", "ey serv", &["px-kelvin"]),
        // LIKE metacharacters are literals.
        ("/proxies", "50%", &["px-pct"]),
        ("/proxies", "%", &["px-pct"]),
        ("/proxies", "a_b", &["px-under"]),
        ("/proxies", "_", &["px-under"]),
        ("/proxies", "!", &[]),
        // Host matching never spans the stored JSON array.
        ("/proxies", "com\",\"", &[]),
        ("/consumers", "ALICE", &["c-alice"]),
        ("/consumers", "crm-1", &["c-alice"]),
        ("/consumers", "café", &["c-accent"]),
        ("/consumers", "CAFÉ", &[]),
        ("/consumers", "cafe", &[]),
        ("/upstreams", "POOL", &["u-alpha", "u-beta"]),
        ("/plugins/config", "RATE_", &["g-rl", "grp-rl"]),
        ("/plugins/config", "p-", &["grp-rl", "p-cors-a", "p-rsl-a"]),
    ];
    for (path, term, expected) in cases {
        let body = admin.ok(&list(path, term)).await;
        assert_eq!(ids(&body), expected.to_vec(), "{label}: {path}?q={term:?}");
        assert_eq!(
            body["pagination"]["total"],
            json!(expected.len()),
            "{label}: total counts matches for {path}?q={term:?}"
        );
    }

    // Empty q is no search.
    let all = admin.ok("/proxies?q=").await;
    assert_eq!(all["pagination"]["total"], json!(6), "{label}");
    // Pagination over matches.
    let page = admin.ok("/upstreams?q=pool&limit=1&offset=1").await;
    assert_eq!(ids(&page), ["u-beta"], "{label}");
    assert_eq!(page["pagination"]["total"], json!(2), "{label}");

    // Bad q.
    let too_long = "a".repeat(257);
    for path in [
        format!("/proxies?q={too_long}"),
        "/proxies?q=a&q=b".to_string(),
        "/consumers?q=%0A".to_string(),
    ] {
        let (status, _) = admin.get(&path).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}: {path}");
    }

    // ids: missing ids are absent, order is by id.
    let body = admin.ok("/proxies?ids=px-users,px-orders,px-missing").await;
    assert_eq!(ids(&body), ["px-orders", "px-users"], "{label}");
    assert_eq!(body["pagination"]["total"], json!(2), "{label}");
    let body = admin.ok("/consumers?ids=c-bob").await;
    assert_eq!(ids(&body), ["c-bob"], "{label}");
    let body = admin.ok("/upstreams?ids=u-gamma,u-alpha").await;
    assert_eq!(ids(&body), ["u-alpha", "u-gamma"], "{label}");
    let body = admin.ok("/plugins/config?ids=g-ip,grp-rl&q=rate").await;
    assert_eq!(ids(&body), ["grp-rl"], "{label}: ids AND q");
    let over: Vec<String> = (0..101).map(|i| format!("id{i}")).collect();
    for path in [
        "/proxies?ids=a,a".to_string(),
        "/proxies?ids=".to_string(),
        "/proxies?ids=a,,b".to_string(),
        format!("/consumers?ids={}", over.join(",")),
        "/upstreams?ids=bad%20id".to_string(),
    ] {
        let (status, _) = admin.get(&path).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}: {path}");
    }

    // applies_to_proxy: the plugin cache's own scope rule (the unit test
    // `plugin_cache_applies_to_proxy_tests` proves the same rule against a
    // built PluginCache for this fixture shape).
    let body = admin.ok("/plugins/config?applies_to_proxy=px-orders").await;
    assert_eq!(
        ids(&body),
        ["g-ip", "g-rsl", "grp-rl", "p-cors-a", "p-rsl-a"],
        "{label}: effective plugins of px-orders"
    );
    assert_eq!(body["pagination"]["total"], json!(5), "{label}");
    let body = admin.ok("/plugins/config?applies_to_proxy=px-users").await;
    assert_eq!(
        ids(&body),
        ["g-cors", "g-ip", "g-rl", "g-rsl"],
        "{label}: effective plugins of px-users"
    );
    let body = admin
        .ok("/plugins/config?applies_to_proxy=px-orders&q=cors")
        .await;
    assert_eq!(ids(&body), ["p-cors-a"], "{label}: applies_to AND q");
    let body = admin
        .ok("/plugins/config?applies_to_proxy=px-orders&limit=2&offset=2")
        .await;
    assert_eq!(ids(&body), ["grp-rl", "p-cors-a"], "{label}: paginated");
    let (status, body) = admin
        .get("/plugins/config?applies_to_proxy=px-missing")
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{label}: {body}");
    let (status, _) = admin.get("/plugins/config?applies_to_proxy=bad%20id").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{label}");
    // Unknown on other routes: ignored like any unknown parameter.
    let body = admin.ok("/proxies?applies_to_proxy=px-orders").await;
    assert_eq!(body["pagination"]["total"], json!(6), "{label}");

    // Every list carries a revision; a stale one is a 409.
    for path in ["/proxies", "/consumers", "/upstreams", "/plugins/config"] {
        let body = admin.ok(path).await;
        let current = revision(&body);
        let body = admin.ok(&format!("{path}?if_revision={current}")).await;
        assert_eq!(revision(&body), current, "{label}: {path}");
        let (status, body) = admin.get(&format!("{path}?if_revision=s0stale")).await;
        assert_eq!(status, StatusCode::CONFLICT, "{label}: {path}: {body}");
        assert_eq!(body["revision"], json!(current), "{label}: {path}");
    }
    let (status, _) = admin.get("/proxies?if_revision=").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{label}");
}

/// A same-size change between two pages is detected (database modes).
async fn assert_same_size_change_is_detected(admin: &Admin<'_>, label: &str) {
    let first = admin.ok("/proxies?limit=2").await;
    let walk_revision = revision(&first);
    assert!(walk_revision.starts_with('s'), "{label}: {walk_revision}");
    let second = admin
        .ok(&format!(
            "/proxies?limit=2&offset=2&if_revision={walk_revision}"
        ))
        .await;
    assert_eq!(revision(&second), walk_revision, "{label}");

    // Other collections do not move the proxy revision.
    let consumers_before = revision(&admin.ok("/consumers").await);
    admin
        .write(Method::DELETE, "/proxies/px-axb?apply=async", None)
        .await;
    admin
        .write(
            Method::POST,
            "/proxies?apply=async",
            Some(&proxy_body("px-axc", "axc", "/axc", &[], &[])),
        )
        .await;
    let same_size = admin.ok("/proxies").await;
    assert_eq!(same_size["pagination"]["total"], json!(6), "{label}");
    assert_ne!(revision(&same_size), walk_revision, "{label}");
    let (status, body) = admin
        .get(&format!(
            "/proxies?limit=2&offset=2&if_revision={walk_revision}"
        ))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{label}: {body}");
    assert_eq!(body["revision"], json!(revision(&same_size)), "{label}");
    assert_eq!(
        revision(&admin.ok("/consumers").await),
        consumers_before,
        "{label}: a proxy write must not move the consumer revision"
    );

    // An association change moves the applies_to_proxy revision.
    let applied = admin.ok("/plugins/config?applies_to_proxy=px-users").await;
    let applied_revision = revision(&applied);
    let mut users = proxy_body("px-users", "Users", "/users", &[], &["grp-rl"]);
    users["namespace"] = json!("ferrum");
    admin
        .write(Method::PUT, "/proxies/px-users?apply=async", Some(&users))
        .await;
    let (status, _) = admin
        .get(&format!(
            "/plugins/config?applies_to_proxy=px-users&if_revision={applied_revision}"
        ))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{label}");
    let applied = admin.ok("/plugins/config?applies_to_proxy=px-users").await;
    assert_eq!(
        ids(&applied),
        ["g-cors", "g-ip", "g-rsl", "grp-rl"],
        "{label}: the group limiter now shadows g-rl"
    );
}

/// Concurrent same-size churn: every walk that completes without a 409
/// observed one consistent collection state.
async fn assert_walks_are_consistent_under_concurrent_churn(admin: &Admin<'_>, label: &str) {
    let stop = Arc::new(AtomicBool::new(false));
    let base: BTreeSet<String> = ids(&admin.ok("/consumers").await).into_iter().collect();

    admin
        .write(
            Method::POST,
            "/consumers?apply=async",
            Some(&json!({"id": "c-churn-0", "username": "churn-0"})),
        )
        .await;

    // Deterministic controlled interleaving: mutate mid-walk and verify 409
    // regardless of scheduler timing during the concurrent churn loop below.
    {
        let first = admin.ok("/consumers?limit=1").await;
        let walk_revision = revision(&first);
        admin
            .write(Method::DELETE, "/consumers/c-churn-0?apply=async", None)
            .await;
        admin
            .write(
                Method::POST,
                "/consumers?apply=async",
                Some(&json!({"id": "c-churn-0", "username": "churn-0"})),
            )
            .await;
        let (status, body) = admin
            .get(&format!(
                "/consumers?limit=1&offset=1&if_revision={walk_revision}"
            ))
            .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "{label}: deterministic mid-walk same-size change must produce 409: {body}"
        );
    }

    let writer = {
        let client = Client::new();
        let url = admin.gateway.admin_url("");
        let auth = admin.gateway.auth_header();
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut current = 0u32;
            for next in 1..=25u32 {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let delete = client
                    .delete(format!("{url}/consumers/c-churn-{current}?apply=async"))
                    .header("Authorization", &auth)
                    .send()
                    .await
                    .expect("churn delete");
                assert!(delete.status().is_success(), "churn delete");
                let create = client
                    .post(format!("{url}/consumers?apply=async"))
                    .header("Authorization", &auth)
                    .json(&json!({"id": format!("c-churn-{next}"), "username": format!("churn-{next}")}))
                    .send()
                    .await
                    .expect("churn create");
                assert!(create.status().is_success(), "churn create");
                current = next;
            }
        })
    };

    let mut _completed = 0usize;
    while !writer.is_finished() {
        let (first_status, first) = admin.get("/consumers?limit=1").await;
        if first_status == StatusCode::SERVICE_UNAVAILABLE {
            // Revision bracket exhausted retries under concurrent churn; retry walk.
            continue;
        }
        assert_eq!(first_status, StatusCode::OK, "{label}: {first}");
        let walk_revision = revision(&first);
        let total = first["pagination"]["total"].as_u64().unwrap() as usize;
        let mut seen: Vec<String> = ids(&first);
        let mut aborted = false;
        for offset in 1..total {
            let (status, body) = admin
                .get(&format!(
                    "/consumers?limit=1&offset={offset}&if_revision={walk_revision}"
                ))
                .await;
            if status == StatusCode::CONFLICT || status == StatusCode::SERVICE_UNAVAILABLE {
                aborted = true;
                break;
            }
            assert_eq!(status, StatusCode::OK, "{label}: {body}");
            assert_eq!(revision(&body), walk_revision, "{label}");
            seen.extend(ids(&body));
        }
        if aborted {
            continue;
        }
        _completed += 1;
        let unique: BTreeSet<String> = seen.iter().cloned().collect();
        assert_eq!(
            unique.len(),
            seen.len(),
            "{label}: duplicate in walk {seen:?}"
        );
        assert_eq!(seen.len(), total, "{label}: walk length vs total {seen:?}");
        // Between a delete and its create the collection holds no churn
        // consumer; otherwise exactly one. A torn walk would show two (or a
        // count that disagrees with `total`).
        let churn = unique
            .iter()
            .filter(|id| id.starts_with("c-churn-"))
            .count();
        assert_eq!(
            churn,
            total - base.len(),
            "{label}: churn consumers in a consistent walk: {seen:?}"
        );
        let rest: BTreeSet<String> = unique
            .into_iter()
            .filter(|id| !id.starts_with("c-churn-"))
            .collect();
        assert_eq!(rest, base, "{label}: stable consumers in walk {seen:?}");
    }
    stop.store(true, Ordering::Relaxed);
    writer.await.expect("churn writer");
}

async fn run_database_scenario(gateway: &TestGateway, label: &str, concurrent: bool) {
    let admin = Admin::new(gateway);
    seed_through_admin(&admin).await;
    assert_search_ids_and_applies_to(&admin, label).await;
    assert_same_size_change_is_detected(&admin, label).await;
    if concurrent {
        assert_walks_are_consistent_under_concurrent_churn(&admin, label).await;
    }
}

// ---------------------------------------------------------------------------
// Backends
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn test_admin_list_queries_sqlite() {
    let gateway = TestGateway::builder()
        .mode_database_sqlite()
        .log_level("warn")
        .db_poll_interval_seconds(1)
        .spawn()
        .await
        .expect("spawn sqlite gateway");
    run_database_scenario(&gateway, "sqlite", true).await;
}

#[tokio::test]
#[ignore]
async fn test_admin_list_queries_postgres() {
    ensure_shared_sql_containers_resumed();
    let Some(url) = postgres_test_url() else {
        return;
    };
    let host_port = host_port_from_db_url(&url);
    if !continue_if_backend_available(
        "postgres",
        tcp_endpoint_reachable(&host_port).await,
        &format!("not reachable at {host_port}"),
    ) {
        return;
    }
    let (url, _isolated_db) = provision_isolated_sql_database(&url);
    let gateway = TestGateway::builder()
        .mode_database(DbType::Postgres(url))
        .log_level("warn")
        .db_poll_interval_seconds(1)
        .spawn()
        .await
        .expect("spawn postgres gateway");
    run_database_scenario(&gateway, "postgres", true).await;
}

#[tokio::test]
#[ignore]
async fn test_admin_list_queries_mysql() {
    ensure_shared_sql_containers_resumed();
    let Some(url) = mysql_test_url() else {
        return;
    };
    let host_port = host_port_from_db_url(&url);
    if !continue_if_backend_available(
        "mysql",
        tcp_endpoint_reachable(&host_port).await,
        &format!("not reachable at {host_port}"),
    ) {
        return;
    }
    let (url, _isolated_db) = provision_isolated_sql_database(&url);
    let gateway = TestGateway::builder()
        .mode_database(DbType::MySql(url))
        .log_level("warn")
        .db_poll_interval_seconds(1)
        .spawn()
        .await
        .expect("spawn mysql gateway");
    run_database_scenario(&gateway, "mysql", true).await;
}

#[tokio::test]
#[ignore]
async fn test_admin_list_queries_mongodb_standalone() {
    let url =
        std::env::var("FERRUM_TEST_MONGO_URL").unwrap_or_else(|_| DEFAULT_MONGO_URL.to_string());
    let host_port = host_port_from_db_url(&url);
    if !continue_if_backend_available(
        "mongodb",
        tcp_endpoint_reachable(&host_port).await,
        &format!("not available at {host_port}"),
    ) {
        return;
    }
    let database = format!("ferrum_list_queries_{}", Uuid::new_v4().simple());
    let _cleanup = MongoDatabaseCleanup {
        url: url.clone(),
        database: database.clone(),
    };
    let gateway = TestGateway::builder()
        .mode_database(DbType::Mongo(url))
        .env("FERRUM_MONGO_DATABASE", database)
        .log_level("warn")
        .db_poll_interval_seconds(1)
        .spawn()
        .await
        .expect("spawn mongodb gateway");
    // Standalone MongoDB writes a resource and its change record as two
    // operations (documented), so the concurrent consistency cell runs on the
    // replica set below; the sequential detection cells run here.
    run_database_scenario(&gateway, "mongodb-standalone", false).await;
}

#[tokio::test]
#[ignore]
async fn test_admin_list_queries_mongodb_replica_set() {
    let Ok(replica_set) = std::env::var("FERRUM_TEST_MONGO_REPLICA_SET") else {
        println!("SKIP: FERRUM_TEST_MONGO_REPLICA_SET not set — no replica set available");
        return;
    };
    let url = std::env::var("FERRUM_TEST_MONGO_REPLICA_SET_URL")
        .or_else(|_| std::env::var("FERRUM_TEST_MONGO_URL"))
        .unwrap_or_else(|_| DEFAULT_MONGO_URL.to_string());
    let host_port = host_port_from_db_url(&url);
    if !continue_if_backend_available(
        "mongodb-replica-set",
        tcp_endpoint_reachable(&host_port).await,
        &format!("declared but not available at {host_port}"),
    ) {
        return;
    }
    let database = format!("ferrum_list_queries_rs_{}", Uuid::new_v4().simple());
    let _cleanup = MongoDatabaseCleanup {
        url: url.clone(),
        database: database.clone(),
    };
    let gateway = TestGateway::builder()
        .mode_database(DbType::Mongo(url))
        .env("FERRUM_MONGO_DATABASE", database)
        .env("FERRUM_MONGO_REPLICA_SET", replica_set)
        .log_level("warn")
        .db_poll_interval_seconds(1)
        .spawn()
        .await
        .expect("spawn mongodb replica-set gateway");
    run_database_scenario(&gateway, "mongodb-replica-set", true).await;
}

#[tokio::test]
#[ignore]
async fn test_admin_list_queries_file_mode_cached_config() {
    let gateway = TestGateway::builder()
        .mode_file(file_mode_config())
        .log_level("warn")
        .spawn()
        .await
        .expect("spawn file-mode gateway");
    let admin = Admin::new(&gateway);
    assert_search_ids_and_applies_to(&admin, "file").await;
    let body = admin.ok("/proxies").await;
    let current = revision(&body);
    assert!(current.starts_with('c'), "cached revision: {current}");
    // Stable across reads of the same config.
    assert_eq!(revision(&admin.ok("/proxies?limit=1").await), current);
    assert_ne!(
        revision(&admin.ok("/consumers").await),
        current,
        "collections have distinct revisions"
    );
}
