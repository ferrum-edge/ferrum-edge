//! `ETag` / `If-Match` conditional writes on full-replacement admin resources.
//!
//! Two administrators editing the same proxy each hold the representation they
//! opened. A full-replacement `PUT` from the second, unconditioned, reverts the
//! first administrator's accepted change. These tests drive the real admin
//! listener over SQLite and pin the contract that closes that gap:
//!
//! * `GET` issues a strong `ETag`; a `PUT`/`DELETE` whose `If-Match` no longer
//!   matches is refused with `412` and changes nothing;
//! * the comparison and the write are atomic — of two concurrent writes that
//!   hold the same tag, exactly one commits;
//! * a malformed header, a weak tag, or `If-Match` on a route that does not
//!   evaluate it is never treated as "no precondition".

use crate::scaffolding::port_registry::TestSocket;

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::db_backend::{
    BatchConfigWriteMode, DatabaseBackend, NamespaceConfigAdmissionLeaseBackend,
};
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use jsonwebtoken::{EncodingKey, Header, encode};
use reqwest::Method;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;

const JWT_SECRET: &str = "test-secret-key-for-conditional-writes-32";
const JWT_ISSUER: &str = "test-ferrum-edge";

fn jwt_manager_with_secret(secret: &str) -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: secret.to_string(),
        issuer: JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn token_with_role(secret: &str, role: &str) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": JWT_ISSUER,
        "sub": "conditional-writer",
        "role": role,
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("token encodes")
}

fn admin_token() -> String {
    token_with_role(JWT_SECRET, "admin")
}

async fn make_store(dir: &TempDir) -> Arc<DatabaseStore> {
    make_store_with_url(dir).await.0
}

async fn make_store_with_url(dir: &TempDir) -> (Arc<DatabaseStore>, String) {
    let db_path = dir
        .path()
        .join(format!("conditional-{}.db", uuid::Uuid::new_v4()));
    let url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config(
        "sqlite",
        &url,
        DbPoolConfig {
            max_connections: 4,
            min_connections: 0,
            acquire_timeout_seconds: 10,
            idle_timeout_seconds: 60,
            max_lifetime_seconds: 300,
            connect_timeout_seconds: 5,
            statement_timeout_seconds: 0,
        },
    )
    .await
    .expect("connect sqlite store");
    (Arc::new(store), url)
}

fn admin_state(db: Arc<dyn DatabaseBackend>, secret: &str) -> AdminState {
    AdminState {
        db: Some(db),
        jwt_manager: jwt_manager_with_secret(secret),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_audit_fallback_dir: Some(crate::common::isolated_audit_fallback_dir()),
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        gateway_listener_status: None,
        gateway_listener_failure_fails_readiness: false,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::none()),
        cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        admin_request_limits: Default::default(),
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        external_ref_policy: Arc::new(
            ferrum_edge::admin::api_specs::ExternalRefProcessPolicy::default(),
        ),
        external_ref_loader: Arc::new(
            ferrum_edge::admin::api_specs::DefaultExternalDocumentLoader::default(),
        ),
        runtime_config_apply: None,
    }
}

async fn start_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("loopback addr parses");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind_test(addr)
        .await
        .expect("bind");
    let actual = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = serve_admin_on_listener(
            listener,
            state,
            shutdown_rx,
            None,
            ferrum_edge::admin::AdminConnLimiter::unlimited(),
        )
        .await;
    });
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(actual).await.is_ok() {
            return (format!("http://{actual}"), shutdown_tx);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("admin listener at {actual} never became ready");
}

struct Reply {
    status: u16,
    etag: Option<String>,
    body: Value,
}

async fn send(
    method: Method,
    base: &str,
    path: &str,
    token: &str,
    if_match: Option<&str>,
    body: Option<&Value>,
) -> Reply {
    send_ns(method, base, path, token, if_match, body, "ferrum").await
}

async fn send_ns(
    method: Method,
    base: &str,
    path: &str,
    token: &str,
    if_match: Option<&str>,
    body: Option<&Value>,
    namespace: &str,
) -> Reply {
    let mut request = reqwest::Client::new()
        .request(method, format!("{base}{path}"))
        .bearer_auth(token)
        .header("X-Ferrum-Namespace", namespace);
    if let Some(if_match) = if_match {
        request = request.header("If-Match", if_match);
    }
    if let Some(body) = body {
        request = request.json(body);
    }
    let response = request.send().await.expect("request succeeds");
    let status = response.status().as_u16();
    let etag = response
        .headers()
        .get("etag")
        .map(|value| value.to_str().expect("etag is ascii").to_string());
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    Reply { status, etag, body }
}

async fn get_ns(base: &str, path: &str, namespace: &str) -> Reply {
    send_ns(
        Method::GET,
        base,
        path,
        &admin_token(),
        None,
        None,
        namespace,
    )
    .await
}

async fn get(base: &str, path: &str) -> Reply {
    send(Method::GET, base, path, &admin_token(), None, None).await
}

/// Handler-owned admission guards release their database lease from an async
/// cleanup task after the response returns, so wait briefly before competing.
async fn acquire_namespace_config_admission_lease_after_handler(
    db: &dyn DatabaseBackend,
    namespace: &str,
    owner: &str,
) -> u64 {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(generation) = db
                .try_acquire_namespace_config_admission_lease(namespace, owner)
                .await
                .expect("lease acquisition succeeds after handler response")
            {
                return generation;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("handler's admission lease is released within five seconds")
}

async fn create(base: &str, collection: &str, body: Value) {
    let reply = send(
        Method::POST,
        base,
        collection,
        &admin_token(),
        None,
        Some(&body),
    )
    .await;
    assert_eq!(reply.status, 201, "seed {collection}: {}", reply.body);
}

fn proxy(backend_host: &str, read_timeout_ms: u64) -> Value {
    json!({
        "id": "shared-proxy",
        "listen_path": "/shared",
        "backend_scheme": "http",
        "backend_host": backend_host,
        "backend_port": 8080,
        "backend_read_timeout_ms": read_timeout_ms,
    })
}

async fn serve() -> (TempDir, String, tokio::sync::watch::Sender<bool>) {
    let dir = TempDir::new().expect("tempdir");
    let db = make_store(&dir).await;
    let (base, shutdown) = start_admin(admin_state(db, JWT_SECRET)).await;
    (dir, base, shutdown)
}

/// The two-administrator sequence from the Foundry report: both open the
/// editor, the first changes the backend and saves, the second changes only a
/// timeout and submits the draft it opened. The second save must not revert
/// the backend.
#[tokio::test]
async fn stale_full_replacement_put_is_refused_and_newer_change_survives() {
    let (_dir, base, _shutdown) = serve().await;
    create(&base, "/proxies", proxy("backend-a.internal", 30_000)).await;

    let opened_by_first = get(&base, "/proxies/shared-proxy").await;
    let opened_by_second = get(&base, "/proxies/shared-proxy").await;
    let first_tag = opened_by_first.etag.expect("GET issues an ETag");
    let second_tag = opened_by_second.etag.expect("GET issues an ETag");
    assert_eq!(
        first_tag, second_tag,
        "two reads of one representation must carry one tag"
    );
    assert!(
        first_tag.starts_with('"') && first_tag.ends_with('"') && !first_tag.starts_with("W/"),
        "the tag is a quoted strong entity-tag: {first_tag}"
    );

    let first_save = send(
        Method::PUT,
        &base,
        "/proxies/shared-proxy",
        &admin_token(),
        Some(&first_tag),
        Some(&proxy("backend-b.internal", 30_000)),
    )
    .await;
    assert_eq!(first_save.status, 200, "first save: {}", first_save.body);

    let second_save = send(
        Method::PUT,
        &base,
        "/proxies/shared-proxy",
        &admin_token(),
        Some(&second_tag),
        Some(&proxy("backend-a.internal", 45_000)),
    )
    .await;
    assert_eq!(
        second_save.status, 412,
        "a save from a stale draft must be refused: {}",
        second_save.body
    );
    let message = second_save.body["error"].as_str().unwrap_or_default();
    assert!(
        message.contains("shared-proxy") && message.contains("re-read"),
        "the refusal names the resource and the recovery: {message}"
    );

    let current = get(&base, "/proxies/shared-proxy").await;
    assert_eq!(current.body["backend_host"], "backend-b.internal");
    assert_eq!(current.body["backend_read_timeout_ms"], 30_000);
    assert_ne!(
        current.etag.as_deref(),
        Some(second_tag.as_str()),
        "the accepted change must advance the tag"
    );

    // Re-read, reapply, and save against the current tag: accepted.
    let reapplied = send(
        Method::PUT,
        &base,
        "/proxies/shared-proxy",
        &admin_token(),
        current.etag.as_deref(),
        Some(&proxy("backend-b.internal", 45_000)),
    )
    .await;
    assert_eq!(reapplied.status, 200, "reapplied save: {}", reapplied.body);
    let settled = get(&base, "/proxies/shared-proxy").await;
    assert_eq!(settled.body["backend_host"], "backend-b.internal");
    assert_eq!(settled.body["backend_read_timeout_ms"], 45_000);
}

/// The comparison and the write happen under the namespace admission lease, so
/// two writers racing on the same tag cannot both commit.
#[tokio::test]
async fn concurrent_writes_holding_one_tag_commit_exactly_once() {
    let (_dir, base, _shutdown) = serve().await;
    create(&base, "/proxies", proxy("backend-a.internal", 30_000)).await;
    let tag = get(&base, "/proxies/shared-proxy")
        .await
        .etag
        .expect("GET issues an ETag");

    let writers = (0..6).map(|index| {
        let base = base.clone();
        let tag = tag.clone();
        tokio::spawn(async move {
            let body = proxy(&format!("backend-{index}.internal"), 30_000);
            let reply = send(
                Method::PUT,
                &base,
                "/proxies/shared-proxy",
                &admin_token(),
                Some(&tag),
                Some(&body),
            )
            .await;
            (index, reply.status)
        })
    });
    let mut accepted = Vec::new();
    for writer in writers {
        let (index, status) = writer.await.expect("writer task");
        match status {
            200 => accepted.push(index),
            412 => {}
            other => panic!("writer {index} got unexpected status {other}"),
        }
    }
    assert_eq!(
        accepted.len(),
        1,
        "exactly one writer commits: {accepted:?}"
    );
    let current = get(&base, "/proxies/shared-proxy").await;
    assert_eq!(
        current.body["backend_host"],
        format!("backend-{}.internal", accepted[0]),
        "the stored proxy is the one accepted write"
    );
}

#[tokio::test]
async fn unconditional_writes_are_unchanged_and_star_requires_existence() {
    let (_dir, base, _shutdown) = serve().await;
    create(&base, "/proxies", proxy("backend-a.internal", 30_000)).await;

    let unconditional = send(
        Method::PUT,
        &base,
        "/proxies/shared-proxy",
        &admin_token(),
        None,
        Some(&proxy("backend-b.internal", 30_000)),
    )
    .await;
    assert_eq!(unconditional.status, 200, "{}", unconditional.body);

    let star = send(
        Method::PUT,
        &base,
        "/proxies/shared-proxy",
        &admin_token(),
        Some("*"),
        Some(&proxy("backend-c.internal", 30_000)),
    )
    .await;
    assert_eq!(star.status, 200, "{}", star.body);

    // A precondition is ignored when the unconditional request would 404.
    let missing = send(
        Method::PUT,
        &base,
        "/proxies/never-created",
        &admin_token(),
        Some("*"),
        Some(&proxy("backend-c.internal", 30_000)),
    )
    .await;
    assert_eq!(missing.status, 404, "{}", missing.body);
}

#[tokio::test]
async fn weak_malformed_and_list_tags_are_evaluated_strictly() {
    let (_dir, base, _shutdown) = serve().await;
    create(&base, "/proxies", proxy("backend-a.internal", 30_000)).await;
    let tag = get(&base, "/proxies/shared-proxy")
        .await
        .etag
        .expect("GET issues an ETag");
    let path = "/proxies/shared-proxy";
    let body = proxy("backend-b.internal", 30_000);

    // If-Match uses strong comparison: the weak form of the current tag fails.
    let weak = format!("W/{tag}");
    let reply = send(
        Method::PUT,
        &base,
        path,
        &admin_token(),
        Some(&weak),
        Some(&body),
    )
    .await;
    assert_eq!(reply.status, 412, "weak tag: {}", reply.body);

    for malformed in ["", "unquoted", "\"unterminated", "\"a\" \"b\"", "*, \"a\""] {
        let reply = send(
            Method::PUT,
            &base,
            path,
            &admin_token(),
            Some(malformed),
            Some(&body),
        )
        .await;
        assert_eq!(
            reply.status, 400,
            "malformed If-Match {malformed:?} must not be treated as absent: {}",
            reply.body
        );
    }

    // A list matches when any member matches.
    let list = format!("\"stale\", {tag}");
    let reply = send(
        Method::PUT,
        &base,
        path,
        &admin_token(),
        Some(&list),
        Some(&body),
    )
    .await;
    assert_eq!(reply.status, 200, "list containing the tag: {}", reply.body);

    let current = get(&base, path).await;
    assert_eq!(current.body["backend_host"], "backend-b.internal");
}

#[tokio::test]
async fn a_malformed_header_never_preempts_the_role_gate() {
    let (_dir, base, _shutdown) = serve().await;
    create(&base, "/proxies", proxy("backend-a.internal", 30_000)).await;
    let viewer = token_with_role(JWT_SECRET, "viewer");
    let reply = send(
        Method::PUT,
        &base,
        "/proxies/shared-proxy",
        &viewer,
        Some("unquoted"),
        Some(&proxy("backend-b.internal", 30_000)),
    )
    .await;
    assert_eq!(reply.status, 403, "{}", reply.body);
}

#[tokio::test]
async fn stale_delete_is_refused_and_current_delete_succeeds() {
    let (_dir, base, _shutdown) = serve().await;
    create(&base, "/proxies", proxy("backend-a.internal", 30_000)).await;
    let stale = get(&base, "/proxies/shared-proxy")
        .await
        .etag
        .expect("GET issues an ETag");
    let update = send(
        Method::PUT,
        &base,
        "/proxies/shared-proxy",
        &admin_token(),
        None,
        Some(&proxy("backend-b.internal", 30_000)),
    )
    .await;
    assert_eq!(update.status, 200, "{}", update.body);

    let refused = send(
        Method::DELETE,
        &base,
        "/proxies/shared-proxy",
        &admin_token(),
        Some(&stale),
        None,
    )
    .await;
    assert_eq!(refused.status, 412, "stale delete: {}", refused.body);
    assert_eq!(get(&base, "/proxies/shared-proxy").await.status, 200);

    let current = get(&base, "/proxies/shared-proxy")
        .await
        .etag
        .expect("GET issues an ETag");
    let deleted = send(
        Method::DELETE,
        &base,
        "/proxies/shared-proxy",
        &admin_token(),
        Some(&current),
        None,
    )
    .await;
    assert_eq!(deleted.status, 204, "current delete: {}", deleted.body);
    assert_eq!(get(&base, "/proxies/shared-proxy").await.status, 404);
}

/// Upstreams, consumers, and plugin configs share the contract.
#[tokio::test]
async fn every_full_replacement_family_refuses_a_stale_tag() {
    let (_dir, base, _shutdown) = serve().await;
    let cases = [
        (
            "/upstreams",
            "/upstreams/shared-upstream",
            json!({"id": "shared-upstream", "name": "shared", "targets": [{"host": "10.0.0.1", "port": 8080, "weight": 100}]}),
            json!({"id": "shared-upstream", "name": "shared", "targets": [{"host": "10.0.0.2", "port": 8080, "weight": 100}]}),
            json!({"id": "shared-upstream", "name": "renamed", "targets": [{"host": "10.0.0.1", "port": 8080, "weight": 100}]}),
        ),
        (
            "/consumers",
            "/consumers/shared-consumer",
            json!({"id": "shared-consumer", "username": "alice"}),
            json!({"id": "shared-consumer", "username": "alice", "custom_id": "first"}),
            json!({"id": "shared-consumer", "username": "alice", "custom_id": "second"}),
        ),
        (
            "/plugins/config",
            "/plugins/config/shared-plugin",
            json!({"id": "shared-plugin", "plugin_name": "cors", "scope": "global", "enabled": false, "config": {"allowed_origins": ["https://a.example"]}}),
            json!({"id": "shared-plugin", "plugin_name": "cors", "scope": "global", "enabled": true, "config": {"allowed_origins": ["https://a.example"]}}),
            json!({"id": "shared-plugin", "plugin_name": "cors", "scope": "global", "enabled": false, "config": {"allowed_origins": ["https://b.example"]}}),
        ),
    ];
    for (collection, path, seed, first, second) in cases {
        create(&base, collection, seed).await;
        let tag = get(&base, path).await.etag.expect("GET issues an ETag");
        let accepted = send(
            Method::PUT,
            &base,
            path,
            &admin_token(),
            Some(&tag),
            Some(&first),
        )
        .await;
        assert_eq!(accepted.status, 200, "{path} first: {}", accepted.body);
        let refused = send(
            Method::PUT,
            &base,
            path,
            &admin_token(),
            Some(&tag),
            Some(&second),
        )
        .await;
        assert_eq!(refused.status, 412, "{path} stale: {}", refused.body);
    }
    let upstream = get(&base, "/upstreams/shared-upstream").await;
    assert_eq!(upstream.body["targets"][0]["host"], "10.0.0.2");
    let consumer = get(&base, "/consumers/shared-consumer").await;
    assert_eq!(consumer.body["custom_id"], "first");
    let plugin = get(&base, "/plugins/config/shared-plugin").await;
    assert_eq!(plugin.body["enabled"], true);
}

/// A tag is bound to the resource it was issued for: identical bodies under
/// different ids never share one.
#[tokio::test]
async fn a_tag_never_satisfies_a_precondition_on_another_resource() {
    let (_dir, base, _shutdown) = serve().await;
    for id in ["consumer-one", "consumer-two"] {
        create(&base, "/consumers", json!({"id": id, "username": id})).await;
    }
    let one = get(&base, "/consumers/consumer-one")
        .await
        .etag
        .expect("tag");
    let reply = send(
        Method::PUT,
        &base,
        "/consumers/consumer-two",
        &admin_token(),
        Some(&one),
        Some(&json!({"id": "consumer-two", "username": "consumer-two"})),
    )
    .await;
    assert_eq!(reply.status, 412, "{}", reply.body);
}

/// Replicas that accept the same admin tokens agree on tags; a different
/// secret yields a different tag, so a tag is not a plain digest of the body.
#[tokio::test]
async fn tags_are_keyed_by_the_admin_secret_and_shared_by_replicas() {
    let dir = TempDir::new().expect("tempdir");
    let db = make_store(&dir).await;
    let (replica_a, _a) = start_admin(admin_state(db.clone(), JWT_SECRET)).await;
    let (replica_b, _b) = start_admin(admin_state(db.clone(), JWT_SECRET)).await;
    let other_secret = "a-different-admin-secret-of-32-chars!";
    let (other, _c) = start_admin(admin_state(db, other_secret)).await;

    create(&replica_a, "/proxies", proxy("backend-a.internal", 30_000)).await;
    let from_a = get(&replica_a, "/proxies/shared-proxy").await.etag;
    let from_b = get(&replica_b, "/proxies/shared-proxy").await.etag;
    let from_other = send(
        Method::GET,
        &other,
        "/proxies/shared-proxy",
        &token_with_role(other_secret, "admin"),
        None,
        None,
    )
    .await
    .etag;
    assert!(from_a.is_some());
    assert_eq!(from_a, from_b, "replicas sharing the secret share tags");
    assert_ne!(from_a, from_other, "the tag is keyed by the admin secret");

    // A tag read from one replica conditions a write on the other.
    let reply = send(
        Method::PUT,
        &replica_b,
        "/proxies/shared-proxy",
        &admin_token(),
        from_a.as_deref(),
        Some(&proxy("backend-b.internal", 30_000)),
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
}

/// Routes that do not evaluate `If-Match` refuse it instead of writing
/// unconditionally — including trust bundles, which keep their own body
/// `revision` contract, and creates.
#[tokio::test]
async fn if_match_on_a_route_that_does_not_evaluate_it_is_refused() {
    let (_dir, base, _shutdown) = serve().await;
    let create_with_tag = send(
        Method::POST,
        &base,
        "/proxies",
        &admin_token(),
        Some("*"),
        Some(&proxy("backend-a.internal", 30_000)),
    )
    .await;
    assert_eq!(create_with_tag.status, 400, "{}", create_with_tag.body);
    assert_eq!(get(&base, "/proxies/shared-proxy").await.status, 404);

    let trust_bundle = send(
        Method::PUT,
        &base,
        "/gateway-trust-bundles/any",
        &admin_token(),
        Some("*"),
        Some(&json!({})),
    )
    .await;
    assert_eq!(trust_bundle.status, 400, "{}", trust_bundle.body);

    let batch = send(
        Method::POST,
        &base,
        "/batch",
        &admin_token(),
        Some("*"),
        Some(&json!({})),
    )
    .await;
    assert_eq!(batch.status, 400, "{}", batch.body);
}

#[tokio::test]
async fn consumer_verification_is_complete_admin_only_and_uses_the_existing_tag() {
    let (_dir, base, _shutdown) = serve().await;
    create(
        &base,
        "/consumers",
        json!({
            "id": "verified", "username": "verified",
            "credentials": {"jwt": [{"secret": "first-credential-secret-at-least-32-characters"},
                {"secret": "second-credential-secret-at-least-32-characters"}]}
        }),
    )
    .await;
    let redacted = get(&base, "/consumers/verified").await;
    let complete = get(&base, "/consumers/verified/verification").await;
    assert_eq!(complete.status, 200, "{}", complete.body);
    assert_eq!(complete.etag, redacted.etag);
    assert_eq!(
        complete.body["credentials"]["jwt"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        complete.body["credentials"]["jwt"][1]["secret"],
        "second-credential-secret-at-least-32-characters"
    );
    assert_ne!(redacted.body["credentials"], complete.body["credentials"]);
    for role in ["viewer", "operator"] {
        let denied = send(
            Method::GET,
            &base,
            "/consumers/verified/verification",
            &token_with_role(JWT_SECRET, role),
            None,
            None,
        )
        .await;
        assert_eq!(denied.status, 403, "{role}: {}", denied.body);
        assert!(!denied.body.to_string().contains("credential-secret"));
        assert!(denied.etag.is_none());
    }
    let denied = send(
        Method::GET,
        &base,
        "/consumers/verified/verification",
        "",
        None,
        None,
    )
    .await;
    assert_eq!(denied.status, 401);
    let backup = get(&base, "/backup?conditional=true").await;
    assert_eq!(backup.status, 200, "{}", backup.body);
    assert_eq!(
        backup.body["version"],
        ferrum_edge::config::types::CURRENT_CONFIG_VERSION
    );
    assert_eq!(backup.body["consumers"][0], complete.body);
    assert_eq!(
        backup.body["conditional"]["row_etags"]["consumers"]["verified"],
        complete.etag.unwrap()
    );
    let changed = send(
        Method::PUT,
        &base,
        "/consumers/verified",
        &admin_token(),
        redacted.etag.as_deref(),
        Some(&json!({"username": "verified", "credentials": {"jwt": [
            {"secret": "replacement-credential-secret-at-least-32-characters"}
        ]}})),
    )
    .await;
    assert_eq!(changed.status, 200, "{}", changed.body);
    let stale = send(
        Method::PUT,
        &base,
        "/consumers/verified",
        &admin_token(),
        redacted.etag.as_deref(),
        Some(&complete.body),
    )
    .await;
    assert_eq!(stale.status, 412, "{}", stale.body);
}

#[tokio::test]
async fn conditional_reads_preserve_historical_credential_fields_and_shapes() {
    let dir = TempDir::new().unwrap();
    let db = make_store(&dir).await;
    let consumer: ferrum_edge::config::types::Consumer = serde_json::from_value(json!({
        "id": "historical", "username": "historical",
        "credentials": {
            "jwt": [{"secret": "historical-jwt-secret-with-at-least-32-characters",
                "algorithm": "HS256"}],
            "hmac_auth": {"secret": "historical-hmac-secret-with-at-least-32-characters"},
            "custom_auth": {"opaque_stored_field": "historical-custom-value"}
        }
    }))
    .unwrap();
    // Model an older stored row that current HTTP admission would reject. The
    // conditional verification and snapshot paths read the authoritative raw
    // row, so they retain these stored credentials exactly. Archival `/backup`
    // follows the released full-config load path: `quarantine_invalid_hmac_credentials`
    // strips this legacy non-array `hmac_auth` before the canonical wrapper is
    // serialized. Keep that fail-closed quarantine contract intact.
    db.create_consumer(&consumer).await.unwrap();
    let (base, _shutdown) = start_admin(admin_state(db, JWT_SECRET)).await;
    let complete = get(&base, "/consumers/historical/verification").await;
    assert_eq!(complete.status, 200, "{}", complete.body);
    assert_eq!(complete.body, serde_json::to_value(&consumer).unwrap());
    assert_eq!(
        complete.body["credentials"],
        json!({
            "jwt": [{
                "secret": "historical-jwt-secret-with-at-least-32-characters",
                "algorithm": "HS256"
            }],
            "hmac_auth": {
                "secret": "historical-hmac-secret-with-at-least-32-characters"
            },
            "custom_auth": {"opaque_stored_field": "historical-custom-value"}
        })
    );
    let backup = get(&base, "/backup?conditional=true").await;
    assert_eq!(backup.status, 200, "{}", backup.body);
    assert_eq!(backup.body["consumers"][0], complete.body);
    assert_eq!(
        backup.body["consumers"][0]["credentials"],
        complete.body["credentials"]
    );
    assert_eq!(
        backup.body["conditional"]["row_etags"]["consumers"]["historical"],
        complete.etag.unwrap()
    );
    let archival = get(&base, "/backup").await;
    assert_eq!(archival.status, 200, "{}", archival.body);
    assert!(
        !archival.body["consumers"][0]["credentials"]
            .as_object()
            .unwrap()
            .contains_key("hmac_auth"),
        "archival export omits the non-array hmac_auth credential quarantined during config load"
    );
    assert_eq!(
        archival.body["consumers"][0]["credentials"],
        json!({
            "jwt": [{"secret": "historical-jwt-secret-with-at-least-32-characters"}],
            "custom_auth": [{"opaque_stored_field": "historical-custom-value"}]
        })
    );
}

#[tokio::test]
async fn conditional_backup_tags_match_every_complete_row_and_noop_keeps_revision() {
    let (_dir, base, _shutdown) = serve().await;
    create(&base, "/proxies", proxy("backend.internal", 30_000)).await;
    create(
        &base,
        "/upstreams",
        json!({"id": "tagged-upstream", "targets": [
            {"host": "upstream.internal", "port": 8080}
        ]}),
    )
    .await;
    create(
        &base,
        "/plugins/config",
        json!({"id": "tagged-plugin", "plugin_name": "cors",
            "scope": "global", "config": {"allowed_origins": ["https://example.com"]}
        }),
    )
    .await;
    let backup = get(&base, "/backup?conditional=true").await;
    assert_eq!(backup.status, 200, "{}", backup.body);
    assert_eq!(
        backup.body["conditional"]["namespace_etag"],
        backup.etag.as_deref().unwrap()
    );
    for (section, prefix) in [
        ("proxies", "/proxies"),
        ("upstreams", "/upstreams"),
        ("plugin_configs", "/plugins/config"),
    ] {
        for row in backup.body[section].as_array().unwrap() {
            let id = row["id"].as_str().unwrap();
            let read = get(&base, &format!("{prefix}/{id}")).await;
            assert_eq!(read.status, 200);
            assert_eq!(row, &read.body);
            assert_eq!(
                backup.body["conditional"]["row_etags"][section][id],
                read.etag.unwrap()
            );
        }
    }
    assert!(
        get(&base, "/backup")
            .await
            .body
            .get("conditional")
            .is_none()
    );
    assert_eq!(
        get(&base, "/backup?conditional=true").await.etag,
        backup.etag
    );
    let missing = send(
        Method::DELETE,
        &base,
        "/consumers/missing",
        &admin_token(),
        None,
        None,
    )
    .await;
    assert_eq!(missing.status, 404);
    assert_eq!(
        get(&base, "/backup?conditional=true").await.etag,
        backup.etag
    );
    for path in [
        "/backup?conditional=true&resources=proxies",
        "/backup?conditional=maybe",
        "/backup?conditional=true&conditional=false",
    ] {
        assert_eq!(get(&base, path).await.status, 400, "{path}");
    }
}

#[tokio::test]
async fn concurrent_conditional_restores_have_one_winner_and_preserve_the_winner() {
    let (_dir, base, _shutdown) = serve().await;
    create(&base, "/proxies", proxy("original.internal", 30_000)).await;
    let opened = get(&base, "/backup?conditional=true").await;
    let tag = opened.etag.unwrap();
    let mut first = opened.body.clone();
    let mut second = opened.body;
    first["proxies"][0]["backend_host"] = json!("first.internal");
    second["proxies"][0]["backend_host"] = json!("second.internal");
    let bearer = admin_token();
    let (a, b) = tokio::join!(
        send(
            Method::POST,
            &base,
            "/restore?confirm=true",
            &bearer,
            Some(&tag),
            Some(&first),
        ),
        send(
            Method::POST,
            &base,
            "/restore?confirm=true",
            &bearer,
            Some(&tag),
            Some(&second),
        ),
    );
    let mut statuses = [a.status, b.status];
    statuses.sort();
    assert_eq!(
        statuses,
        [200, 412],
        "first: {}; second: {}",
        a.body,
        b.body
    );
    let expected = if a.status == 200 {
        "first.internal"
    } else {
        "second.internal"
    };
    assert_eq!(
        get(&base, "/proxies/shared-proxy").await.body["backend_host"],
        expected
    );
}

#[tokio::test]
async fn namespace_revision_fences_other_resource_changes_and_delete_recreate() {
    let (_dir, base, _shutdown) = serve().await;
    create(&base, "/proxies", proxy("original.internal", 30_000)).await;
    let opened = get(&base, "/backup?conditional=true").await;
    create(
        &base,
        "/consumers",
        json!({"id": "intervening", "username": "intervening"}),
    )
    .await;
    let stale = send(
        Method::POST,
        &base,
        "/restore?confirm=true",
        &admin_token(),
        opened.etag.as_deref(),
        Some(&opened.body),
    )
    .await;
    assert_eq!(stale.status, 412, "{}", stale.body);
    let deleted = send(
        Method::DELETE,
        &base,
        "/consumers/intervening",
        &admin_token(),
        None,
        None,
    )
    .await;
    assert_eq!(deleted.status, 204, "{}", deleted.body);
    // Content returned to its previous state, but the durable change watermark
    // prevents the old namespace token from becoming authoritative again.
    let stale = send(
        Method::POST,
        &base,
        "/restore?confirm=true",
        &admin_token(),
        opened.etag.as_deref(),
        Some(&opened.body),
    )
    .await;
    assert_eq!(stale.status, 412);
    assert_eq!(
        get(&base, "/proxies/shared-proxy").await.body["backend_host"],
        "original.internal"
    );
}

#[tokio::test]
async fn conditional_restore_rolls_back_all_phases_and_checks_empty_replacements() {
    use ferrum_edge::_test_support::{
        AtomicBatchFault, AtomicBatchPhase, set_atomic_batch_fault_for_test,
    };

    let namespace = format!("restore-{}", uuid::Uuid::new_v4());
    let dir = TempDir::new().unwrap();
    let db = make_store(&dir).await;
    let (base, _shutdown) = start_admin(admin_state(db.clone(), JWT_SECRET)).await;
    let created = send_ns(
        Method::POST,
        &base,
        "/proxies",
        &admin_token(),
        None,
        Some(&proxy("original.internal", 30_000)),
        &namespace,
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.body);
    let opened = get_ns(&base, "/backup?conditional=true", &namespace).await;
    let snapshot = db
        .load_conditional_namespace_snapshot(&namespace)
        .await
        .unwrap()
        .representation()
        .unwrap();
    set_atomic_batch_fault_for_test(
        &namespace,
        Some(AtomicBatchFault::new(AtomicBatchPhase::Commit, 0)),
    );
    let mut replacement = opened.body.clone();
    replacement["proxies"][0]["backend_host"] = json!("replacement.internal");
    let failed = send_ns(
        Method::POST,
        &base,
        "/restore?confirm=true",
        &admin_token(),
        opened.etag.as_deref(),
        Some(&replacement),
        &namespace,
    )
    .await;
    set_atomic_batch_fault_for_test(&namespace, None);
    assert_eq!(failed.status, 503, "{}", failed.body);
    assert_eq!(
        db.load_conditional_namespace_snapshot(&namespace)
            .await
            .unwrap()
            .representation()
            .unwrap(),
        snapshot
    );
    assert_eq!(
        get_ns(&base, "/backup?conditional=true", &namespace)
            .await
            .etag,
        opened.etag
    );
    let empty = json!({});
    for (tag, status) in [
        ("*".to_string(), 400),
        (format!("W/{}", opened.etag.as_ref().unwrap()), 412),
        ("unquoted".to_string(), 400),
    ] {
        let refused = send_ns(
            Method::POST,
            &base,
            "/restore?confirm=true",
            &admin_token(),
            Some(&tag),
            Some(&empty),
            &namespace,
        )
        .await;
        assert_eq!(refused.status, status, "{}", refused.body);
    }
    let cleared = send_ns(
        Method::POST,
        &base,
        "/restore?confirm=true",
        &admin_token(),
        opened.etag.as_deref(),
        Some(&empty),
        &namespace,
    )
    .await;
    assert_eq!(cleared.status, 200, "{}", cleared.body);
    assert_eq!(
        get_ns(&base, "/proxies/shared-proxy", &namespace)
            .await
            .status,
        404
    );
    let current = get_ns(&base, "/backup?conditional=true", &namespace).await;
    let noop = send_ns(
        Method::POST,
        &base,
        "/restore?confirm=true",
        &admin_token(),
        current.etag.as_deref(),
        Some(&empty),
        &namespace,
    )
    .await;
    assert_eq!(noop.status, 200, "{}", noop.body);
    assert_eq!(
        get_ns(&base, "/backup?conditional=true", &namespace)
            .await
            .etag,
        current.etag
    );
}

#[tokio::test]
async fn standalone_mongo_refuses_conditional_snapshots_and_restore_without_io() {
    use ferrum_edge::config::db_backend::{
        AtomicBatchGraph, BatchConfigWriteMode, ConditionalNamespaceRestore,
        NamespaceConfigAdmissionLeaseRef, SnapshotDigest, atomic_batch_unsupported,
    };

    let store = ferrum_edge::_test_support::mongo_store_new_unconnected_for_test(vec![]).unwrap();
    let error = match store.load_conditional_namespace_snapshot("ferrum").await {
        Ok(_) => panic!("standalone snapshot must be refused"),
        Err(error) => error,
    };
    assert!(atomic_batch_unsupported(&error).is_some());
    let expected = SnapshotDigest::of_representation(&json!({})).unwrap();
    let restore = ConditionalNamespaceRestore {
        graph: AtomicBatchGraph {
            namespace: "ferrum",
            consumers: &[],
            upstreams: &[],
            proxies: &[],
            plugin_configs: &[],
            admission_lease: Some(NamespaceConfigAdmissionLeaseRef {
                owner: "test-owner",
                generation: 1,
            }),
        },
        expected,
        api_specs: &[],
        gateway_trust_bundles: None,
    };
    let error = store
        .restore_namespace_conditionally(&restore, &BatchConfigWriteMode::Admission)
        .await
        .unwrap_err();
    assert!(atomic_batch_unsupported(&error).is_some());
    let (base, _shutdown) = start_admin(admin_state(Arc::new(store), JWT_SECRET)).await;
    assert_eq!(get(&base, "/backup?conditional=true").await.status, 501);
    let refused = send(
        Method::POST,
        &base,
        "/restore?confirm=true",
        &admin_token(),
        Some("\"namespace-tag\""),
        Some(&json!({})),
    )
    .await;
    assert_eq!(refused.status, 501, "{}", refused.body);
}

#[tokio::test]
async fn conditional_snapshot_covers_spec_document_only_changes_and_restores_ownership() {
    let (_dir, base, _shutdown) = serve().await;
    let mut document = json!({
        "openapi": "3.0.3", "info": {"title": "Conditional spec", "version": "1"},
        "paths": {"/items": {"get": {"responses": {"200": {"description": "OK"}}}}},
        "x-ferrum-proxy": {"id": "spec-proxy", "listen_path": "/spec",
            "backend_host": "backend.example.com", "backend_port": 8080},
        "x-ferrum-upstream": {"id": "spec-upstream", "targets": [
            {"host": "backend.example.com", "port": 8080}
        ]}
    });
    let imported = send(
        Method::POST,
        &base,
        "/api-specs",
        &admin_token(),
        None,
        Some(&document),
    )
    .await;
    assert_eq!(imported.status, 201, "{}", imported.body);
    let opened = get(&base, "/backup?conditional=true").await;
    let spec_id = opened.body["api_specs"]["items"][0]["id"].as_str().unwrap();
    document["info"]["description"] = json!("Document metadata changed; resources unchanged");
    let updated = send(
        Method::PUT,
        &base,
        &format!("/api-specs/{spec_id}"),
        &admin_token(),
        None,
        Some(&document),
    )
    .await;
    assert_eq!(updated.status, 200, "{}", updated.body);
    let current = get(&base, "/backup?conditional=true").await;
    assert_eq!(
        opened.body["conditional"]["row_etags"],
        current.body["conditional"]["row_etags"]
    );
    assert_ne!(opened.etag, current.etag, "spec-only metadata is covered");
    let stale = send(
        Method::POST,
        &base,
        "/restore?confirm=true",
        &admin_token(),
        opened.etag.as_deref(),
        Some(&opened.body),
    )
    .await;
    assert_eq!(stale.status, 412, "{}", stale.body);
    let restored = send(
        Method::POST,
        &base,
        "/restore?confirm=true",
        &admin_token(),
        current.etag.as_deref(),
        Some(&current.body),
    )
    .await;
    assert_eq!(restored.status, 200, "{}", restored.body);
    let after = get(&base, "/backup?conditional=true").await;
    assert_eq!(after.body["api_specs"], current.body["api_specs"]);
    assert_eq!(after.body["proxies"][0]["api_spec_id"], spec_id);
    assert_eq!(after.body["upstreams"][0]["api_spec_id"], spec_id);
}

/// Exercise the store boundary directly: the snapshot can change after a
/// handler has verified its token, and the transaction must still refuse it.
async fn assert_transaction_precondition(db: &dyn DatabaseBackend) {
    use ferrum_edge::config::db_backend::{
        AtomicBatchGraph, BatchConfigWriteMode, ConditionalNamespaceRestore,
        NamespaceConfigAdmissionLeaseRef, NamespacePreconditionFailed,
        is_batch_admission_lease_lost,
    };
    use ferrum_edge::config::types::Consumer;

    let namespace = format!("transaction-{}", uuid::Uuid::new_v4());
    assert_eq!(
        db.load_conditional_namespace_snapshot(&namespace)
            .await
            .unwrap()
            .config
            .version,
        ferrum_edge::config::types::CURRENT_CONFIG_VERSION
    );
    let expected = db
        .load_conditional_namespace_snapshot(&namespace)
        .await
        .unwrap()
        .digest()
        .unwrap();
    let consumer: Consumer = serde_json::from_value(json!({
        "namespace": namespace, "id": "concurrent", "username": "concurrent"
    }))
    .unwrap();
    db.create_consumer(&consumer).await.unwrap();
    let owner = uuid::Uuid::new_v4().to_string();
    let generation = db
        .try_acquire_namespace_config_admission_lease(&namespace, &owner)
        .await
        .unwrap()
        .unwrap();
    let mut restore = ConditionalNamespaceRestore {
        graph: AtomicBatchGraph {
            namespace: &namespace,
            consumers: &[],
            upstreams: &[],
            proxies: &[],
            plugin_configs: &[],
            admission_lease: Some(NamespaceConfigAdmissionLeaseRef {
                owner: &owner,
                generation,
            }),
        },
        expected,
        api_specs: &[],
        gateway_trust_bundles: None,
    };
    let error = db
        .restore_namespace_conditionally(&restore, &BatchConfigWriteMode::Admission)
        .await
        .unwrap_err();
    assert!(
        error
            .chain()
            .any(|cause| cause.is::<NamespacePreconditionFailed>())
    );
    assert!(
        db.get_consumer(&namespace, "concurrent")
            .await
            .unwrap()
            .is_some()
    );
    let current = db
        .load_conditional_namespace_snapshot(&namespace)
        .await
        .unwrap()
        .digest()
        .unwrap();
    // A matching state with a released admission lease cannot commit either.
    assert!(
        db.release_namespace_config_admission_lease(&namespace, &owner)
            .await
            .unwrap()
    );
    restore.expected = current;
    let error = db
        .restore_namespace_conditionally(&restore, &BatchConfigWriteMode::Admission)
        .await
        .unwrap_err();
    assert!(is_batch_admission_lease_lost(&error), "{error}");
    assert_eq!(
        db.load_conditional_namespace_snapshot(&namespace)
            .await
            .unwrap()
            .digest()
            .unwrap(),
        current
    );
    let generation = db
        .try_acquire_namespace_config_admission_lease(&namespace, &owner)
        .await
        .unwrap()
        .unwrap();
    restore.graph.admission_lease = Some(NamespaceConfigAdmissionLeaseRef {
        owner: &owner,
        generation,
    });
    db.restore_namespace_conditionally(&restore, &BatchConfigWriteMode::Admission)
        .await
        .unwrap();
    assert!(
        db.get_consumer(&namespace, "concurrent")
            .await
            .unwrap()
            .is_none()
    );
    let empty = db
        .load_conditional_namespace_snapshot(&namespace)
        .await
        .unwrap()
        .digest()
        .unwrap();
    assert_ne!(empty, current);
    let error = db
        .restore_namespace_conditionally(&restore, &BatchConfigWriteMode::Admission)
        .await
        .unwrap_err();
    assert!(
        error
            .chain()
            .any(|cause| cause.is::<NamespacePreconditionFailed>())
    );
    // An empty-to-empty replacement still checks the state and lease, but it
    // must not fabricate a resource change or advance the namespace watermark.
    restore.expected = empty;
    db.restore_namespace_conditionally(&restore, &BatchConfigWriteMode::Admission)
        .await
        .unwrap();
    assert_eq!(
        db.load_conditional_namespace_snapshot(&namespace)
            .await
            .unwrap()
            .digest()
            .unwrap(),
        empty
    );
    assert!(
        db.release_namespace_config_admission_lease(&namespace, &owner)
            .await
            .unwrap()
    );
}

/// Batch admission validates the graph the batch commits, including each
/// proxy-scoped config's implied association with its `proxy_id` (issue
/// #6070). A proxy-scoped policy whose target proxy does not list it is still
/// attached by persistence, so admission must see it as active: here a
/// `san_dns` policy that makes two stored mTLS identities collide, and a TCP
/// throttle on an HTTP proxy. Both batch entry points must reject the write
/// with nothing durable and no cursor advance.
async fn assert_batch_admission_sees_implied_proxy_associations(db: &dyn DatabaseBackend) {
    use ferrum_edge::config::db_backend::{AtomicBatchGraph, BatchConfigWriteMode};
    use ferrum_edge::config::types::{Consumer, PluginConfig, Proxy};

    let namespace = format!("batch-implied-{}", uuid::Uuid::new_v4());
    let proxy: Proxy = serde_json::from_value(json!({
        "namespace": namespace,
        "id": "p",
        "listen_path": "/p",
        "backend_scheme": "http",
        "backend_host": "backend.internal",
        "backend_port": 8080,
    }))
    .unwrap();
    let consumer = |id: &str, identity: &str| -> Consumer {
        serde_json::from_value(json!({
            "namespace": namespace,
            "id": id,
            "username": id,
            "credentials": { "mtls_auth": [{ "identity": identity }] },
        }))
        .unwrap()
    };
    let seed_consumers = [
        consumer("upper", "Svc.Example"),
        consumer("lower", "svc.example"),
    ];
    let seed = AtomicBatchGraph {
        namespace: &namespace,
        consumers: &seed_consumers,
        upstreams: &[],
        proxies: std::slice::from_ref(&proxy),
        plugin_configs: &[],
        admission_lease: None,
    };
    db.batch_create_config_graph_atomically(&seed, &BatchConfigWriteMode::Admission)
        .await
        .expect("case-variant identities are allowed while no san_dns policy is effective");

    let proxy_scoped = |id: &str, plugin_name: &str, config: serde_json::Value| -> PluginConfig {
        serde_json::from_value(json!({
            "namespace": namespace,
            "id": id,
            "plugin_name": plugin_name,
            "config": config,
            "scope": "proxy",
            "proxy_id": "p",
        }))
        .unwrap()
    };
    let rejected = [
        proxy_scoped("dns", "mtls_auth", json!({ "cert_field": "san_dns" })),
        proxy_scoped(
            "throttle",
            "tcp_connection_throttle",
            json!({ "max_connections_per_key": 10 }),
        ),
    ];
    for config in &rejected {
        let before = db.latest_change_sequence(&namespace).await.unwrap();
        let graph = AtomicBatchGraph {
            namespace: &namespace,
            consumers: &[],
            upstreams: &[],
            proxies: &[],
            plugin_configs: std::slice::from_ref(config),
            admission_lease: None,
        };
        assert!(
            db.batch_create_config_graph_atomically(&graph, &BatchConfigWriteMode::Admission)
                .await
                .is_err(),
            "atomic batch must reject {:?} once attached to p",
            config.id
        );
        assert!(
            db.batch_create_plugin_configs(
                std::slice::from_ref(config),
                &BatchConfigWriteMode::Admission
            )
            .await
            .is_err(),
            "per-family batch must reject {:?} once attached to p",
            config.id
        );
        assert!(
            db.get_plugin_config(&namespace, &config.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.get_proxy(&namespace, "p")
                .await
                .unwrap()
                .expect("proxy exists")
                .plugins
                .is_empty()
        );
        assert_eq!(db.latest_change_sequence(&namespace).await.unwrap(), before);
    }
}

/// `POST /batch` and conditional restore persist a proxy-scoped plugin
/// config's implied association with its `proxy_id` inside the same
/// transaction on every backend (issue #4611). The runtime only applies a
/// config the proxy lists, so a batched proxy-scoped auth plugin that SQL
/// attaches but MongoDB does not would be silently unenforced on MongoDB.
async fn assert_batch_proxy_scoped_plugin_association_parity(db: &dyn DatabaseBackend) {
    use ferrum_edge::_test_support::{
        AtomicBatchFault, AtomicBatchPhase, set_atomic_batch_fault_for_test,
    };
    use ferrum_edge::config::db_backend::{
        AtomicBatchGraph, BatchConfigWriteMode, ConditionalNamespaceRestore,
        NamespaceConfigAdmissionLeaseRef,
    };
    use ferrum_edge::config::types::{PluginConfig, Proxy};

    let namespace = format!("batch-assoc-{}", uuid::Uuid::new_v4());
    let proxy = |id: &str, plugins: &[&str]| -> Proxy {
        serde_json::from_value(json!({
            "namespace": namespace,
            "id": id,
            "listen_path": format!("/{id}"),
            "backend_scheme": "http",
            "backend_host": "backend.internal",
            "backend_port": 8080,
            "plugins": plugins
                .iter()
                .map(|plugin| json!({ "plugin_config_id": plugin }))
                .collect::<Vec<_>>(),
        }))
        .unwrap()
    };
    let plugin = |id: &str, scope: &str, proxy_id: Option<&str>| -> PluginConfig {
        serde_json::from_value(json!({
            "namespace": namespace,
            "id": id,
            "plugin_name": "key_auth",
            "config": {},
            "scope": scope,
            "proxy_id": proxy_id,
        }))
        .unwrap()
    };
    let associations = |proxy: Option<Proxy>| -> Vec<String> {
        let mut ids: Vec<String> = proxy
            .expect("proxy exists")
            .plugins
            .into_iter()
            .map(|association| association.plugin_config_id)
            .collect();
        ids.sort();
        ids
    };
    let batch = |proxies: Vec<Proxy>, plugin_configs: Vec<PluginConfig>| {
        let namespace = namespace.as_str();
        async move {
            let graph = AtomicBatchGraph {
                namespace,
                consumers: &[],
                upstreams: &[],
                proxies: &proxies,
                plugin_configs: &plugin_configs,
                admission_lease: None,
            };
            db.batch_create_config_graph_atomically(&graph, &BatchConfigWriteMode::Admission)
                .await
        }
    };

    // The 2026-10-07 reproduction: a proxy listing only its group config plus
    // a proxy-scoped config targeting it in the same graph. A proxy that
    // already lists its own proxy-scoped config gains no duplicate.
    batch(
        vec![proxy("p6", &["group-b"]), proxy("p7", &["local-p7"])],
        vec![
            plugin("group-b", "proxy_group", None),
            plugin("local-p6", "proxy", Some("p6")),
            plugin("local-p7", "proxy", Some("p7")),
        ],
    )
    .await
    .unwrap();
    assert_eq!(
        associations(db.get_proxy(&namespace, "p6").await.unwrap()),
        ["group-b", "local-p6"]
    );
    assert_eq!(
        associations(db.get_proxy(&namespace, "p7").await.unwrap()),
        ["local-p7"]
    );

    // Attaching to an existing proxy outside the graph also records that
    // proxy's config change, so incremental polling republishes it.
    let before = db.latest_change_sequence(&namespace).await.unwrap();
    batch(Vec::new(), vec![plugin("late-p6", "proxy", Some("p6"))])
        .await
        .unwrap();
    assert_eq!(
        associations(db.get_proxy(&namespace, "p6").await.unwrap()),
        ["group-b", "late-p6", "local-p6"]
    );
    let delta = db
        .load_incremental_config(&namespace, before)
        .await
        .unwrap();
    let republished = delta
        .added_or_modified_proxies
        .iter()
        .find(|proxy| proxy.id == "p6")
        .expect("the attached proxy is republished by incremental polling");
    assert!(
        republished
            .plugins
            .iter()
            .any(|association| association.plugin_config_id == "late-p6")
    );

    // The per-family path used by non-conditional restore and import
    // (`persist_payload_resources`) attaches the same way.
    db.batch_create_plugin_configs(
        &[plugin("family-p7", "proxy", Some("p7"))],
        &BatchConfigWriteMode::Admission,
    )
    .await
    .unwrap();
    assert_eq!(
        associations(db.get_proxy(&namespace, "p7").await.unwrap()),
        ["family-p7", "local-p7"]
    );

    // An abort at the final gate rolls the attachment back with the config.
    set_atomic_batch_fault_for_test(
        &namespace,
        Some(AtomicBatchFault::new(AtomicBatchPhase::Commit, 0)),
    );
    let faulted = batch(Vec::new(), vec![plugin("faulted-p6", "proxy", Some("p6"))]).await;
    set_atomic_batch_fault_for_test(&namespace, None);
    assert!(faulted.is_err());
    assert_eq!(
        associations(db.get_proxy(&namespace, "p6").await.unwrap()),
        ["group-b", "late-p6", "local-p6"]
    );
    assert!(
        db.get_plugin_config(&namespace, "faulted-p6")
            .await
            .unwrap()
            .is_none()
    );

    // A proxy-scoped config naming a missing proxy fails the whole graph on
    // every backend (SQL through the `proxy_plugins` foreign key).
    assert!(
        batch(Vec::new(), vec![plugin("orphan", "proxy", Some("missing"))])
            .await
            .is_err()
    );
    assert!(
        db.get_plugin_config(&namespace, "orphan")
            .await
            .unwrap()
            .is_none()
    );

    // Conditional restore replays the same graph writer: a restored
    // proxy-scoped config is attached even when the restored proxy omits it.
    let expected = db
        .load_conditional_namespace_snapshot(&namespace)
        .await
        .unwrap()
        .digest()
        .unwrap();
    let owner = uuid::Uuid::new_v4().to_string();
    let generation = db
        .try_acquire_namespace_config_admission_lease(&namespace, &owner)
        .await
        .unwrap()
        .unwrap();
    let proxies = [proxy("p6", &[])];
    let plugin_configs = [plugin("local-p6", "proxy", Some("p6"))];
    let restore = ConditionalNamespaceRestore {
        graph: AtomicBatchGraph {
            namespace: &namespace,
            consumers: &[],
            upstreams: &[],
            proxies: &proxies,
            plugin_configs: &plugin_configs,
            admission_lease: Some(NamespaceConfigAdmissionLeaseRef {
                owner: &owner,
                generation,
            }),
        },
        expected,
        api_specs: &[],
        gateway_trust_bundles: None,
    };
    db.restore_namespace_conditionally(&restore, &BatchConfigWriteMode::Admission)
        .await
        .unwrap();
    assert_eq!(
        associations(db.get_proxy(&namespace, "p6").await.unwrap()),
        ["local-p6"]
    );
    assert!(db.get_proxy(&namespace, "p7").await.unwrap().is_none());
    assert!(
        db.release_namespace_config_admission_lease(&namespace, &owner)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn sqlite_conditional_restore_checks_state_and_lease_inside_the_transaction() {
    let dir = TempDir::new().unwrap();
    let (db, url) = make_store_with_url(&dir).await;
    assert_transaction_precondition(db.as_ref()).await;
    assert_batch_proxy_scoped_plugin_association_parity(db.as_ref()).await;
    assert_batch_admission_sees_implied_proxy_associations(db.as_ref()).await;
    assert_sql_deployment_raw_preservation(db.clone(), "sqlite", &url).await;
    assert_deployment_mutation_contract(db.clone()).await;
    assert_deployment_cancellation_and_live_ack(db.clone()).await;
    assert_deployment_concurrent_writer_fences(db.clone()).await;
    let pool = db.pool();
    assert_restore_renewal_and_fencing(db.clone(), move |namespace, ttl| {
        let pool = pool.clone();
        async move {
            let result = sqlx::query(
                "UPDATE config_admission_locks SET expires_at = \
                 CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER) + ? \
                 WHERE namespace = ?",
            )
            .bind(ttl)
            .bind(namespace)
            .execute(&pool)
            .await
            .unwrap();
            assert_eq!(result.rows_affected(), 1);
        }
    })
    .await;
    db.pool().close().await;
}

/// Healthy keepers must extend live leases, including after a wait beyond the
/// original server expiry. A refused renewal, even with unchanged ownership,
/// invalidates the guard; only a fresh writer may take over and revalidate.
async fn assert_live_keeper_renewal_and_loss<F, Fut>(db: Arc<dyn DatabaseBackend>, set_expiry: &F)
where
    F: Fn(String, i64) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    use ferrum_edge::_test_support::{
        TestNamespaceConfigAdmissionCompletion, lock_namespace_config_admission_db_for_test,
        lock_namespace_config_admission_for_test,
    };
    use std::time::Duration;

    let namespace = format!("live-keeper-{}", uuid::Uuid::new_v4());
    assert!(
        !db.renew_namespace_config_admission_lease(&namespace, "absent-owner")
            .await
            .unwrap(),
        "renewal must never insert an absent lease"
    );
    let guard = lock_namespace_config_admission_db_for_test(db.clone(), &namespace)
        .await
        .unwrap();
    let owner = guard.lease_ref().owner.to_string();
    let generation = guard.lease_ref().generation;
    set_expiry(namespace.clone(), 5_000).await;
    tokio::task::yield_now().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(30)).await;
    tokio::time::resume();
    // Real datastore time passes: the original five-second deadline is now
    // gone. No direct test renewal may mask a broken production keeper.
    tokio::time::sleep(Duration::from_secs(6)).await;
    let competitor = uuid::Uuid::new_v4().to_string();
    assert!(
        db.try_acquire_namespace_config_admission_lease(&namespace, &competitor)
            .await
            .unwrap()
            .is_none(),
        "a healthy long-wait guard must keep exclusive ownership"
    );
    assert!(matches!(
        guard
            .run_to_completion_while_held(std::future::ready(()))
            .await,
        Ok(TestNamespaceConfigAdmissionCompletion::Held(()))
    ));

    // Refusal is definitive loss even before any other owner has appeared.
    set_expiry(namespace.clone(), -1).await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(30)).await;
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if guard
                .run_to_completion_while_held(std::future::ready(()))
                .await
                .is_err()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the production keeper must invalidate a refused renewal");
    assert!(
        !db.renew_namespace_config_admission_lease(&namespace, &owner)
            .await
            .unwrap(),
        "an expired same-owner row is not renewable"
    );
    let next_generation = db
        .try_acquire_namespace_config_admission_lease(&namespace, &competitor)
        .await
        .unwrap()
        .expect("a new writer takes the expired row");
    assert_eq!(next_generation, generation + 1);
    assert!(
        !db.renew_namespace_config_admission_lease(&namespace, &owner)
            .await
            .unwrap()
    );
    drop(guard);
    let local = tokio::time::timeout(
        Duration::from_secs(15),
        lock_namespace_config_admission_for_test(&namespace),
    )
    .await
    .expect("old-owner cleanup releases the local shard");
    assert!(
        db.try_acquire_namespace_config_admission_lease(&namespace, &owner)
            .await
            .unwrap()
            .is_none(),
        "old-owner cleanup must not release the successor's live lease"
    );
    db.release_namespace_config_admission_lease(&namespace, &competitor)
        .await
        .unwrap();
    drop(local);
}

/// Exercise the real keeper handoff, a transaction spanning its 30-second
/// renewal interval and the original datastore expiry, and competing owners.
async fn assert_restore_renewal_and_fencing<F, Fut>(db: Arc<dyn DatabaseBackend>, set_expiry: F)
where
    F: Fn(String, i64) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    use ferrum_edge::config::batch_atomicity::{
        ConditionalRestoreTestPause, set_conditional_restore_pause,
    };
    use ferrum_edge::config::db_backend::{
        AtomicBatchGraph, BatchConfigWriteMode, ConditionalNamespaceRestore,
        NamespaceConfigAdmissionLeaseRef, is_batch_admission_lease_lost,
    };
    use ferrum_edge::config::types::Consumer;
    use std::time::Duration;

    assert_live_keeper_renewal_and_loss(db.clone(), &set_expiry).await;

    let namespace = format!("renewed-{}", uuid::Uuid::new_v4());
    let consumer: Consumer = serde_json::from_value(json!({
        "namespace": namespace, "id": "original", "username": "original"
    }))
    .unwrap();
    db.create_consumer(&consumer).await.unwrap();
    let expected = db
        .load_conditional_namespace_snapshot(&namespace)
        .await
        .unwrap()
        .digest()
        .unwrap();
    let mut guard = ferrum_edge::_test_support::lock_namespace_config_admission_db_for_test(
        db.clone(),
        &namespace,
    )
    .await
    .unwrap();
    guard.hand_off_to_restore_transaction().await.unwrap();
    // This deliberately shortened datastore TTL must expire during the import.
    // It is valid at entry; the transaction pin, rather than a stale expiry or
    // an external keeper update, must then prevent takeover until commit.
    set_expiry(namespace.clone(), 5_000).await;
    let pause = Arc::new(ConditionalRestoreTestPause::default());
    set_conditional_restore_pause(&namespace, Some(pause.clone()));
    let restore = ConditionalNamespaceRestore {
        graph: AtomicBatchGraph {
            namespace: &namespace,
            consumers: &[],
            upstreams: &[],
            proxies: &[],
            plugin_configs: &[],
            admission_lease: Some(guard.lease_ref()),
        },
        expected,
        api_specs: &[],
        gateway_trust_bundles: None,
    };
    let competitor = uuid::Uuid::new_v4().to_string();
    let observer = async {
        tokio::time::timeout(Duration::from_secs(15), pause.entered.notified())
            .await
            .expect("restore reached its pinned transaction snapshot");
        tokio::time::sleep(Duration::from_secs(35)).await;
        // SQL blocks on the row pin; Mongo rejects a conflicting write. Neither
        // backend may grant a new generation despite the elapsed original TTL.
        let attempt = tokio::time::timeout(
            Duration::from_millis(250),
            db.try_acquire_namespace_config_admission_lease(&namespace, &competitor),
        )
        .await;
        if let Ok(Ok(generation)) = attempt {
            assert!(generation.is_none(), "takeover succeeded during restore");
        }
        pause.resume.notify_one();
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::join!(
            db.restore_namespace_conditionally(&restore, &BatchConfigWriteMode::Admission),
            observer,
        )
    })
    .await
    .expect("renewed restore settled");
    set_conditional_restore_pause(&namespace, None);
    result.expect("restore spanning renewal and expiry commits under its transaction pin");
    assert!(
        db.get_consumer(&namespace, "original")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.try_acquire_namespace_config_admission_lease(&namespace, &competitor)
            .await
            .unwrap()
            .is_none(),
        "commit renewed the pinned lease before releasing its transaction fence"
    );

    // An already expired lease must never acquire a transaction pin, including
    // when nobody has taken over yet. The unchanged namespace must survive.
    db.create_consumer(&consumer).await.unwrap();
    let current = db
        .load_conditional_namespace_snapshot(&namespace)
        .await
        .unwrap()
        .digest()
        .unwrap();
    let mut restore = restore;
    restore.expected = current;
    set_expiry(namespace.clone(), -1).await;
    let error = db
        .restore_namespace_conditionally(&restore, &BatchConfigWriteMode::Admission)
        .await
        .unwrap_err();
    assert!(is_batch_admission_lease_lost(&error), "{error}");
    assert_eq!(
        db.load_conditional_namespace_snapshot(&namespace)
            .await
            .unwrap()
            .digest()
            .unwrap(),
        current
    );
    let generation = db
        .try_acquire_namespace_config_admission_lease(&namespace, &competitor)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(generation, guard.lease_ref().generation);
    let error = db
        .restore_namespace_conditionally(&restore, &BatchConfigWriteMode::Admission)
        .await
        .unwrap_err();
    assert!(is_batch_admission_lease_lost(&error), "{error}");
    assert_eq!(
        db.load_conditional_namespace_snapshot(&namespace)
            .await
            .unwrap()
            .digest()
            .unwrap(),
        current
    );
    // Restore succeeds only with the new live owner's exact generation.
    restore.graph.admission_lease = Some(NamespaceConfigAdmissionLeaseRef {
        owner: &competitor,
        generation,
    });
    db.restore_namespace_conditionally(&restore, &BatchConfigWriteMode::Admission)
        .await
        .unwrap();
    db.release_namespace_config_admission_lease(&namespace, &competitor)
        .await
        .unwrap();
    drop(guard);
    let local = tokio::time::timeout(
        Duration::from_secs(15),
        ferrum_edge::_test_support::lock_namespace_config_admission_for_test(&namespace),
    )
    .await
    .expect("restore cleanup completes before fixture pool closure");
    drop(local);
}

/// A row lock held without a server timeout blocks both renewal and release.
/// Cleanup must free the process-local shard within its 30-second budget even
/// while that server-side barrier remains held indefinitely.
async fn assert_postgres_stalled_cleanup_is_bounded(db: Arc<DatabaseStore>) {
    use ferrum_edge::_test_support::{
        lock_namespace_config_admission_db_for_test, lock_namespace_config_admission_for_test,
    };
    use std::time::Duration;

    let namespace = format!("stalled-{}", uuid::Uuid::new_v4());
    let guard = lock_namespace_config_admission_db_for_test(db.clone(), &namespace)
        .await
        .unwrap();
    let owner = guard.lease_ref().owner.to_string();
    let generation = guard.lease_ref().generation;
    let pool = db.pool();
    let mut barrier = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL statement_timeout = 0")
        .execute(&mut *barrier)
        .await
        .unwrap();
    sqlx::query("SELECT 1 FROM config_admission_locks WHERE namespace = $1 FOR UPDATE")
        .bind(&namespace)
        .execute(&mut *barrier)
        .await
        .unwrap();

    tokio::task::yield_now().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(30)).await;
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pg_stat_activity \
                 WHERE wait_event_type = 'Lock' \
                 AND query LIKE 'UPDATE config_admission_locks SET expires_at = %'",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            if waiting > 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the production renewal reached the permanently held row lock");
    drop(guard);
    // Poll the detached cleanup once so its whole-cleanup deadline is armed.
    tokio::task::yield_now().await;
    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            lock_namespace_config_admission_for_test(&namespace),
        )
        .await
        .is_err(),
        "the test must reach cleanup while it still owns the local shard"
    );
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(31)).await;
    tokio::time::resume();
    let local = tokio::time::timeout(
        Duration::from_secs(2),
        lock_namespace_config_admission_for_test(&namespace),
    )
    .await
    .expect("stalled database I/O cannot retain the local shard past cleanup's budget");

    // The server barrier is still held when the local lock is proved free.
    // Expire the old row before allowing any queued commands to execute; none
    // may revive it, regardless of SQL driver's cancellation semantics.
    sqlx::query("UPDATE config_admission_locks SET expires_at = 0 WHERE namespace = $1")
        .bind(&namespace)
        .execute(&mut *barrier)
        .await
        .unwrap();
    barrier.commit().await.unwrap();
    drop(local);
    let next = tokio::time::timeout(
        Duration::from_secs(15),
        lock_namespace_config_admission_db_for_test(db.clone(), &namespace),
    )
    .await
    .expect("another writer can proceed after the stalled operation is unblocked")
    .unwrap();
    assert_eq!(next.lease_ref().generation, generation + 1);
    assert_ne!(next.lease_ref().owner, owner);
    assert!(
        !db.renew_namespace_config_admission_lease(&namespace, &owner)
            .await
            .unwrap(),
        "the cancelled owner remains fenced after takeover"
    );
    let remaining: i64 = sqlx::query_scalar(
        "SELECT expires_at - CAST(EXTRACT(EPOCH FROM clock_timestamp()) * 1000 AS BIGINT) \
         FROM config_admission_locks WHERE namespace = $1",
    )
    .bind(&namespace)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        remaining > 115_000,
        "the production TTL must remain 120 seconds"
    );
    drop(next);
}

async fn assert_sql_restore_renewal(db: Arc<DatabaseStore>) {
    let pool = db.pool();
    let sql = match db.db_type_str() {
        "postgres" => {
            "UPDATE config_admission_locks SET expires_at = \
             CAST(EXTRACT(EPOCH FROM clock_timestamp()) * 1000 AS BIGINT) + $2 \
             WHERE namespace = $1"
        }
        "mysql" => {
            "UPDATE config_admission_locks SET expires_at = \
             CAST(UNIX_TIMESTAMP(CURRENT_TIMESTAMP(3)) * 1000 AS SIGNED) + ? \
             WHERE namespace = ?"
        }
        _ => panic!("live SQL restore regression requires PostgreSQL or MySQL"),
    };
    let mysql = db.db_type_str() == "mysql";
    assert_restore_renewal_and_fencing(db, move |namespace, ttl| {
        let pool = pool.clone();
        async move {
            let query = sqlx::query(sql);
            let query = if mysql {
                query.bind(ttl).bind(namespace)
            } else {
                query.bind(namespace).bind(ttl)
            };
            assert_eq!(query.execute(&pool).await.unwrap().rows_affected(), 1);
        }
    })
    .await;
}

/// The HTTP path must hand off its automatically running production keeper,
/// rather than merely relying on direct store callers to suppress renewal.
async fn assert_http_restore_spans_keeper_renewal(db: Arc<dyn DatabaseBackend>) {
    use ferrum_edge::config::batch_atomicity::{
        ConditionalRestoreTestPause, set_conditional_restore_pause,
    };
    use ferrum_edge::config::types::Consumer;
    use std::time::Duration;

    let namespace = format!("http-renewed-{}", uuid::Uuid::new_v4());
    let consumer: Consumer = serde_json::from_value(json!({
        "namespace": namespace, "id": "original", "username": "original"
    }))
    .unwrap();
    db.create_consumer(&consumer).await.unwrap();
    let (base, _shutdown) = start_admin(admin_state(db.clone(), JWT_SECRET)).await;
    let opened = get_ns(&base, "/backup?conditional=true", &namespace).await;
    assert_eq!(opened.status, 200, "{}", opened.body);
    let pause = Arc::new(ConditionalRestoreTestPause::default());
    set_conditional_restore_pause(&namespace, Some(pause.clone()));
    let bearer = admin_token();
    let writer = send_ns(
        Method::POST,
        &base,
        "/restore?confirm=true",
        &bearer,
        opened.etag.as_deref(),
        Some(&opened.body),
        &namespace,
    );
    let observer = async {
        tokio::time::timeout(Duration::from_secs(15), pause.entered.notified())
            .await
            .expect("HTTP restore entered its fenced transaction");
        tokio::time::sleep(Duration::from_secs(35)).await;
        pause.resume.notify_one();
    };
    let (restored, ()) = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::join!(writer, observer)
    })
    .await
    .expect("HTTP restore spanning keeper renewal settled");
    set_conditional_restore_pause(&namespace, None);
    assert_eq!(restored.status, 200, "{}", restored.body);
    let verified = get_ns(&base, "/consumers/original/verification", &namespace).await;
    assert_eq!(verified.status, 200, "{}", verified.body);
    let mut expected = opened.body["consumers"][0].clone();
    assert_ne!(verified.body["updated_at"], expected["updated_at"]);
    expected["updated_at"] = verified.body["updated_at"].clone();
    assert_eq!(verified.body, expected);
}

/// A wire fault around the production Mongo driver and a real replica-set
/// primary. The hosted fixture does not enable server failpoints, so hold an
/// actual submitted OP_MSG on its already-connected upstream socket, sever
/// the driver's socket, and execute that exact command after cleanup/takeover.
/// Direct connection prevents discovery from bypassing the proxy; retries and
/// compression are disabled so the fault has one unambiguous wire command.
struct MongoLeaseWireFault {
    namespace: String,
    mode: std::sync::atomic::AtomicU8,
    acquisitions: std::sync::atomic::AtomicU32,
    renewal_entered: tokio::sync::Notify,
    release_entered: tokio::sync::Notify,
    disconnected: tokio::sync::Notify,
    resume: tokio::sync::Notify,
    replayed: tokio::sync::Notify,
    response: tokio::sync::Mutex<Option<mongodb::bson::Document>>,
}

impl MongoLeaseWireFault {
    fn new(namespace: String) -> Self {
        Self {
            namespace,
            mode: std::sync::atomic::AtomicU8::new(0),
            acquisitions: std::sync::atomic::AtomicU32::new(0),
            renewal_entered: tokio::sync::Notify::new(),
            release_entered: tokio::sync::Notify::new(),
            disconnected: tokio::sync::Notify::new(),
            resume: tokio::sync::Notify::new(),
            replayed: tokio::sync::Notify::new(),
            response: tokio::sync::Mutex::new(None),
        }
    }
}

struct MongoLeaseWireProxy {
    url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for MongoLeaseWireProxy {
    fn drop(&mut self) {
        // The accept task owns a JoinSet: aborting it also drops/aborts every
        // fixture connection, including deliberately permanent stalls.
        self.task.abort();
    }
}

async fn read_mongo_wire_frame<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;

    let mut length = [0_u8; 4];
    reader.read_exact(&mut length).await?;
    let length = i32::from_le_bytes(length);
    assert!(
        (16..=8_388_608).contains(&length),
        "invalid fixture frame size"
    );
    let mut frame = vec![0_u8; length as usize];
    frame[..4].copy_from_slice(&length.to_le_bytes());
    reader.read_exact(&mut frame[4..]).await?;
    Ok(frame)
}

fn mongo_wire_command(frame: &[u8]) -> Option<mongodb::bson::Document> {
    let opcode = i32::from_le_bytes(frame[12..16].try_into().unwrap());
    if opcode != 2013 {
        // The driver's initial OP_QUERY hello is forwarded unchanged.
        return None;
    }
    assert_eq!(frame[20], 0, "fixture expects an OP_MSG body section");
    let length = i32::from_le_bytes(frame[21..25].try_into().unwrap()) as usize;
    // The production driver puts update's `updates` array in the body (kind
    // zero), and this fixture does not negotiate wire compression.
    Some(mongodb::bson::from_slice(&frame[21..21 + length]).unwrap())
}

async fn serve_mongo_lease_wire_connection(
    client: tokio::net::TcpStream,
    upstream: &str,
    fault: Arc<MongoLeaseWireFault>,
) -> std::io::Result<()> {
    use mongodb::bson::Bson;
    use std::sync::atomic::Ordering;
    use tokio::io::AsyncWriteExt;

    let server = tokio::net::TcpStream::connect(upstream).await?;
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();
    let mut requests = Box::pin(async {
        loop {
            let frame = read_mongo_wire_frame(&mut client_read).await?;
            if let Some(command) = mongo_wire_command(&frame) {
                if command.get_str("findAndModify").ok() == Some("config_admission_locks") {
                    let query = command.get_document("query").unwrap();
                    if query.get_str("_id").ok() == Some(fault.namespace.as_str()) {
                        fault.acquisitions.fetch_add(1, Ordering::SeqCst);
                    }
                }
                if command.get_str("update").ok() == Some("config_admission_locks") {
                    let update = command.get_array("updates").unwrap()[0]
                        .as_document()
                        .unwrap();
                    let query = update.get_document("q").unwrap();
                    if query.get_str("_id").ok() == Some(fault.namespace.as_str()) {
                        let releasing = update
                            .get_document("u")
                            .ok()
                            .and_then(|u| u.get_document("$set").ok())
                            .and_then(|set| set.get_datetime("expires_at").ok())
                            .is_some_and(|expiry| expiry.timestamp_millis() == 0);
                        let mode = fault.mode.load(Ordering::SeqCst);
                        if mode == 1 {
                            if releasing {
                                fault.release_entered.notify_one();
                            } else {
                                fault.renewal_entered.notify_one();
                            }
                            std::future::pending::<()>().await;
                        }
                        if !releasing
                            && fault
                                .mode
                                .compare_exchange(2, 0, Ordering::SeqCst, Ordering::SeqCst)
                                .is_ok()
                        {
                            assert!(matches!(update.get("u"), Some(Bson::Array(_))));
                            fault.renewal_entered.notify_one();
                            return Ok::<_, std::io::Error>(frame);
                        }
                    }
                }
            }
            server_write.write_all(&frame).await?;
        }
    });
    let delayed = tokio::select! {
        result = &mut requests => result?,
        result = tokio::io::copy(&mut server_read, &mut client_write) => {
            result?;
            return Ok(());
        }
    };
    drop(requests);
    // A real disconnect, not a fabricated backend return value. Keep both
    // upstream halves alive so the submitted command can still reach Mongo.
    drop(client_read);
    drop(client_write);
    fault.disconnected.notify_one();
    fault.resume.notified().await;
    server_write.write_all(&delayed).await?;
    let response = read_mongo_wire_frame(&mut server_read).await?;
    *fault.response.lock().await = mongo_wire_command(&response);
    fault.replayed.notify_one();
    Ok(())
}

async fn start_mongo_lease_wire_proxy(
    url: &str,
    fault: Arc<MongoLeaseWireFault>,
) -> MongoLeaseWireProxy {
    let options = mongodb::options::ClientOptions::parse(url).await.unwrap();
    assert!(
        options.tls.is_none(),
        "wire fault requires the plaintext hosted fixture"
    );
    let upstream = options.hosts.first().unwrap().to_string();
    let replica_set = options.repl_set_name.as_deref().unwrap();
    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let url = format!(
        "mongodb://{address}/?replicaSet={replica_set}&directConnection=true&retryWrites=false"
    );
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (client, _) = accepted.unwrap();
                    let upstream = upstream.clone();
                    let fault = fault.clone();
                    connections.spawn(async move {
                        serve_mongo_lease_wire_connection(client, &upstream, fault).await
                    });
                }
                joined = connections.join_next(), if !connections.is_empty() => {
                    // Driver pool/monitor shutdown may close a socket mid-frame.
                    // A task panic is still a fixture failure; target command
                    // errors are caught by the positive replay barrier below.
                    let _ = joined.unwrap().unwrap();
                }
            }
        }
    });
    MongoLeaseWireProxy { url, task }
}

async fn assert_mongo_cancelled_renewals_cannot_revive(url: &str) {
    use ferrum_edge::_test_support::{
        lock_namespace_config_admission_db_for_test, lock_namespace_config_admission_for_test,
    };
    use mongodb::bson::{Bson, Document, doc};
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    for (permanently_stalled, after_takeover) in [(true, false), (false, false), (false, true)] {
        let namespace = format!("wire-cancelled-{}", uuid::Uuid::new_v4());
        let fault = Arc::new(MongoLeaseWireFault::new(namespace.clone()));
        let proxy = start_mongo_lease_wire_proxy(url, fault.clone()).await;
        let database = format!("wire_{}", uuid::Uuid::new_v4().simple());
        let db = ferrum_edge::config::mongo_store::MongoStore::connect(
            &proxy.url,
            &database,
            None,
            None,
            None,
            Some(5),
            Some(5),
            false,
            None,
            None,
            None,
            false,
        )
        .await
        .unwrap();
        let db = Arc::new(db);
        let raw = mongodb::Client::with_uri_str(url)
            .await
            .unwrap()
            .database(&database);
        let locks = raw.collection::<Document>("config_admission_locks");
        let mut guard = lock_namespace_config_admission_db_for_test(db.clone(), &namespace)
            .await
            .unwrap();
        let owner = guard.lease_ref().owner.to_string();
        let generation = guard.lease_ref().generation;
        assert_eq!(fault.acquisitions.load(Ordering::SeqCst), 1);
        if permanently_stalled {
            fault.mode.store(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(30)).await;
            tokio::time::resume();
            tokio::time::timeout(Duration::from_secs(15), fault.renewal_entered.notified())
                .await
                .expect("production keeper submitted the permanently stalled renewal");
            drop(guard);
            tokio::time::timeout(Duration::from_secs(15), fault.release_entered.notified())
                .await
                .expect("cleanup submitted the permanently stalled release");
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(31)).await;
            tokio::time::resume();
            let local = tokio::time::timeout(
                Duration::from_secs(2),
                lock_namespace_config_admission_for_test(&namespace),
            )
            .await
            .expect("Mongo stalls cannot hold the local shard beyond cleanup's bound");
            assert_eq!(fault.acquisitions.load(Ordering::SeqCst), 1);
            drop(local);
            // Neither deliberately stalled command is resumed. Fixture Drop
            // cancels its connections; production cleanup is already finished.
            continue;
        }

        // Stop the ordinary keeper, then submit its exact production store
        // renewal to observe an actual driver transport error before cleanup.
        // The server-side command must remain possible after that result.
        guard.hand_off_to_restore_transaction().await.unwrap();
        fault.mode.store(2, Ordering::SeqCst);
        let renew_db = db.clone();
        let renew_namespace = namespace.clone();
        let renew_owner = owner.clone();
        let renewal = tokio::spawn(async move {
            renew_db
                .renew_namespace_config_admission_lease(&renew_namespace, &renew_owner)
                .await
        });
        tokio::time::timeout(Duration::from_secs(15), fault.disconnected.notified())
            .await
            .expect("wire proxy severed the actual Mongo driver connection");
        let result = tokio::time::timeout(Duration::from_secs(5), renewal)
            .await
            .expect("disconnected driver future returned before cleanup")
            .unwrap();
        assert!(
            result.is_err(),
            "a real driver transport error must be observed"
        );
        drop(guard);
        let local = tokio::time::timeout(
            Duration::from_secs(15),
            lock_namespace_config_admission_for_test(&namespace),
        )
        .await
        .expect("cleanup finished before the delayed command is resumed");
        let released = locks
            .find_one(doc! { "_id": &namespace })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(released.get_str("owner").unwrap(), owner);
        assert_eq!(
            released
                .get_datetime("expires_at")
                .unwrap()
                .timestamp_millis(),
            0
        );
        drop(local);
        if after_takeover {
            let next = lock_namespace_config_admission_db_for_test(db.clone(), &namespace)
                .await
                .unwrap();
            assert_eq!(next.lease_ref().generation, generation + 1);
            drop(next);
        }
        let local = tokio::time::timeout(
            Duration::from_secs(15),
            lock_namespace_config_admission_for_test(&namespace),
        )
        .await
        .expect("all cleanup completes before the replay");
        let before = locks
            .find_one(doc! { "_id": &namespace })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            before
                .get_datetime("expires_at")
                .unwrap()
                .timestamp_millis(),
            0
        );
        let expected_generation = if after_takeover {
            generation + 1
        } else {
            generation
        };
        let expected_acquisitions = if after_takeover { 2 } else { 1 };
        assert_eq!(
            fault.acquisitions.load(Ordering::SeqCst),
            expected_acquisitions
        );
        fault.resume.notify_one();
        tokio::time::timeout(Duration::from_secs(15), fault.replayed.notified())
            .await
            .expect("the exact delayed wire command executed on the real replica-set primary");
        let response = fault.response.lock().await.take().unwrap();
        assert_eq!(response.get("n"), Some(&Bson::Int32(0)), "{response:?}");
        assert_eq!(
            locks
                .find_one(doc! { "_id": &namespace })
                .await
                .unwrap()
                .unwrap(),
            before,
            "a disconnected owner's command cannot revive a released lease"
        );
        drop(local);
        let final_guard = lock_namespace_config_admission_db_for_test(db.clone(), &namespace)
            .await
            .unwrap();
        assert_eq!(final_guard.lease_ref().generation, expected_generation + 1);
        assert!(
            db.try_acquire_namespace_config_admission_lease(&namespace, &owner)
                .await
                .unwrap()
                .is_none(),
            "takeover remains exclusive after the delayed command"
        );
        drop(final_guard);
        let local = tokio::time::timeout(
            Duration::from_secs(15),
            lock_namespace_config_admission_for_test(&namespace),
        )
        .await
        .expect("final writer cleanup finishes before the proxy is stopped");
        drop(local);
    }
}

async fn assert_mongo_legacy_consumer_tags(db: Arc<dyn DatabaseBackend>, raw: &mongodb::Database) {
    use ferrum_edge::config::types::Consumer;
    use mongodb::bson::{Document, doc};

    let (base, _shutdown) = start_admin(admin_state(db.clone(), JWT_SECRET)).await;
    let consumers = raw.collection::<Document>("consumers");
    for custom_id in ["", " \t "] {
        let namespace = format!("legacy-{}", uuid::Uuid::new_v4());
        let consumer: Consumer = serde_json::from_value(json!({
            "namespace": namespace,
            "id": "legacy",
            "username": "legacy",
            "custom_id": custom_id,
            "credentials": {"mtls_auth": [{"identity": " legacy.example.com \t"}]},
        }))
        .unwrap();
        // Insert an actual historical BSON row, bypassing current admission
        // normalization and identity-index preparation deliberately.
        let mut row = mongodb::bson::to_document(&consumer).unwrap();
        row.insert("_id", format!("{namespace}:legacy"));
        consumers.insert_one(row).await.unwrap();
        let backup = get_ns(&base, "/backup?conditional=true", &namespace).await;
        assert_eq!(backup.status, 200, "{}", backup.body);
        assert_eq!(
            backup.body["version"],
            ferrum_edge::config::types::CURRENT_CONFIG_VERSION
        );
        let verified = get_ns(&base, "/consumers/legacy/verification", &namespace).await;
        assert_eq!(verified.status, 200, "{}", verified.body);
        assert_eq!(verified.body, serde_json::to_value(&consumer).unwrap());
        assert_eq!(backup.body["consumers"][0], verified.body);
        let tag = backup.body["conditional"]["row_etags"]["consumers"]["legacy"]
            .as_str()
            .unwrap();
        assert_eq!(verified.etag.as_deref(), Some(tag));
        let ordinary = get_ns(&base, "/consumers/legacy", &namespace).await;
        assert_eq!(ordinary.etag.as_deref(), Some(tag));
        let accepted = send_ns(
            Method::PUT,
            &base,
            "/consumers/legacy",
            &admin_token(),
            Some(tag),
            Some(&backup.body["consumers"][0]),
            &namespace,
        )
        .await;
        assert_eq!(accepted.status, 200, "unchanged row: {}", accepted.body);
        let current = get_ns(&base, "/backup?conditional=true", &namespace).await;
        let tag = current.body["conditional"]["row_etags"]["consumers"]["legacy"]
            .as_str()
            .unwrap();
        // An out-of-band credential change must invalidate the row tag even
        // without a config-change event or timestamp update.
        consumers
            .update_one(
                doc! { "_id": format!("{namespace}:legacy") },
                doc! { "$set": {
                    "credentials.mtls_auth.0.identity": "changed.example.com",
                } },
            )
            .await
            .unwrap();
        let stale = send_ns(
            Method::PUT,
            &base,
            "/consumers/legacy",
            &admin_token(),
            Some(tag),
            Some(&current.body["consumers"][0]),
            &namespace,
        )
        .await;
        assert_eq!(stale.status, 412, "changed credential: {}", stale.body);
        assert_eq!(
            get_ns(&base, "/consumers/legacy/verification", &namespace)
                .await
                .body["credentials"]["mtls_auth"][0]["identity"],
            "changed.example.com"
        );
    }
}

#[tokio::test]
#[ignore = "Requires a MongoDB replica set supplied by MONGO_URL"]
async fn mongo_replica_set_conditional_restore_checks_state_and_lease_in_transaction() {
    let url = std::env::var("MONGO_URL").expect("MONGO_URL with replicaSet is required");
    assert_mongo_cancelled_renewals_cannot_revive(&url).await;
    let database = format!("conditional_{}", uuid::Uuid::new_v4().simple());
    let db = ferrum_edge::config::mongo_store::MongoStore::connect(
        &url,
        &database,
        None,
        None,
        None,
        Some(5),
        Some(5),
        false,
        None,
        None,
        None,
        false,
    )
    .await
    .unwrap();
    db.run_migrations().await.unwrap();
    assert_transaction_precondition(&db).await;
    assert_batch_proxy_scoped_plugin_association_parity(&db).await;
    assert_batch_admission_sees_implied_proxy_associations(&db).await;
    let db = Arc::new(db);
    crate::integration::admin_plugin_graph_scope_tests::assert_policy_neighborhood_matches_restricted_graph(
        db.as_ref(),
    )
    .await;
    assert_deployment_mutation_contract(db.clone()).await;
    assert_deployment_cancellation_and_live_ack(db.clone()).await;
    assert_deployment_concurrent_writer_fences(db.clone()).await;
    let raw = mongodb::Client::with_uri_str(&url)
        .await
        .unwrap()
        .database(&database);
    let consumers_raw = raw.collection::<mongodb::bson::Document>("consumers");
    crate::integration::consumer_delta_quarantine_tests::assert_consumer_delta_quarantine_contract(
        db.as_ref(),
        |namespace, id, secret| {
            let consumers_raw = consumers_raw.clone();
            async move {
                let result = consumers_raw
                    .update_one(
                        mongodb::bson::doc! { "_id": format!("{namespace}:{id}") },
                        mongodb::bson::doc! {
                            "$set": { "credentials.hmac_auth": [{ "secret": secret }] },
                        },
                    )
                    .await
                    .unwrap();
                assert_eq!(result.matched_count, 1);
            }
        },
    )
    .await;
    assert_mongo_orphaned_spec_refused(db.clone(), &raw).await;
    assert_mongo_deployment_raw_preservation(db.clone(), &raw).await;
    let locks = raw.collection::<mongodb::bson::Document>("config_admission_locks");
    assert_restore_renewal_and_fencing(db.clone(), move |namespace, ttl| {
        let locks = locks.clone();
        async move {
            let result = locks
                .update_one(
                    mongodb::bson::doc! { "_id": namespace },
                    vec![mongodb::bson::doc! {
                        "$set": { "expires_at": { "$add": [ "$$NOW", ttl ] } },
                    }],
                )
                .await
                .unwrap();
            assert_eq!(result.matched_count, 1);
        }
    })
    .await;
    assert_http_restore_spans_keeper_renewal(db.clone()).await;
    assert_mongo_legacy_consumer_tags(db, &raw).await;
}

#[tokio::test]
#[ignore = "Requires PostgreSQL supplied by POSTGRES_URL"]
async fn postgres_conditional_restore_checks_state_and_lease_in_transaction() {
    let url = std::env::var("POSTGRES_URL").expect("POSTGRES_URL is required");
    let db = DatabaseStore::connect_with_pool_config("postgres", &url, DbPoolConfig::default())
        .await
        .unwrap();
    assert_transaction_precondition(&db).await;
    assert_batch_proxy_scoped_plugin_association_parity(&db).await;
    assert_batch_admission_sees_implied_proxy_associations(&db).await;
    let db = Arc::new(db);
    assert_sql_deployment_raw_preservation(db.clone(), "postgres", &url).await;
    crate::integration::consumer_delta_quarantine_tests::assert_consumer_delta_quarantine_contract(
        db.as_ref(),
        |namespace, id, secret| {
            let store = db.clone();
            async move {
                crate::integration::consumer_delta_quarantine_tests::corrupt_sql_hmac_secret(
                    &store, &namespace, &id, &secret,
                )
                .await
            }
        },
    )
    .await;
    crate::integration::admin_plugin_graph_scope_tests::assert_policy_neighborhood_matches_restricted_graph(
        db.as_ref(),
    )
    .await;
    assert_deployment_mutation_contract(db.clone()).await;
    assert_deployment_cancellation_and_live_ack(db.clone()).await;
    assert_deployment_concurrent_writer_fences(db.clone()).await;
    let stalled_db = DatabaseStore::connect_with_pool_config(
        "postgres",
        &url,
        DbPoolConfig {
            statement_timeout_seconds: 0,
            ..DbPoolConfig::default()
        },
    )
    .await
    .unwrap();
    assert_postgres_stalled_cleanup_is_bounded(Arc::new(stalled_db)).await;
    assert_sql_restore_renewal(db.clone()).await;
    assert_http_restore_spans_keeper_renewal(db).await;
}

#[tokio::test]
#[ignore = "Requires MySQL supplied by MYSQL_URL"]
async fn mysql_conditional_restore_checks_state_and_lease_in_transaction() {
    let url = std::env::var("MYSQL_URL").expect("MYSQL_URL is required");
    let db = DatabaseStore::connect_with_pool_config("mysql", &url, DbPoolConfig::default())
        .await
        .unwrap();
    assert_transaction_precondition(&db).await;
    assert_batch_proxy_scoped_plugin_association_parity(&db).await;
    assert_batch_admission_sees_implied_proxy_associations(&db).await;
    let db = Arc::new(db);
    assert_sql_deployment_raw_preservation(db.clone(), "mysql", &url).await;
    crate::integration::consumer_delta_quarantine_tests::assert_consumer_delta_quarantine_contract(
        db.as_ref(),
        |namespace, id, secret| {
            let store = db.clone();
            async move {
                crate::integration::consumer_delta_quarantine_tests::corrupt_sql_hmac_secret(
                    &store, &namespace, &id, &secret,
                )
                .await
            }
        },
    )
    .await;
    crate::integration::admin_plugin_graph_scope_tests::assert_policy_neighborhood_matches_restricted_graph(
        db.as_ref(),
    )
    .await;
    assert_deployment_mutation_contract(db.clone()).await;
    assert_deployment_cancellation_and_live_ack(db.clone()).await;
    assert_deployment_concurrent_writer_fences(db.clone()).await;
    assert_sql_restore_renewal(db.clone()).await;
    assert_http_restore_spans_keeper_renewal(db).await;
}

/// The same contract runs inside the required SQLite and three live-store gates.
async fn assert_deployment_mutation_contract(db: Arc<dyn DatabaseBackend>) {
    use ferrum_edge::_test_support::{
        AtomicBatchFault, AtomicBatchPhase, set_atomic_batch_fault_for_test,
    };
    use ferrum_edge::config::db_backend::{
        NamespaceConfigAdmissionLeaseRef, NamespacePreconditionFailed, SnapshotDigest,
        is_batch_admission_lease_lost,
    };
    use ferrum_edge::config::deployment_mutation::{
        DeploymentPrecondition, is_deployment_commit_outcome_unknown,
    };
    use ferrum_edge::config::types::Consumer;

    assert_deployment_external_dependencies_refused(db.clone()).await;
    assert_issued_deployment_evidence_authorizes_the_transaction(db.clone()).await;

    let validation_http_client = ferrum_edge::plugins::PluginHttpClient::default();
    let namespace = format!("deployment-{}", uuid::Uuid::new_v4());
    let (base, _shutdown) = start_admin(admin_state(db.clone(), JWT_SECRET)).await;
    let mut document = json!({
        "openapi": "3.0.3", "info": {"title": "Deployment", "version": "1"},
        "paths": {"/items": {"get": {"responses": {"200": {"description": "OK"}}}}},
        "x-ferrum-proxy": {"id": "deployment", "listen_path": "/deployment",
            "backend_host": "backend.example.com", "backend_port": 8080},
        "x-ferrum-plugins": [{"id": "generated", "plugin_name": "cors",
            "config": {"allowed_origins": ["https://original.example"]}}]
    });
    let imported = send_ns(
        Method::POST,
        &base,
        "/api-specs",
        &admin_token(),
        None,
        Some(&document),
        &namespace,
    )
    .await;
    assert_eq!(imported.status, 201, "{}", imported.body);
    let spec_id = imported.body["id"].as_str().unwrap().to_string();
    let replace_path = format!("/api-specs/{spec_id}?conditional=true");
    let remove_path = "/proxies/deployment?conditional=true&cleanup_orphaned_upstream=false";
    // Historical credential representations and timestamps survive without
    // restore's normalization, credential preparation or trust re-publication.
    let consumer: Consumer = serde_json::from_value(json!({
        "namespace": namespace, "id": "historical", "username": "historical",
        "credentials": {"custom": [{"legacy": "  value  ", "nested": {"unknown": true}}]},
        "created_at": "2000-01-01T00:00:00Z", "updated_at": "2001-01-01T00:00:00Z"
    }))
    .unwrap();
    db.create_consumer(&consumer).await.unwrap();
    let trust = deployment_trust_record(&namespace);
    db.create_gateway_trust_bundle(&trust).await.unwrap();
    let trust_before = db
        .get_namespace_gateway_trust_bundle(&namespace)
        .await
        .unwrap()
        .unwrap();
    for (path, body) in [
        (
            "/upstreams",
            json!({"id": "retained", "name": "retained", "targets": [
                {"host": "backend.example.com", "port": 8080}
            ]}),
        ),
        (
            "/plugins/config",
            json!({"id": "shared", "plugin_name": "cors", "scope": "proxy_group",
                "config": {"allowed_origins": ["https://shared.example"]},
                "labels": {"unknown-owner-metadata": "retained"}}),
        ),
        (
            "/proxies",
            json!({"id": "unrelated", "listen_path": "/unrelated",
                "backend_host": "unrelated.example.com", "backend_port": 8080,
                "plugins": [{"plugin_config_id": "shared"}],
                "labels": {"unrelated-unknown": "keep"}}),
        ),
    ] {
        let result = send_ns(
            Method::POST,
            &base,
            path,
            &admin_token(),
            None,
            Some(&body),
            &namespace,
        )
        .await;
        assert_eq!(result.status, 201, "{}", result.body);
    }
    let mut target = get_ns(&base, "/proxies/deployment", &namespace).await.body;
    target["upstream_id"] = json!("retained");
    target["plugins"]
        .as_array_mut()
        .unwrap()
        .push(json!({"plugin_config_id": "shared"}));
    let updated = send_ns(
        Method::PUT,
        &base,
        "/proxies/deployment",
        &admin_token(),
        None,
        Some(&target),
        &namespace,
    )
    .await;
    assert_eq!(updated.status, 200, "{}", updated.body);

    let opened = get_ns(&base, "/deployment-snapshot", &namespace).await;
    assert_eq!(opened.status, 200, "{}", opened.body);
    assert_eq!(
        opened.etag.as_ref().unwrap(),
        opened.body["namespace_etag"].as_str().unwrap()
    );
    assert_eq!(opened.body["api_specs"][0]["id"], spec_id);
    // Stored spec documents appear only as digest and length, once per view.
    let stored = db.load_deployment_snapshot(&namespace).await.unwrap();
    let spec_content = &opened.body["api_specs"][0]["spec_content"];
    assert_eq!(
        spec_content["len"],
        stored.snapshot().api_specs[0].spec_content.len()
    );
    assert_eq!(spec_content["sha256"].as_str().unwrap().len(), 64);
    assert_eq!(
        opened.body["api_specs"],
        opened.body["evidence"]["resources"][5]
    );
    // One base64 copy of the stored bytes travels outside the evidence.
    let content = &opened.body["api_spec_contents"][0];
    assert_eq!(content["id"], spec_id);
    let encoded = content["spec_content_base64"].as_str().unwrap();
    let decoded = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap()
    };
    assert_eq!(decoded, stored.snapshot().api_specs[0].spec_content);
    assert!(
        !opened.body["evidence"].to_string().contains(encoded),
        "stored bytes must not enter the digested evidence"
    );
    for header in [
        None,
        Some("*"),
        Some(r#""row-token""#),
        Some(r#"W/"deployment-v1-00000000000000000000000000000000""#),
        Some(concat!(
            "\"deployment-v1-00000000000000000000000000000000\",",
            "\"deployment-v1-00000000000000000000000000000000\""
        )),
    ] {
        for (method, path, body) in [
            (Method::DELETE, remove_path, None),
            (Method::PUT, replace_path.as_str(), Some(&document)),
        ] {
            let result = send_ns(
                method,
                &base,
                path,
                &admin_token(),
                header,
                body,
                &namespace,
            )
            .await;
            assert_eq!(result.status, 400, "{}", result.body);
        }
    }
    for path in [
        "/proxies/deployment?conditional=true",
        "/proxies/deployment?conditional=false&cleanup_orphaned_upstream=false",
        "/proxies/deployment?conditional=true&conditional=true&cleanup_orphaned_upstream=false",
        "/proxies/deployment?conditional=true&cleanup_orphaned_upstream=false&apply=async",
        "/proxies/deployment",
    ] {
        let result = send_ns(
            Method::DELETE,
            &base,
            path,
            &admin_token(),
            opened.etag.as_deref(),
            None,
            &namespace,
        )
        .await;
        assert_eq!(result.status, 400, "{}", result.body);
    }
    for suffix in [
        "",
        "?conditional=false",
        "?conditional=true&conditional=true",
        "?conditional=true&apply=async",
    ] {
        let result = send_ns(
            Method::PUT,
            &base,
            &format!("/api-specs/{spec_id}{suffix}"),
            &admin_token(),
            opened.etag.as_deref(),
            Some(&document),
            &namespace,
        )
        .await;
        assert_eq!(result.status, 400, "{}", result.body);
    }
    for (method, path) in [
        (Method::PUT, "/proxies/deployment?conditional=true"),
        (Method::DELETE, "/plugins/config/generated?conditional=true"),
        (Method::POST, "/api-specs?conditional=true"),
    ] {
        let unsupported = send_ns(
            method,
            &base,
            path,
            &admin_token(),
            opened.etag.as_deref(),
            Some(&document),
            &namespace,
        )
        .await;
        assert_eq!(unsupported.status, 400, "{}", unsupported.body);
    }
    let duplicate = reqwest::Client::new()
        .delete(format!("{base}{remove_path}"))
        .bearer_auth(admin_token())
        .header("X-Ferrum-Namespace", &namespace)
        .header("If-Match", opened.etag.as_ref().unwrap())
        .header("If-Match", opened.etag.as_ref().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate.status().as_u16(), 400);
    assert_eq!(
        get_ns(&base, "/deployment-snapshot?conditional=true", &namespace)
            .await
            .status,
        400
    );

    let missing_sequence = db.latest_change_sequence(&namespace).await.unwrap();
    for (method, path, body) in [
        (
            Method::DELETE,
            "/proxies/missing?conditional=true&cleanup_orphaned_upstream=false",
            None,
        ),
        (
            Method::PUT,
            "/api-specs/missing?conditional=true",
            Some(&document),
        ),
    ] {
        let missing = send_ns(
            method,
            &base,
            path,
            &admin_token(),
            opened.etag.as_deref(),
            body,
            &namespace,
        )
        .await;
        assert_eq!(missing.status, 409, "{}", missing.body);
        assert_eq!(missing.body["durable"], "not_committed");
        assert_eq!(missing.body["live"], "unconfirmed");
        assert_eq!(missing.body["recovery_cleanup_authorized"], false);
        let unchanged = get_ns(&base, "/deployment-snapshot", &namespace).await;
        assert_eq!(unchanged.status, 200);
        assert!(unchanged.etag == opened.etag, "original authority changed");
        assert!(
            unchanged.body == opened.body,
            "missing-target refusal changed persisted deployment evidence"
        );
        assert_eq!(
            db.latest_change_sequence(&namespace).await.unwrap(),
            missing_sequence
        );
    }

    // Writes after the original evidence must invalidate both owner operations,
    // including document-only spec drift and unrelated rows in this namespace.
    for mutation in ["hosts", "plugin", "spec", "unrelated"] {
        let original = get_ns(&base, "/deployment-snapshot", &namespace).await;
        let (path, changed) = match mutation {
            "hosts" => {
                let mut proxy = get_ns(&base, "/proxies/deployment", &namespace).await.body;
                proxy["hosts"] = json!(["operator.example"]);
                ("/proxies/deployment".to_string(), Some(proxy))
            }
            "plugin" => {
                let mut plugin = get_ns(&base, "/plugins/config/generated", &namespace)
                    .await
                    .body;
                plugin["config"] = json!({"allowed_origins": ["https://operator.example"]});
                ("/plugins/config/generated".to_string(), Some(plugin))
            }
            "spec" => {
                document["info"]["description"] = json!("operator changed spec");
                (format!("/api-specs/{spec_id}"), Some(document.clone()))
            }
            _ => {
                let mut changed = consumer.clone();
                changed.acl_groups = vec!["operator".to_string()];
                db.update_consumer(&changed, &BatchConfigWriteMode::Admission)
                    .await
                    .unwrap();
                (String::new(), None)
            }
        };
        if let Some(changed) = changed {
            let updated = send_ns(
                Method::PUT,
                &base,
                &path,
                &admin_token(),
                None,
                Some(&changed),
                &namespace,
            )
            .await;
            assert_eq!(updated.status, 200, "{}", updated.body);
        }
        let current = db
            .load_deployment_snapshot(&namespace)
            .await
            .unwrap()
            .representation()
            .unwrap();
        for (method, path, body) in [
            (Method::DELETE, remove_path, None),
            (Method::PUT, replace_path.as_str(), Some(&document)),
        ] {
            let result = send_ns(
                method,
                &base,
                path,
                &admin_token(),
                original.etag.as_deref(),
                body,
                &namespace,
            )
            .await;
            assert_eq!(result.status, 412, "{}", result.body);
            assert_eq!(result.body["recovery_cleanup_authorized"], false);
        }
        assert_eq!(
            db.load_deployment_snapshot(&namespace)
                .await
                .unwrap()
                .representation()
                .unwrap(),
            current
        );
        // Bypass the handler's initial comparison to exercise the transaction
        // boundary itself, retaining the original representation on both calls.
        let owner = uuid::Uuid::new_v4().to_string();
        let generation = acquire_namespace_config_admission_lease_after_handler(
            db.as_ref(),
            &namespace,
            &owner,
        )
        .await;
        let precondition = DeploymentPrecondition {
            namespace: &namespace,
            expected: SnapshotDigest::of_representation(&original.body["evidence"]).unwrap(),
            validation_http_client: &validation_http_client,
            lease: NamespaceConfigAdmissionLeaseRef {
                owner: &owner,
                generation,
            },
        };
        let error = db
            .remove_deployment_conditionally("deployment", &precondition)
            .await
            .unwrap_err();
        assert!(error.chain().any(|e| e.is::<NamespacePreconditionFailed>()));
        let snapshot = db.load_deployment_snapshot(&namespace).await.unwrap();
        let spec = &snapshot.snapshot().api_specs[0];
        let bundle = deployment_bundle(&snapshot, "deployment", &spec_id);
        let error = db
            .replace_deployment_conditionally(&bundle, spec, &precondition)
            .await
            .unwrap_err();
        assert!(error.chain().any(|e| e.is::<NamespacePreconditionFailed>()));
        db.release_namespace_config_admission_lease(&namespace, &owner)
            .await
            .unwrap();
    }

    // An unrelated tenant write must not invalidate this tenant's authority.
    let original = get_ns(&base, "/deployment-snapshot", &namespace).await;
    let other: Consumer = serde_json::from_value(json!({
        "namespace": format!("other-{}", uuid::Uuid::new_v4()),
        "id": "other", "username": "other", "credentials": {}
    }))
    .unwrap();
    db.create_consumer(&other).await.unwrap();
    assert_eq!(
        get_ns(&base, "/deployment-snapshot", &namespace).await.etag,
        original.etag
    );

    // Entry loss with matching evidence cannot authorize either mutation.
    let snapshot = db.load_deployment_snapshot(&namespace).await.unwrap();
    let exact = snapshot.digest().unwrap();
    let spec = &snapshot.snapshot().api_specs[0];
    let bundle = deployment_bundle(&snapshot, "deployment", &spec_id);
    let precondition = DeploymentPrecondition {
        namespace: &namespace,
        expected: exact,
        validation_http_client: &validation_http_client,
        lease: NamespaceConfigAdmissionLeaseRef {
            owner: "missing-owner",
            generation: 999,
        },
    };
    let error = db
        .remove_deployment_conditionally("deployment", &precondition)
        .await
        .unwrap_err();
    assert!(is_batch_admission_lease_lost(&error));
    // Lease loss is raised before commit: known not committed.
    assert!(!is_deployment_commit_outcome_unknown(&error));
    let error = db
        .replace_deployment_conditionally(&bundle, spec, &precondition)
        .await
        .unwrap_err();
    assert!(is_batch_admission_lease_lost(&error));
    assert!(!is_deployment_commit_outcome_unknown(&error));

    // Failure immediately before commit must roll back both operations and
    // retain the original token, without compensation or freshly read retries.
    let sequence_before_fault = db.latest_change_sequence(&namespace).await.unwrap();
    for (method, path, body) in [
        (Method::DELETE, remove_path, None),
        (Method::PUT, replace_path.as_str(), Some(&document)),
    ] {
        set_atomic_batch_fault_for_test(
            &namespace,
            Some(AtomicBatchFault::new(AtomicBatchPhase::Commit, 0)),
        );
        let failed = send_ns(
            method,
            &base,
            path,
            &admin_token(),
            original.etag.as_deref(),
            body,
            &namespace,
        )
        .await;
        set_atomic_batch_fault_for_test(&namespace, None);
        assert_eq!(failed.status, 503, "{}", failed.body);
        // A failure raised before commit is attempted rolls back: it is known
        // not to have committed. Only a failed commit reports `unknown`.
        assert_eq!(failed.body["durable"], "not_committed");
        assert_eq!(failed.body["live"], "unconfirmed");
        assert_eq!(failed.body["recovery_cleanup_authorized"], false);
        let unchanged = get_ns(&base, "/deployment-snapshot", &namespace).await;
        assert!(unchanged.etag == original.etag);
        assert!(
            unchanged.body == original.body,
            "pre-commit persistence failure changed complete typed/raw evidence"
        );
        assert_eq!(
            db.latest_change_sequence(&namespace).await.unwrap(),
            sequence_before_fault
        );
    }

    let consumer_before = db
        .get_consumer(&namespace, "historical")
        .await
        .unwrap()
        .unwrap();
    let unrelated_before = db
        .get_proxy_for_write(&namespace, "unrelated")
        .await
        .unwrap()
        .unwrap();
    let shared_before = db
        .get_plugin_config(&namespace, "shared")
        .await
        .unwrap()
        .unwrap();
    let upstream_before = db
        .get_upstream(&namespace, "retained")
        .await
        .unwrap()
        .unwrap();
    let generated_before = db
        .get_plugin_config(&namespace, "generated")
        .await
        .unwrap()
        .unwrap();
    document["x-ferrum-proxy"]["backend_host"] = json!("replacement.example.com");
    let replaced = send_ns(
        Method::PUT,
        &base,
        &replace_path,
        &admin_token(),
        original.etag.as_deref(),
        Some(&document),
        &namespace,
    )
    .await;
    assert_eq!(replaced.status, 200, "{}", replaced.body);
    assert_eq!(replaced.body["durable"], "committed");
    // No serving poll loop: a durable-only acknowledgement forbids cleanup.
    assert_eq!(replaced.body["live"], "not_applicable");
    assert_eq!(replaced.body["recovery_cleanup_authorized"], false);
    let target = db
        .get_proxy_for_write(&namespace, "deployment")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(target.backend_host, "replacement.example.com");
    assert!(
        target
            .plugins
            .iter()
            .any(|a| a.plugin_config_id == "shared")
    );
    assert_eq!(
        db.get_plugin_config(&namespace, "generated")
            .await
            .unwrap()
            .unwrap()
            .created_at,
        generated_before.created_at
    );
    assert_eq!(
        db.get_plugin_config(&namespace, "generated")
            .await
            .unwrap()
            .unwrap()
            .updated_at,
        generated_before.updated_at
    );
    // Reattach the last-referenced hand-owned upstream before exact removal.
    let mut target = get_ns(&base, "/proxies/deployment", &namespace).await.body;
    target["upstream_id"] = json!("retained");
    let updated = send_ns(
        Method::PUT,
        &base,
        "/proxies/deployment",
        &admin_token(),
        None,
        Some(&target),
        &namespace,
    )
    .await;
    assert_eq!(updated.status, 200, "{}", updated.body);
    let exact = get_ns(&base, "/deployment-snapshot", &namespace).await;
    let removed = send_ns(
        Method::DELETE,
        &base,
        remove_path,
        &admin_token(),
        exact.etag.as_deref(),
        None,
        &namespace,
    )
    .await;
    assert_eq!(removed.status, 200, "{}", removed.body);
    assert_eq!(removed.body["durable"], "committed");
    assert_eq!(removed.body["recovery_cleanup_authorized"], false);
    assert!(
        db.get_proxy_for_write(&namespace, "deployment")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.get_api_spec(&namespace, &spec_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.get_plugin_config(&namespace, "generated")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        serde_json::to_value(
            db.get_consumer(&namespace, "historical")
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap()
            == serde_json::to_value(consumer_before).unwrap(),
        "stored credential preservation mismatch"
    );
    assert_eq!(
        serde_json::to_value(
            db.get_proxy_for_write(&namespace, "unrelated")
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        serde_json::to_value(unrelated_before).unwrap()
    );
    assert_eq!(
        serde_json::to_value(
            db.get_plugin_config(&namespace, "shared")
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        serde_json::to_value(shared_before).unwrap()
    );
    assert_eq!(
        serde_json::to_value(
            db.get_upstream(&namespace, "retained")
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        serde_json::to_value(upstream_before).unwrap()
    );
    assert_eq!(
        db.get_namespace_gateway_trust_bundle(&namespace)
            .await
            .unwrap()
            .unwrap(),
        trust_before
    );
}

/// The evidence issued by `GET /deployment-snapshot` digests to exactly what
/// the store recomputes inside its mutation transaction, so issued authority
/// is spendable at the transaction boundary itself, not only via a fresh read.
async fn assert_issued_deployment_evidence_authorizes_the_transaction(
    db: Arc<dyn DatabaseBackend>,
) {
    use ferrum_edge::config::db_backend::{NamespaceConfigAdmissionLeaseRef, SnapshotDigest};
    use ferrum_edge::config::deployment_mutation::DeploymentPrecondition;

    let validation_http_client = ferrum_edge::plugins::PluginHttpClient::default();
    let namespace = format!("issued-{}", uuid::Uuid::new_v4());
    let (base, _shutdown) = start_admin(admin_state(db.clone(), JWT_SECRET)).await;
    let document = json!({
        "openapi": "3.0.3", "info": {"title": "Issued", "version": "1"},
        "paths": {"/items": {"get": {"responses": {"200": {"description": "OK"}}}}},
        "x-ferrum-proxy": {"id": "issued", "listen_path": "/issued",
            "backend_host": "backend.example.com", "backend_port": 8080}
    });
    let imported = send_ns(
        Method::POST,
        &base,
        "/api-specs",
        &admin_token(),
        None,
        Some(&document),
        &namespace,
    )
    .await;
    assert_eq!(imported.status, 201, "{}", imported.body);
    let spec_id = imported.body["id"].as_str().unwrap().to_string();

    let issued = get_ns(&base, "/deployment-snapshot", &namespace).await;
    assert_eq!(issued.status, 200, "{}", issued.body);
    let expected = SnapshotDigest::of_representation(&issued.body["evidence"]).unwrap();
    // The issued evidence and the streamed store digest are one computation.
    assert_eq!(
        db.load_deployment_snapshot(&namespace)
            .await
            .unwrap()
            .digest()
            .unwrap(),
        expected
    );
    // Reissuing an unchanged namespace yields the same authority.
    assert_eq!(
        get_ns(&base, "/deployment-snapshot", &namespace).await.etag,
        issued.etag
    );

    let owner = uuid::Uuid::new_v4().to_string();
    let generation = acquire_namespace_config_admission_lease_after_handler(
        db.as_ref(),
        &namespace,
        &owner,
    )
    .await;
    let precondition = DeploymentPrecondition {
        namespace: &namespace,
        expected,
        validation_http_client: &validation_http_client,
        lease: NamespaceConfigAdmissionLeaseRef {
            owner: &owner,
            generation,
        },
    };
    db.remove_deployment_conditionally("issued", &precondition)
        .await
        .unwrap();
    db.release_namespace_config_admission_lease(&namespace, &owner)
        .await
        .unwrap();
    assert!(
        db.get_proxy_for_write(&namespace, "issued")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.get_api_spec(&namespace, &spec_id)
            .await
            .unwrap()
            .is_none()
    );
}

/// Each dependency shape allows metadata-only replacement, then retains one
/// original authority through conditional refusals and ordinary error contracts.
async fn assert_deployment_external_dependencies_refused(db: Arc<dyn DatabaseBackend>) {
    use ferrum_edge::config::types::{Consumer, Proxy};

    let (base, _shutdown) = start_admin(admin_state(db.clone(), JWT_SECRET)).await;
    for external_mesh in [false, true] {
        let namespace = format!("deployment-dependency-{}", uuid::Uuid::new_v4());
        let mut document = json!({
            "openapi": "3.0.3", "info": {"title": "Dependency", "version": "1"},
            "paths": {"/items": {"get": {"responses": {"200": {"description": "OK"}}}}},
            "x-ferrum-proxy": {"id": "dependency", "listen_path": "/dependency",
                "backend_host": "backend.example.com", "backend_port": 8080},
            "x-ferrum-upstream": {"id": "owned-upstream", "name": "owned-upstream",
                "targets": [{"host": "backend.example.com", "port": 8080}]},
            "x-ferrum-plugins": [{"id": "owned-plugin", "plugin_name": "cors",
                "config": {"allowed_origins": ["https://original.example"]}}]
        });
        let imported = send_ns(
            Method::POST,
            &base,
            "/api-specs",
            &admin_token(),
            None,
            Some(&document),
            &namespace,
        )
        .await;
        assert_eq!(imported.status, 201, "{}", imported.body);
        let spec_id = imported.body["id"].as_str().unwrap();
        let mut external_proxy = json!({
            "id": "external", "listen_path": "/external",
            "backend_host": "external.example.com", "backend_port": 8080,
            "labels": {"future-owner-metadata": "retained"}
        });
        if !external_mesh {
            external_proxy["upstream_id"] = json!("owned-upstream");
        }
        let sequence_before_admission = db.latest_change_sequence(&namespace).await.unwrap();
        let created = send_ns(
            Method::POST,
            &base,
            "/proxies",
            &admin_token(),
            None,
            Some(&external_proxy),
            &namespace,
        )
        .await;
        if external_mesh {
            assert_eq!(created.status, 201, "{}", created.body);
        } else {
            // Ordinary admission must still reject a hand-managed proxy that
            // attaches a spec-owned upstream. Seed the historical relationship
            // through persistence so the removal guard can be exercised.
            assert_eq!(created.status, 400, "{}", created.body);
            assert!(created.body.to_string().contains("is owned by api_spec"));
            assert!(
                db.get_proxy_for_write(&namespace, "external")
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                db.latest_change_sequence(&namespace).await.unwrap(),
                sequence_before_admission
            );
            external_proxy["namespace"] = json!(namespace);
            let historical: Proxy = serde_json::from_value(external_proxy).unwrap();
            db.create_proxy(&historical).await.unwrap();
        }
        if external_mesh {
            let plugin = send_ns(
                Method::POST,
                &base,
                "/plugins/config",
                &admin_token(),
                None,
                Some(&json!({
                    "id": "external-mesh", "plugin_name": "mesh_route_dispatch",
                    "scope": "global", "enabled": true,
                    "config": {"rules": [{"match": {"methods": ["GET"]},
                        "destination": {"upstream_id": "owned-upstream"}}]},
                    "labels": {"future-owner-metadata": "retained"}
                })),
                &namespace,
            )
            .await;
            assert_eq!(plugin.status, 201, "{}", plugin.body);
        }
        let consumer: Consumer = serde_json::from_value(json!({
            "namespace": namespace, "id": "historical", "username": "historical",
            "credentials": {"custom": [{"legacy": "  dependency-canary  ",
                "future": {"preserve": true}}]},
            "created_at": "2000-01-01T00:00:00Z", "updated_at": "2001-01-01T00:00:00Z"
        }))
        .unwrap();
        db.create_consumer(&consumer).await.unwrap();
        db.create_gateway_trust_bundle(&deployment_trust_record(&namespace))
            .await
            .unwrap();

        // Ordinary metadata-only PUT still takes the matching-resource shortcut
        // while an external owner references the generated upstream.
        let proxy_before = get_ns(&base, "/proxies/dependency", &namespace).await;
        assert_eq!(proxy_before.status, 200);
        assert!(proxy_before.etag.is_some());
        let ordinary_replace = format!("/api-specs/{spec_id}");
        document["info"]["description"] = json!("metadata-only update");
        let metadata = send_ns(
            Method::PUT,
            &base,
            &ordinary_replace,
            &admin_token(),
            None,
            Some(&document),
            &namespace,
        )
        .await;
        assert_eq!(metadata.status, 200, "{}", metadata.body);
        let proxy_after = get_ns(&base, "/proxies/dependency", &namespace).await;
        assert_eq!(proxy_after.status, 200);
        assert!(proxy_after.etag == proxy_before.etag);
        assert!(proxy_after.body == proxy_before.body);

        // Conditional metadata-only PUT also preserves the complete resource
        // graph while committing a covering proxy change for acknowledgement.
        let metadata_before = db.load_deployment_snapshot(&namespace).await.unwrap();
        let metadata_authority = get_ns(&base, "/deployment-snapshot", &namespace).await;
        assert_eq!(metadata_authority.status, 200);
        assert!(metadata_authority.etag.is_some());
        assert!(metadata_authority.body["evidence"] == metadata_before.representation().unwrap());
        let sequence_before_metadata = db.latest_change_sequence(&namespace).await.unwrap();
        assert_eq!(
            metadata_before.snapshot().change_sequence,
            sequence_before_metadata
        );
        let conditional_replace = format!("{ordinary_replace}?conditional=true");
        document["info"]["description"] = json!("conditional metadata-only update");
        let metadata = send_ns(
            Method::PUT,
            &base,
            &conditional_replace,
            &admin_token(),
            metadata_authority.etag.as_deref(),
            Some(&document),
            &namespace,
        )
        .await;
        assert_eq!(metadata.status, 200, "{}", metadata.body);
        assert_eq!(metadata.body["profile"], "deployment-v1");
        assert_eq!(metadata.body["id"], spec_id);
        assert_eq!(metadata.body["durable"], "committed");
        assert_eq!(metadata.body["live"], "not_applicable");
        assert_eq!(metadata.body["recovery_cleanup_authorized"], false);
        assert!(!metadata.body.to_string().contains("dependency-canary"));
        let proxy_after = get_ns(&base, "/proxies/dependency", &namespace).await;
        assert_eq!(proxy_after.status, 200);
        assert!(proxy_after.etag == proxy_before.etag);
        assert!(proxy_after.body == proxy_before.body);
        let stored_before = db.load_deployment_snapshot(&namespace).await.unwrap();
        let resources_before = metadata_before.snapshot().representation().unwrap();
        let resources_after = stored_before.snapshot().representation().unwrap();
        // These members cover proxies, consumers, upstreams, plugins, trust and
        // namespace metadata; only the spec and covering sequence may change.
        for index in [0, 1, 2, 3, 4, 6] {
            assert!(
                resources_after[index] == resources_before[index],
                "metadata-only replacement changed typed resource evidence at {index}"
            );
        }
        assert_eq!(
            stored_before.stored.as_object().unwrap().len(),
            metadata_before.stored.as_object().unwrap().len()
        );
        // Compare every non-spec raw table/document, including unknown columns,
        // association metadata, credential maps and identity reservation rows.
        for (name, rows) in metadata_before.stored.as_object().unwrap() {
            if name != "api_specs" {
                assert!(
                    stored_before.stored.get(name) == Some(rows),
                    "metadata-only replacement changed raw {name} evidence"
                );
            }
        }
        assert_eq!(metadata_before.snapshot().api_specs.len(), 1);
        assert_eq!(stored_before.snapshot().api_specs.len(), 1);
        let spec_before = &metadata_before.snapshot().api_specs[0];
        let spec_after = &stored_before.snapshot().api_specs[0];
        assert_eq!(spec_after.id, spec_before.id);
        assert_eq!(spec_after.proxy_id, spec_before.proxy_id);
        assert_eq!(spec_after.namespace, spec_before.namespace);
        assert_eq!(spec_after.created_at, spec_before.created_at);
        assert_eq!(spec_after.resource_hash, spec_before.resource_hash);
        assert_eq!(
            spec_after.description.as_deref(),
            Some("conditional metadata-only update")
        );
        assert_ne!(spec_after.content_hash, spec_before.content_hash);
        assert!(spec_after.spec_content != spec_before.spec_content);
        let sequence_after_metadata = db.latest_change_sequence(&namespace).await.unwrap();
        assert!(sequence_after_metadata > sequence_before_metadata);
        assert_eq!(
            stored_before.snapshot().change_sequence,
            sequence_after_metadata
        );
        let covering = db
            .load_incremental_config(&namespace, sequence_before_metadata)
            .await
            .unwrap();
        assert_eq!(covering.sequence_cursor, sequence_after_metadata);
        assert_eq!(covering.added_or_modified_proxies.len(), 1);
        assert_eq!(covering.added_or_modified_proxies[0].id, "dependency");
        assert!(covering.removed_proxy_ids.is_empty());
        assert!(covering.added_or_modified_consumers.is_empty());
        assert!(covering.removed_consumer_ids.is_empty());
        assert!(covering.added_or_modified_plugin_configs.is_empty());
        assert!(covering.removed_plugin_config_ids.is_empty());
        assert!(covering.added_or_modified_upstreams.is_empty());
        assert!(covering.removed_upstream_ids.is_empty());

        let config = &stored_before.snapshot().config;
        assert_eq!(stored_before.snapshot().api_specs.len(), 1);
        assert_eq!(stored_before.snapshot().api_specs[0].id, spec_id);
        assert_eq!(config.proxies.len(), 2);
        assert_eq!(config.upstreams.len(), 1);
        assert_eq!(config.upstreams[0].id, "owned-upstream");
        assert_eq!(config.upstreams[0].api_spec_id.as_deref(), Some(spec_id));
        let plugin_count = if external_mesh { 2 } else { 1 };
        assert_eq!(config.plugin_configs.len(), plugin_count);
        let owned_plugin = config
            .plugin_configs
            .iter()
            .find(|p| p.id == "owned-plugin")
            .unwrap();
        assert_eq!(owned_plugin.api_spec_id.as_deref(), Some(spec_id));
        let external = config.proxies.iter().find(|p| p.id == "external").unwrap();
        assert!(external.api_spec_id.is_none());
        if external_mesh {
            assert!(external.upstream_id.is_none());
            let plugin = config
                .plugin_configs
                .iter()
                .find(|p| p.id == "external-mesh")
                .unwrap();
            assert!(plugin.enabled);
            assert!(plugin.api_spec_id.is_none());
            assert_eq!(
                plugin.config["rules"][0]["destination"]["upstream_id"],
                "owned-upstream"
            );
        } else {
            assert_eq!(external.upstream_id.as_deref(), Some("owned-upstream"));
        }
        assert_eq!(config.consumers.len(), 1);
        assert!(
            serde_json::to_value(&config.consumers[0]).unwrap()
                == serde_json::to_value(&consumer).unwrap(),
            "historical credential evidence changed during setup"
        );
        let evidence_before = stored_before.representation().unwrap();
        // Successful metadata replacement advances authority legitimately.
        // Capture refusal authority once here and retain it for every refusal.
        let original = get_ns(&base, "/deployment-snapshot", &namespace).await;
        assert_eq!(original.status, 200);
        assert!(original.etag.is_some());
        assert!(original.etag != metadata_authority.etag);
        assert!(original.body["evidence"] == evidence_before);
        assert!(original.body["namespace_etag"].as_str() == original.etag.as_deref());
        let sequence_before = db.latest_change_sequence(&namespace).await.unwrap();
        assert_eq!(sequence_before, sequence_after_metadata);

        // The shared helper's Display remains useful to ordinary store callers.
        // Mongo's ordinary PUT exercises its non-session guard here as well.
        let mut bundle = deployment_bundle(&stored_before, "dependency", spec_id);
        bundle.upstream = Some(config.upstreams[0].clone());
        bundle.proxy.backend_host = "replacement.example.com".to_string();
        let mut spec = stored_before.snapshot().api_specs[0].clone();
        spec.resource_hash = ferrum_edge::admin::api_specs::hash_resource_bundle(&bundle).unwrap();
        let error = db
            .replace_api_spec_bundle(&bundle, &spec)
            .await
            .unwrap_err();
        let expected_message = if external_mesh {
            format!(
                "mesh_route_dispatch plugin_config \"external-mesh\" references a spec-owned \
                 upstream \"owned-upstream\" from api_spec {spec_id:?}; \
                 detach it before replacing or deleting the API spec"
            )
        } else {
            format!(
                "proxy \"external\" references a spec-owned upstream \"owned-upstream\" \
                 from api_spec {spec_id:?}; detach it before replacing or deleting the API spec"
            )
        };
        assert_eq!(error.to_string(), expected_message);

        // Change resources, not just spec metadata, so PUT must reach the
        // external dependency guard rather than its matching-resource shortcut.
        document["x-ferrum-proxy"]["backend_host"] = json!("replacement.example.com");
        document["x-ferrum-upstream"]["targets"][0]["host"] = json!("replacement.example.com");
        document["x-ferrum-plugins"][0]["config"]["allowed_origins"] =
            json!(["https://replacement.example"]);
        let ordinary_remove = "/proxies/dependency?cleanup_orphaned_upstream=false";
        let conditional_remove =
            "/proxies/dependency?conditional=true&cleanup_orphaned_upstream=false";
        for conditional in [true, false, true] {
            for (method, ordinary_path, conditional_path, body, ordinary_status) in [
                (
                    Method::DELETE,
                    ordinary_remove,
                    conditional_remove,
                    None,
                    503,
                ),
                (
                    Method::PUT,
                    ordinary_replace.as_str(),
                    conditional_replace.as_str(),
                    Some(&document),
                    422,
                ),
            ] {
                let result = send_ns(
                    method,
                    &base,
                    if conditional {
                        conditional_path
                    } else {
                        ordinary_path
                    },
                    &admin_token(),
                    if conditional {
                        original.etag.as_deref()
                    } else {
                        None
                    },
                    body,
                    &namespace,
                )
                .await;
                if conditional {
                    assert_eq!(result.status, 409, "{}", result.body);
                    assert_eq!(result.body["durable"], "not_committed");
                    assert_eq!(result.body["live"], "unconfirmed");
                    assert_eq!(result.body["recovery_cleanup_authorized"], false);
                } else {
                    assert_eq!(result.status, ordinary_status, "{}", result.body);
                    assert!(result.body.get("durable").is_none());
                    assert!(result.body.get("recovery_cleanup_authorized").is_none());
                }
                assert!(!result.body.to_string().contains("dependency-canary"));
                let unchanged = get_ns(&base, "/deployment-snapshot", &namespace).await;
                assert_eq!(unchanged.status, 200);
                assert!(
                    unchanged.etag == original.etag,
                    "original authority changed"
                );
                assert!(
                    unchanged.body == original.body,
                    "external dependency refusal changed complete typed/raw evidence"
                );
                assert!(
                    db.load_deployment_snapshot(&namespace)
                        .await
                        .unwrap()
                        .representation()
                        .unwrap()
                        == evidence_before,
                    "external dependency refusal changed persisted resources or identity indexes"
                );
                assert_eq!(
                    db.latest_change_sequence(&namespace).await.unwrap(),
                    sequence_before
                );
            }
        }
    }
}

fn deployment_trust_record(
    namespace: &str,
) -> ferrum_edge::config::gateway_trust::GatewayTrustBundleRecord {
    use base64::Engine;
    use ferrum_edge::config::gateway_trust::GatewayTrustBundleRecord;
    use ferrum_edge::identity::TrustDomain;
    use ferrum_edge::modes::mesh::config::{TrustBundle, TrustBundleSet};

    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let certificate = params.self_signed(&key).unwrap();
    GatewayTrustBundleRecord::new(
        namespace,
        namespace,
        TrustBundleSet {
            local: TrustBundle {
                trust_domain: TrustDomain::new("deployment.example").unwrap(),
                x509_authorities: vec![
                    base64::engine::general_purpose::STANDARD.encode(certificate.der()),
                ],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: Vec::new(),
        },
    )
}

fn deployment_bundle(
    snapshot: &ferrum_edge::config::deployment_mutation::DeploymentSnapshot,
    proxy_id: &str,
    spec_id: &str,
) -> ferrum_edge::admin::api_specs::ExtractedBundle {
    let typed = snapshot.snapshot();
    ferrum_edge::admin::api_specs::ExtractedBundle {
        proxy: typed
            .config
            .proxies
            .iter()
            .find(|p| p.id == proxy_id)
            .unwrap()
            .clone(),
        upstream: None,
        plugins: typed
            .config
            .plugin_configs
            .iter()
            .filter(|p| p.api_spec_id.as_deref() == Some(spec_id))
            .cloned()
            .collect(),
    }
}

async fn assert_deployment_cancellation_and_live_ack(db: Arc<dyn DatabaseBackend>) {
    use ferrum_edge::config::batch_atomicity::{
        ConditionalRestoreTestPause, set_conditional_restore_pause,
    };
    use ferrum_edge::config::runtime_config_apply::{LiveApplyCursor, RuntimeConfigApply};
    use std::time::Duration;

    for live in [false, true] {
        let namespace = format!("deployment-live-{}", uuid::Uuid::new_v4());
        let proxy: ferrum_edge::config::types::Proxy = serde_json::from_value(json!({
            "namespace": namespace, "id": "live", "listen_path": "/live-proxy",
            "backend_host": "backend.example.com", "backend_port": 8080
        }))
        .unwrap();
        db.create_proxy(&proxy).await.unwrap();
        let timeout = if live {
            Duration::from_secs(5)
        } else {
            Duration::from_millis(200)
        };
        let apply = Arc::new(RuntimeConfigApply::with_timeout_at_epoch(
            namespace.clone(),
            db.config_topology_epoch(),
            0,
            timeout,
        ));
        let mut state = admin_state(db.clone(), JWT_SECRET);
        state.runtime_config_apply = Some(apply.clone());
        let (base, _shutdown) = start_admin(state).await;
        let snapshot = get_ns(&base, "/deployment-snapshot", &namespace).await;
        let path = "/proxies/live?conditional=true&cleanup_orphaned_upstream=false";
        let request = tokio::spawn({
            let base = base.clone();
            let namespace = namespace.clone();
            let token = snapshot.etag.clone();
            async move {
                send_ns(
                    Method::DELETE,
                    &base,
                    path,
                    &admin_token(),
                    token.as_deref(),
                    None,
                    &namespace,
                )
                .await
            }
        });
        if live {
            tokio::time::timeout(Duration::from_secs(10), async {
                while apply.waiter_count() == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            apply.record_accepted_cursor(LiveApplyCursor::new(
                db.config_topology_epoch(),
                db.latest_change_sequence(&namespace).await.unwrap(),
            ));
        }
        let response = request.await.unwrap();
        assert_eq!(response.body["durable"], "committed");
        assert_eq!(
            response.status,
            if live { 200 } else { 503 },
            "{}",
            response.body
        );
        assert_eq!(response.body["recovery_cleanup_authorized"], live);
        assert_eq!(
            response.body["live"],
            if live { "applied" } else { "unconfirmed" }
        );
        assert!(
            db.get_proxy_for_write(&namespace, "live")
                .await
                .unwrap()
                .is_none()
        );
    }

    for replacement in [false, true] {
        let namespace = format!("deployment-cancel-{}", uuid::Uuid::new_v4());
        let (base, _shutdown) = start_admin(admin_state(db.clone(), JWT_SECRET)).await;
        let mut document = json!({
            "openapi": "3.0.3", "info": {"title": "Cancel", "version": "1"},
            "paths": {"/cancel": {"get": {"responses": {"200": {"description": "OK"}}}}},
            "x-ferrum-proxy": {"id": "cancel", "listen_path": "/cancel",
                "backend_host": "backend.example.com", "backend_port": 8080}
        });
        let imported = send_ns(
            Method::POST,
            &base,
            "/api-specs",
            &admin_token(),
            None,
            Some(&document),
            &namespace,
        )
        .await;
        assert_eq!(imported.status, 201, "{}", imported.body);
        let spec_id = imported.body["id"].as_str().unwrap();
        let original = get_ns(&base, "/deployment-snapshot", &namespace).await;
        let pause = Arc::new(ConditionalRestoreTestPause::default());
        set_conditional_restore_pause(&namespace, Some(pause.clone()));
        let path = if replacement {
            format!("/api-specs/{spec_id}?conditional=true")
        } else {
            "/proxies/cancel?conditional=true&cleanup_orphaned_upstream=false".to_string()
        };
        document["info"]["description"] = json!("cancellation completed");
        let method = if replacement {
            Method::PUT
        } else {
            Method::DELETE
        };
        let request = tokio::spawn({
            let namespace = namespace.clone();
            let base = base.clone();
            let token = original.etag.clone();
            let path = path.clone();
            let document = document.clone();
            let method = method.clone();
            async move {
                send_ns(
                    method,
                    &base,
                    &path,
                    &admin_token(),
                    token.as_deref(),
                    replacement.then_some(&document),
                    &namespace,
                )
                .await
            }
        });
        tokio::time::timeout(Duration::from_secs(10), pause.entered.notified())
            .await
            .unwrap();
        request.abort();
        assert!(matches!(request.await, Err(error) if error.is_cancelled()));
        pause.resume.notify_one();
        set_conditional_restore_pause(&namespace, None);
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let settled = if replacement {
                    db.get_api_spec(&namespace, spec_id)
                        .await
                        .unwrap()
                        .is_some_and(|s| s.description.as_deref() == Some("cancellation completed"))
                } else {
                    db.get_proxy_for_write(&namespace, "cancel")
                        .await
                        .unwrap()
                        .is_none()
                };
                if settled {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let replay = send_ns(
            method,
            &base,
            &path,
            &admin_token(),
            original.etag.as_deref(),
            replacement.then_some(&document),
            &namespace,
        )
        .await;
        assert_eq!(replay.status, 412, "{}", replay.body);
        assert_eq!(replay.body["recovery_cleanup_authorized"], false);
    }
}

/// A competing writer cannot enter the dependency graph after comparison and
/// before commit. An unrelated namespace remains independent where supported.
async fn assert_deployment_concurrent_writer_fences(db: Arc<dyn DatabaseBackend>) {
    use ferrum_edge::config::batch_atomicity::{
        ConditionalRestoreTestPause, set_conditional_restore_pause,
    };
    use std::time::Duration;

    let (base, _shutdown) = start_admin(admin_state(db.clone(), JWT_SECRET)).await;
    for replacement in [false, true] {
        let namespace = format!("deployment-fence-{}", uuid::Uuid::new_v4());
        let mut document = json!({
            "openapi": "3.0.3", "info": {"title": "Fence", "version": "1"},
            "paths": {"/items": {"get": {"responses": {"200": {"description": "OK"}}}}},
            "x-ferrum-proxy": {"id": "fenced", "listen_path": "/fenced",
                "backend_host": "backend.example.com", "backend_port": 8080},
            "x-ferrum-upstream": {"id": "generated-upstream", "targets": [
                {"host": "backend.example.com", "port": 8080}
            ]}
        });
        let imported = send_ns(
            Method::POST,
            &base,
            "/api-specs",
            &admin_token(),
            None,
            Some(&document),
            &namespace,
        )
        .await;
        assert_eq!(imported.status, 201, "{}", imported.body);
        let spec_id = imported.body["id"].as_str().unwrap();
        let unrelated: ferrum_edge::config::types::Proxy = serde_json::from_value(json!({
            "namespace": namespace, "id": "unrelated", "listen_path": "/unrelated",
            "backend_host": "unrelated.example.com", "backend_port": 8080
        }))
        .unwrap();
        db.create_proxy(&unrelated).await.unwrap();
        let snapshot = get_ns(&base, "/deployment-snapshot", &namespace).await;
        document["x-ferrum-proxy"]["hosts"] = json!(["replacement.example"]);
        let pause = Arc::new(ConditionalRestoreTestPause::default());
        set_conditional_restore_pause(&namespace, Some(pause.clone()));
        let request = tokio::spawn({
            let base = base.clone();
            let namespace = namespace.clone();
            let token = snapshot.etag.clone();
            let path = if replacement {
                format!("/api-specs/{spec_id}?conditional=true")
            } else {
                "/proxies/fenced?conditional=true&cleanup_orphaned_upstream=false".to_string()
            };
            async move {
                send_ns(
                    if replacement {
                        Method::PUT
                    } else {
                        Method::DELETE
                    },
                    &base,
                    &path,
                    &admin_token(),
                    token.as_deref(),
                    replacement.then_some(&document),
                    &namespace,
                )
                .await
            }
        });
        tokio::time::timeout(Duration::from_secs(10), pause.entered.notified())
            .await
            .unwrap();
        let mut writer = tokio::spawn({
            let db = db.clone();
            let mut changed = unrelated;
            changed.hosts = vec!["operator.example".to_string()];
            async move { db.update_proxy(&changed).await }
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut writer)
                .await
                .is_err(),
            "a writer crossed the comparison/commit admission fence"
        );
        pause.resume.notify_one();
        set_conditional_restore_pause(&namespace, None);
        let response = request.await.unwrap();
        assert_eq!(response.status, 200, "{}", response.body);
        assert_eq!(response.body["recovery_cleanup_authorized"], false);
        assert!(writer.await.unwrap().unwrap());
        assert_eq!(
            db.get_proxy_for_write(&namespace, "unrelated")
                .await
                .unwrap()
                .unwrap()
                .hosts,
            vec!["operator.example".to_string()]
        );
        assert_eq!(
            db.get_upstream(&namespace, "generated-upstream")
                .await
                .unwrap()
                .is_some(),
            replacement
        );
    }
}

/// Run on SQLite, PostgreSQL, MySQL and replica-set MongoDB, both with only
/// generated associations and with a hand-added association carrying raw metadata.
async fn assert_plugin_only_replacement_preserves_proxy(
    db: &dyn DatabaseBackend,
    base: &str,
    namespace: &str,
    spec_id: &str,
    document: &mut Value,
    hand_added: bool,
) {
    let proxy_id = document["x-ferrum-proxy"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let plugin_id = document["x-ferrum-plugins"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let proxy_path = format!("/proxies/{proxy_id}");
    let plugin_path = format!("/plugins/config/{plugin_id}");
    let proxy_before = get_ns(base, &proxy_path, namespace).await;
    let plugin_before = get_ns(base, &plugin_path, namespace).await;
    let stored_before = db.load_deployment_snapshot(namespace).await.unwrap();
    let original = get_ns(base, "/deployment-snapshot", namespace).await;
    assert_eq!(original.status, 200, "{}", original.body);
    assert_eq!(proxy_before.status, 200, "{}", proxy_before.body);
    assert_eq!(plugin_before.status, 200, "{}", plugin_before.body);
    assert_eq!(
        proxy_before.body["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["plugin_config_id"] == "hand-added"),
        hand_added
    );
    assert!(proxy_before.etag.is_some());
    assert!(plugin_before.etag.is_some());

    // Keep all IDs and proxy fields identical; only the plugin body changes.
    document["x-ferrum-plugins"][0]["config"] = json!({
        "allowed_origins": [format!("https://{}.example", uuid::Uuid::new_v4())]
    });
    let replace_path = format!("/api-specs/{spec_id}?conditional=true");
    let replaced = send_ns(
        Method::PUT,
        base,
        &replace_path,
        &admin_token(),
        original.etag.as_deref(),
        Some(&*document),
        namespace,
    )
    .await;
    assert_eq!(replaced.status, 200, "{}", replaced.body);
    assert_eq!(replaced.body["durable"], "committed");
    assert_eq!(replaced.body["recovery_cleanup_authorized"], false);
    let proxy_after = get_ns(base, &proxy_path, namespace).await;
    let plugin_after = get_ns(base, &plugin_path, namespace).await;
    assert_eq!(proxy_after.body, proxy_before.body);
    assert_eq!(proxy_after.etag, proxy_before.etag);
    assert_eq!(
        proxy_after.body["updated_at"],
        proxy_before.body["updated_at"]
    );
    assert_eq!(
        plugin_after.body["config"],
        document["x-ferrum-plugins"][0]["config"]
    );
    assert_ne!(plugin_after.body["config"], plugin_before.body["config"]);
    assert_ne!(plugin_after.etag, plugin_before.etag);
    let stored_after = db.load_deployment_snapshot(namespace).await.unwrap();
    // SQL captures every column; Mongo includes complete, ordered BSON bytes.
    assert_eq!(stored_before.stored["proxies"].as_array().unwrap().len(), 1);
    assert_eq!(
        stored_after.stored["proxies"],
        stored_before.stored["proxies"]
    );
    assert_eq!(
        stored_after.stored.get("proxy_plugins"),
        stored_before.stored.get("proxy_plugins")
    );
    for row in stored_before.stored["plugin_configs"].as_array().unwrap() {
        if row["id"]["value"] == plugin_id {
            let after = stored_after.stored["plugin_configs"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["id"]["value"] == plugin_id)
                .unwrap();
            for (column, value) in row.as_object().unwrap() {
                if column.starts_with("deployment_future_") || column == "created_at" {
                    assert_eq!(&after[column], value, "changed stored column {column}");
                }
            }
        }
    }
    let fresh = get_ns(base, "/deployment-snapshot", namespace).await;
    assert_ne!(fresh.etag, original.etag);
    let replay = send_ns(
        Method::PUT,
        base,
        &replace_path,
        &admin_token(),
        original.etag.as_deref(),
        Some(&*document),
        namespace,
    )
    .await;
    assert_eq!(replay.status, 412, "{}", replay.body);
    assert_eq!(
        get_ns(base, "/deployment-snapshot", namespace).await.etag,
        fresh.etag
    );
}

async fn add_hand_added_deployment_association(base: &str, namespace: &str, proxy_id: &str) {
    let created = send_ns(
        Method::POST,
        base,
        "/plugins/config",
        &admin_token(),
        None,
        Some(&json!({
            "id": "hand-added", "plugin_name": "cors", "scope": "proxy_group",
            "config": {"allowed_origins": ["https://hand-added.example"]}
        })),
        namespace,
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.body);
    let path = format!("/proxies/{proxy_id}");
    let mut target = get_ns(base, &path, namespace).await.body;
    target["plugins"]
        .as_array_mut()
        .unwrap()
        .push(json!({"plugin_config_id": "hand-added"}));
    let updated = send_ns(
        Method::PUT,
        base,
        &path,
        &admin_token(),
        None,
        Some(&target),
        namespace,
    )
    .await;
    assert_eq!(updated.status, 200, "{}", updated.body);
}

/// MongoDB can retain a spec after a partial/out-of-band proxy deletion. SQL's
/// baseline foreign keys cascade that spec, so exercise the actual orphan here.
async fn assert_mongo_orphaned_spec_refused(db: Arc<dyn DatabaseBackend>, raw: &mongodb::Database) {
    use ferrum_edge::config::types::Consumer;
    use mongodb::bson::{Document, doc};

    let namespace = format!("deployment-orphan-{}", uuid::Uuid::new_v4());
    let (base, _shutdown) = start_admin(admin_state(db.clone(), JWT_SECRET)).await;
    let mut document = json!({
        "openapi": "3.0.3", "info": {"title": "Orphan", "version": "1"},
        "paths": {"/items": {"get": {"responses": {"200": {"description": "OK"}}}}},
        "x-ferrum-proxy": {"id": "orphan", "listen_path": "/orphan",
            "backend_host": "backend.example.com", "backend_port": 8080},
        "x-ferrum-upstream": {"id": "orphan-upstream", "name": "orphan-upstream",
            "targets": [{"host": "backend.example.com", "port": 8080}]},
        "x-ferrum-plugins": [{"id": "orphan-plugin", "plugin_name": "cors",
            "config": {"allowed_origins": ["https://original.example"]}}]
    });
    let imported = send_ns(
        Method::POST,
        &base,
        "/api-specs",
        &admin_token(),
        None,
        Some(&document),
        &namespace,
    )
    .await;
    assert_eq!(imported.status, 201, "{}", imported.body);
    let spec_id = imported.body["id"].as_str().unwrap();
    let unrelated = send_ns(
        Method::POST,
        &base,
        "/proxies",
        &admin_token(),
        None,
        Some(&json!({"id": "unrelated", "listen_path": "/unrelated",
            "backend_host": "unrelated.example.com", "backend_port": 8080,
            "labels": {"future-owner-metadata": "retained"}})),
        &namespace,
    )
    .await;
    assert_eq!(unrelated.status, 201, "{}", unrelated.body);
    let consumer: Consumer = serde_json::from_value(json!({
        "namespace": namespace, "id": "historical", "username": "historical",
        "credentials": {"custom": [{"legacy": "  orphan-canary  ",
            "future": {"preserve": true}}]},
        "created_at": "2000-01-01T00:00:00Z", "updated_at": "2001-01-01T00:00:00Z"
    }))
    .unwrap();
    db.create_consumer(&consumer).await.unwrap();
    let trust = deployment_trust_record(&namespace);
    db.create_gateway_trust_bundle(&trust).await.unwrap();

    // Delete only the raw proxy document, leaving its persisted spec, generated
    // plugin and upstream intact. Do not use CRUD's complete deployment cascade.
    let deleted = raw
        .collection::<Document>("proxies")
        .delete_one(doc! { "_id": format!("{namespace}:orphan") })
        .await
        .unwrap();
    assert_eq!(deleted.deleted_count, 1);
    assert!(
        db.get_proxy_for_write(&namespace, "orphan")
            .await
            .unwrap()
            .is_none()
    );
    let stored_before = db.load_deployment_snapshot(&namespace).await.unwrap();
    assert_eq!(stored_before.snapshot().api_specs.len(), 1);
    assert_eq!(stored_before.snapshot().api_specs[0].id, spec_id);
    assert_eq!(stored_before.snapshot().api_specs[0].proxy_id, "orphan");
    assert_eq!(stored_before.snapshot().config.proxies.len(), 1);
    assert_eq!(stored_before.snapshot().config.proxies[0].id, "unrelated");
    assert_eq!(stored_before.snapshot().config.plugin_configs.len(), 1);
    assert_eq!(stored_before.snapshot().config.upstreams.len(), 1);
    let evidence_before = stored_before.representation().unwrap();

    // Coherent, decodable original authority may describe an invalid graph.
    // It authorizes comparison, not recreation of the missing dependency.
    let original = get_ns(&base, "/deployment-snapshot", &namespace).await;
    assert_eq!(original.status, 200);
    assert!(original.etag.is_some());
    assert!(original.body["evidence"] == evidence_before);
    assert!(
        original.body["namespace_etag"].as_str() == original.etag.as_deref(),
        "snapshot must return the original authority in both places"
    );
    let sequence_before = db.latest_change_sequence(&namespace).await.unwrap();
    let read_changes = || async {
        let mut rows = Vec::new();
        for name in ["config_changes", "config_change_counters"] {
            let filter = if name == "config_changes" {
                doc! { "namespace": &namespace }
            } else {
                doc! {}
            };
            let mut cursor = raw
                .collection::<Document>(name)
                .find(filter)
                .sort(doc! { "_id": 1 })
                .await
                .unwrap();
            while cursor.advance().await.unwrap() {
                let row = cursor.deserialize_current().unwrap();
                let bytes = mongodb::bson::to_vec(&row).unwrap();
                rows.push((name, bytes));
            }
        }
        rows
    };
    let changes_before = read_changes().await;
    document["info"]["description"] = json!("replacement must not persist");
    document["x-ferrum-upstream"]["targets"][0]["host"] = json!("replacement.example.com");
    document["x-ferrum-plugins"][0]["config"]["allowed_origins"] =
        json!(["https://replacement.example"]);

    // Repeated conditional attempts retain the exact original token. The
    // ordinary PUT retains its existing redacted 500 contract for this state.
    for conditional in [true, false, true] {
        let path = if conditional {
            format!("/api-specs/{spec_id}?conditional=true")
        } else {
            format!("/api-specs/{spec_id}")
        };
        let result = send_ns(
            Method::PUT,
            &base,
            &path,
            &admin_token(),
            if conditional {
                original.etag.as_deref()
            } else {
                None
            },
            Some(&document),
            &namespace,
        )
        .await;
        if conditional {
            assert_eq!(result.status, 409, "{}", result.body);
            assert_eq!(result.body["durable"], "not_committed");
            assert_eq!(result.body["live"], "unconfirmed");
            assert_eq!(result.body["recovery_cleanup_authorized"], false);
        } else {
            assert_eq!(result.status, 500);
            assert_eq!(result.body, json!({"error": "Internal server error"}));
        }
        assert!(!result.body.to_string().contains("orphan-canary"));
        let unchanged = get_ns(&base, "/deployment-snapshot", &namespace).await;
        assert_eq!(unchanged.status, 200);
        assert!(
            unchanged.etag == original.etag,
            "original authority changed"
        );
        assert!(
            unchanged.body == original.body,
            "orphan refusal changed complete typed/raw deployment evidence"
        );
        let stored_after = db.load_deployment_snapshot(&namespace).await.unwrap();
        assert!(
            stored_after.representation().unwrap() == evidence_before,
            "orphan refusal changed persisted resources or identity indexes"
        );
        assert_eq!(
            db.latest_change_sequence(&namespace).await.unwrap(),
            sequence_before
        );
        assert!(
            read_changes().await == changes_before,
            "orphan refusal changed durable change rows or counters"
        );
    }
}

async fn assert_mongo_deployment_raw_preservation(
    db: Arc<dyn DatabaseBackend>,
    raw: &mongodb::Database,
) {
    use mongodb::bson::{Document, doc};

    let namespace = format!("deployment-raw-{}", uuid::Uuid::new_v4());
    let (base, _shutdown) = start_admin(admin_state(db.clone(), JWT_SECRET)).await;
    let mut document = json!({
        "openapi": "3.0.3", "info": {"title": "Raw", "version": "1"},
        "paths": {"/raw": {"get": {"responses": {"200": {"description": "OK"}}}}},
        "x-ferrum-proxy": {"id": "raw", "listen_path": "/raw",
            "backend_host": "backend.example.com", "backend_port": 8080},
        "x-ferrum-plugins": [{"id": "raw-generated", "plugin_name": "cors",
            "config": {"allowed_origins": ["https://original.example"]}}]
    });
    let imported = send_ns(
        Method::POST,
        &base,
        "/api-specs",
        &admin_token(),
        None,
        Some(&document),
        &namespace,
    )
    .await;
    assert_eq!(imported.status, 201, "{}", imported.body);
    let spec_id = imported.body["id"].as_str().unwrap();
    let proxies = raw.collection::<Document>("proxies");
    proxies
        .update_one(
            doc! { "_id": format!("{namespace}:raw") },
            doc! { "$set": { "plugins.0.future_metadata": {
                "owner": "retained", "nested": [1, "opaque"],
            } } },
        )
        .await
        .unwrap();
    assert_plugin_only_replacement_preserves_proxy(
        db.as_ref(),
        &base,
        &namespace,
        spec_id,
        &mut document,
        false,
    )
    .await;
    add_hand_added_deployment_association(&base, &namespace, "raw").await;
    proxies
        .update_one(
            doc! { "_id": format!("{namespace}:raw") },
            doc! { "$set": {
                "plugins.0.future_metadata": { "owner": "generated", "nested": [1, "opaque"] },
                "plugins.1.future_metadata": { "owner": "hand-added", "nested": [2, "opaque"] },
                "created_at": "2000-01-01T00:00:00Z",
                "updated_at": "2001-01-01T00:00:00Z",
            } },
        )
        .await
        .unwrap();
    assert_plugin_only_replacement_preserves_proxy(
        db.as_ref(),
        &base,
        &namespace,
        spec_id,
        &mut document,
        true,
    )
    .await;
    let association_before = proxies
        .find_one(doc! { "_id": format!("{namespace}:raw") })
        .await
        .unwrap()
        .unwrap()
        .get_array("plugins")
        .unwrap()
        .clone();
    let consumers = raw.collection::<Document>("consumers");
    consumers
        .insert_one(doc! {
            "_id": format!("{namespace}:historical"), "namespace": &namespace,
            "id": "historical", "username": "historical", "custom_id": " \t ",
            "credentials": { "custom": [{ "secret": " historical-canary ",
                "future": { "preserve": true } }] },
            "created_at": "2000-01-01T00:00:00Z", "updated_at": "2001-01-01T00:00:00Z",
        })
        .await
        .unwrap();
    let historical = consumers
        .find_one(doc! { "_id": format!("{namespace}:historical") })
        .await
        .unwrap()
        .unwrap();
    let original = get_ns(&base, "/deployment-snapshot", &namespace).await;
    assert_eq!(original.status, 200, "{}", original.body);
    // Unknown association fields participate even without a change-log row.
    proxies
        .update_one(
            doc! { "_id": format!("{namespace}:raw") },
            doc! { "$set": { "plugins.0.future_metadata.owner": "operator" } },
        )
        .await
        .unwrap();
    let remove_path = "/proxies/raw?conditional=true&cleanup_orphaned_upstream=false";
    let replace_path = format!("/api-specs/{spec_id}?conditional=true");
    for (method, path, body) in [
        (Method::DELETE, remove_path, None),
        (Method::PUT, replace_path.as_str(), Some(&document)),
    ] {
        let stale = send_ns(
            method,
            &base,
            path,
            &admin_token(),
            original.etag.as_deref(),
            body,
            &namespace,
        )
        .await;
        assert_eq!(stale.status, 412, "{}", stale.body);
    }
    proxies
        .update_one(
            doc! { "_id": format!("{namespace}:raw") },
            doc! { "$set": { "plugins": &association_before } },
        )
        .await
        .unwrap();
    let exact = get_ns(&base, "/deployment-snapshot", &namespace).await;
    document["x-ferrum-proxy"]["backend_host"] = json!("replacement.example.com");
    let replaced = send_ns(
        Method::PUT,
        &base,
        &replace_path,
        &admin_token(),
        exact.etag.as_deref(),
        Some(&document),
        &namespace,
    )
    .await;
    assert_eq!(replaced.status, 200, "{}", replaced.body);
    assert!(!replaced.body.to_string().contains("historical-canary"));
    assert_eq!(
        proxies
            .find_one(doc! { "_id": format!("{namespace}:raw") })
            .await
            .unwrap()
            .unwrap()
            .get_array("plugins")
            .unwrap(),
        &association_before
    );
    assert!(
        consumers
            .find_one(doc! { "_id": format!("{namespace}:historical") })
            .await
            .unwrap()
            .unwrap()
            == historical,
        "stored credential preservation mismatch"
    );

    // A schema-rejected resource field refuses authority rather than being
    // projected away, and does not erase the original stored representation.
    consumers
        .update_one(
            doc! { "_id": format!("{namespace}:historical") },
            doc! { "$set": { "future_resource_field": "preserve" } },
        )
        .await
        .unwrap();
    assert_eq!(
        get_ns(&base, "/deployment-snapshot", &namespace)
            .await
            .status,
        503
    );
    consumers
        .update_one(
            doc! { "_id": format!("{namespace}:historical") },
            doc! { "$unset": { "future_resource_field": "" } },
        )
        .await
        .unwrap();

    // Reject security audit only for this fixture's namespace. A bad fallback
    // path then proves that neither read disclosure nor mutation is admitted.
    let original = get_ns(&base, "/deployment-snapshot", &namespace).await;
    raw.run_command(doc! {
        "collMod": "audit_events",
        "validator": { "namespace": { "$ne": &namespace } },
        "validationLevel": "strict", "validationAction": "error",
    })
    .await
    .unwrap();
    let fallback = tempfile::NamedTempFile::new().unwrap();
    let mut state = admin_state(db.clone(), JWT_SECRET);
    state.admin_audit_fallback_dir = Some(fallback.path().to_path_buf());
    let (denied_base, _denied_shutdown) = start_admin(state).await;
    assert_eq!(
        get_ns(&denied_base, "/deployment-snapshot", &namespace)
            .await
            .status,
        503
    );
    for (method, path, body) in [
        (Method::DELETE, remove_path, None),
        (Method::PUT, replace_path.as_str(), Some(&document)),
    ] {
        let denied = send_ns(
            method,
            &denied_base,
            path,
            &admin_token(),
            original.etag.as_deref(),
            body,
            &namespace,
        )
        .await;
        assert_eq!(denied.status, 503, "{}", denied.body);
        assert_eq!(denied.body["recovery_cleanup_authorized"], false);
        assert_eq!(denied.body["durable"], "not_started");
        assert!(!denied.body.to_string().contains("historical-canary"));
    }
    raw.run_command(doc! { "collMod": "audit_events", "validator": {} })
        .await
        .unwrap();
    assert_eq!(
        get_ns(&base, "/deployment-snapshot", &namespace).await.etag,
        original.etag
    );
    // Audit rejection after a proven commit and local application still
    // denies successful cleanup. The admitted intent itself remains durable.
    raw.run_command(doc! {
        "collMod": "audit_events",
        "validator": { "$or": [
            { "namespace": { "$ne": &namespace } },
            { "diff": { "$regex": r#""phase":"admitted""# } },
        ] },
        "validationLevel": "strict", "validationAction": "error",
    })
    .await
    .unwrap();
    let apply = Arc::new(
        ferrum_edge::config::runtime_config_apply::RuntimeConfigApply::with_timeout_at_epoch(
            namespace.clone(),
            db.config_topology_epoch(),
            0,
            std::time::Duration::from_secs(5),
        ),
    );
    let mut state = admin_state(db.clone(), JWT_SECRET);
    state.admin_audit_fallback_dir = Some(fallback.path().to_path_buf());
    state.runtime_config_apply = Some(apply.clone());
    let (final_base, _final_shutdown) = start_admin(state).await;
    let request = tokio::spawn({
        let namespace = namespace.clone();
        let token = original.etag.clone();
        async move {
            send_ns(
                Method::DELETE,
                &final_base,
                remove_path,
                &admin_token(),
                token.as_deref(),
                None,
                &namespace,
            )
            .await
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while apply.waiter_count() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    apply.record_accepted_cursor(
        ferrum_edge::config::runtime_config_apply::LiveApplyCursor::new(
            db.config_topology_epoch(),
            db.latest_change_sequence(&namespace).await.unwrap(),
        ),
    );
    let removed = request.await.unwrap();
    assert_eq!(removed.status, 503, "{}", removed.body);
    assert_eq!(removed.body["durable"], "committed");
    assert_eq!(removed.body["live"], "unconfirmed");
    assert_eq!(removed.body["recovery_cleanup_authorized"], false);
    raw.run_command(doc! { "collMod": "audit_events", "validator": {} })
        .await
        .unwrap();
    assert!(
        db.get_proxy_for_write(&namespace, "raw")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        consumers
            .find_one(doc! { "_id": format!("{namespace}:historical") })
            .await
            .unwrap()
            .unwrap()
            == historical,
        "stored credential preservation mismatch"
    );
}

/// Probe admission reads without exposing the graph or driver error text.
async fn assert_postgres_fixture_policy_graph_read(db: &DatabaseStore, namespace: &str) {
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        db.load_namespace_policy_graph(namespace),
    )
    .await;
    match result {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            let sqlx_error = error
                .chain()
                .find_map(|cause| cause.downcast_ref::<sqlx::Error>());
            let category = match sqlx_error {
                Some(sqlx::Error::Database(_)) => "database",
                Some(sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_)) => "decode",
                Some(sqlx::Error::AnyDriverError(_)) => "any_driver_mapping",
                Some(sqlx::Error::Io(_)) => "io",
                Some(sqlx::Error::Tls(_)) => "tls",
                Some(sqlx::Error::Protocol(_)) => "protocol",
                Some(sqlx::Error::PoolTimedOut) => "pool_timeout",
                Some(sqlx::Error::PoolClosed) => "pool_closed",
                Some(sqlx::Error::WorkerCrashed) => "worker_crashed",
                Some(_) => "sqlx_other",
                None => "non_sqlx",
            };
            let sqlstate = sqlx_error
                .and_then(sqlx::Error::as_database_error)
                .and_then(|error| error.code())
                .filter(|code| {
                    code.len() == 5
                        && code
                            .bytes()
                            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
                });
            panic!(
                "operation=load_namespace_policy_graph category={category} sqlstate={}",
                sqlstate.as_deref().unwrap_or("unavailable")
            );
        }
        Err(_) => {
            panic!("operation=load_namespace_policy_graph category=timeout sqlstate=unavailable")
        }
    }
}

/// PostgreSQL must see the native parameter types supplied through SQLx Any.
/// Casting only pg_typeof's result cannot hide reversed typed-NULL bindings.
async fn assert_postgres_any_float_null_parameter_types(pool: &sqlx::AnyPool) {
    use sqlx::Row;

    let row = sqlx::query(
        "SELECT pg_typeof($1)::text AS real_type, $1 IS NULL AS real_is_null, \
         pg_typeof($2)::text AS double_type, $2 IS NULL AS double_is_null",
    )
    .bind(Option::<f32>::None)
    .bind(Option::<f64>::None)
    .fetch_one(pool)
    .await
    .unwrap();
    let real_type: String = row.try_get("real_type").unwrap();
    let real_is_null: bool = row.try_get("real_is_null").unwrap();
    let double_type: String = row.try_get("double_type").unwrap();
    let double_is_null: bool = row.try_get("double_is_null").unwrap();
    assert_eq!(real_type, "real");
    assert!(real_is_null);
    assert_eq!(double_type, "double precision");
    assert!(double_is_null);
}

/// Fixture-only extended schemas prove unknown SQL columns participate in
/// authority and survive selected replacement. This does not qualify online DDL.
async fn assert_sql_deployment_raw_preservation(
    db: Arc<DatabaseStore>,
    dialect: &str,
    db_url: &str,
) {
    use sqlx::any::AnyTypeInfoKind;
    use sqlx::{Row, ValueRef};

    let namespace = format!("deployment-sql-{}", uuid::Uuid::new_v4());
    let pool = db.pool();
    for table in ["proxies", "plugin_configs", "proxy_plugins"] {
        sqlx::query(&format!(
            "ALTER TABLE {table} ADD COLUMN deployment_future_metadata TEXT"
        ))
        .execute(&pool)
        .await
        .unwrap();
        let blob_type = if dialect == "postgres" {
            "BYTEA"
        } else {
            "BLOB"
        };
        let real_type = if dialect == "mysql" { "FLOAT" } else { "REAL" };
        for (column, sql_type) in [
            ("deployment_future_count", "BIGINT"),
            ("deployment_future_small", "SMALLINT"),
            ("deployment_future_integer", "INTEGER"),
            ("deployment_future_real", real_type),
            ("deployment_future_double", "DOUBLE PRECISION"),
            ("deployment_future_bytes", blob_type),
            ("deployment_future_null_small", "SMALLINT"),
            ("deployment_future_null_int", "INTEGER"),
            ("deployment_future_null_integer", "BIGINT"),
            ("deployment_future_null_real", real_type),
            ("deployment_future_null_double", "DOUBLE PRECISION"),
            ("deployment_future_null_text", "TEXT"),
            ("deployment_future_null_bytes", blob_type),
        ] {
            sqlx::query(&format!(
                "ALTER TABLE {table} ADD COLUMN {column} {sql_type}"
            ))
            .execute(&pool)
            .await
            .unwrap();
        }
        if dialect == "postgres" {
            for column in ["deployment_future_flag", "deployment_future_null_flag"] {
                sqlx::query(&format!("ALTER TABLE {table} ADD COLUMN {column} BOOLEAN"))
                    .execute(&pool)
                    .await
                    .unwrap();
            }
        } else if dialect == "sqlite" {
            // SQLite can store text in an integer-affinity column. Decoding by
            // column type instead of runtime value type would fail this fixture.
            sqlx::query(&format!(
                "ALTER TABLE {table} ADD COLUMN deployment_future_dynamic BIGINT"
            ))
            .execute(&pool)
            .await
            .unwrap();
        }
    }
    // Precondition reads have warmed SELECT * before the fixture's ALTERs.
    // Refresh cached statement metadata once, on the SAME durable database,
    // after every table is extended and before any raw authority is captured.
    drop(pool);
    db.reconnect(db_url)
        .await
        .unwrap_or_else(|_| panic!("SQL raw fixture reconnect failed"));
    let pool = db.pool();
    if dialect == "postgres" {
        assert_postgres_fixture_policy_graph_read(db.as_ref(), &namespace).await;
        assert_postgres_any_float_null_parameter_types(&pool).await;
    }
    let (base, _shutdown) = start_admin(admin_state(db.clone(), JWT_SECRET)).await;
    let mut document = json!({
        "openapi": "3.0.3", "info": {"title": "SQL", "version": "1"},
        "paths": {"/sql": {"get": {"responses": {"200": {"description": "OK"}}}}},
        "x-ferrum-proxy": {"id": "sql", "listen_path": "/sql",
            "backend_host": "backend.example.com", "backend_port": 8080},
        "x-ferrum-plugins": [{"id": "sql-generated", "plugin_name": "cors",
            "config": {"allowed_origins": ["https://original.example"]}}]
    });
    let imported = send_ns(
        Method::POST,
        &base,
        "/api-specs",
        &admin_token(),
        None,
        Some(&document),
        &namespace,
    )
    .await;
    assert_eq!(imported.status, 201, "{}", imported.body);
    let spec_id = imported.body["id"].as_str().unwrap();
    let placeholder = if dialect == "postgres" { "$1" } else { "?" };
    for table in ["proxies", "plugin_configs", "proxy_plugins"] {
        sqlx::query(&format!(
            "UPDATE {table} SET deployment_future_metadata = ' opaque-original ' \
             WHERE namespace = {placeholder}"
        ))
        .bind(&namespace)
        .execute(&pool)
        .await
        .unwrap();
    }
    for hand_added in [false, true] {
        if hand_added {
            add_hand_added_deployment_association(&base, &namespace, "sql").await;
        }
        let second = if dialect == "postgres" { "$2" } else { "?" };
        for table in ["proxies", "plugin_configs", "proxy_plugins"] {
            sqlx::query(&format!(
                "UPDATE {table} SET deployment_future_metadata = ' opaque-original ', \
                 deployment_future_count = 9007199254740993, deployment_future_small = -123, \
                 deployment_future_integer = 123456, deployment_future_real = 1.25, \
                 deployment_future_double = -0.125, deployment_future_bytes = {placeholder} \
                 WHERE namespace = {second}"
            ))
            .bind(vec![0u8, 255, 1, 128])
            .bind(&namespace)
            .execute(&pool)
            .await
            .unwrap();
            if dialect == "postgres" {
                sqlx::query(&format!(
                    "UPDATE {table} SET deployment_future_flag = TRUE \
                     WHERE namespace = {placeholder}"
                ))
                .bind(&namespace)
                .execute(&pool)
                .await
                .unwrap();
            } else if dialect == "sqlite" {
                sqlx::query(&format!(
                    "UPDATE {table} SET deployment_future_dynamic = '007opaque' \
                     WHERE namespace = {placeholder}"
                ))
                .bind(&namespace)
                .execute(&pool)
                .await
                .unwrap();
            }
        }
        sqlx::query(&format!(
            "UPDATE proxies SET hosts = ' [ ] ', created_at = '2000-01-01T00:00:00Z', \
             updated_at = '2001-01-01T00:00:00Z' WHERE namespace = {placeholder}"
        ))
        .bind(&namespace)
        .execute(&pool)
        .await
        .unwrap();
        let raw_before = db.load_deployment_snapshot(&namespace).await.unwrap();
        let proxy_row = &raw_before.stored["proxies"][0];
        assert_eq!(
            proxy_row["deployment_future_count"]["value"],
            9007199254740993i64
        );
        assert_eq!(proxy_row["deployment_future_small"]["value"], -123);
        assert_eq!(proxy_row["deployment_future_integer"]["value"], 123456);
        assert_eq!(
            proxy_row["deployment_future_bytes"]["value"],
            json!({
                "sha256": "edc81f7e4ee358fb91e94bd9bd74079c3dcba36f40f2c8a36e7ae0567afecc8f",
                "len": 4,
            })
        );
        for column in [
            "deployment_future_null_small",
            "deployment_future_null_int",
            "deployment_future_null_integer",
            "deployment_future_null_real",
            "deployment_future_null_double",
            "deployment_future_null_text",
            "deployment_future_null_bytes",
        ] {
            assert_eq!(proxy_row[column]["value"], Value::Null);
        }
        if dialect == "sqlite" {
            assert_eq!(proxy_row["deployment_future_dynamic"]["value"], "007opaque");
            assert_eq!(proxy_row["deployment_future_dynamic"]["value_type"], "TEXT");
        }
        if dialect == "postgres" {
            assert_eq!(proxy_row["deployment_future_flag"]["value"], true);
            assert_eq!(
                proxy_row["deployment_future_null_flag"]["value"],
                Value::Null
            );
            assert_eq!(
                proxy_row["deployment_future_small"]["column_type"],
                "SMALLINT"
            );
            assert_eq!(proxy_row["deployment_future_real"]["value_type"], "REAL");
            assert_eq!(
                proxy_row["deployment_future_real"]["value"]["bits"],
                1.25f32.to_bits()
            );
            assert_eq!(
                proxy_row["deployment_future_null_integer"]["column_type"],
                "BIGINT"
            );
            assert_eq!(
                proxy_row["deployment_future_null_bytes"]["column_type"],
                "BLOB"
            );
        }
        assert_plugin_only_replacement_preserves_proxy(
            db.as_ref(),
            &base,
            &namespace,
            spec_id,
            &mut document,
            hand_added,
        )
        .await;
    }
    let original = get_ns(&base, "/deployment-snapshot", &namespace).await;
    assert_eq!(original.status, 200, "{}", original.body);
    sqlx::query(&format!(
        "UPDATE proxy_plugins SET deployment_future_metadata = 'operator' \
         WHERE namespace = {placeholder}"
    ))
    .bind(&namespace)
    .execute(&pool)
    .await
    .unwrap();
    let replace_path = format!("/api-specs/{spec_id}?conditional=true");
    for (method, path, body) in [
        (
            Method::DELETE,
            "/proxies/sql?conditional=true&cleanup_orphaned_upstream=false",
            None,
        ),
        (Method::PUT, replace_path.as_str(), Some(&document)),
    ] {
        let stale = send_ns(
            method,
            &base,
            path,
            &admin_token(),
            original.etag.as_deref(),
            body,
            &namespace,
        )
        .await;
        assert_eq!(stale.status, 412, "{}", stale.body);
    }
    let exact = get_ns(&base, "/deployment-snapshot", &namespace).await;
    document["x-ferrum-proxy"]["backend_host"] = json!("replacement.example.com");
    let replaced = send_ns(
        Method::PUT,
        &base,
        &replace_path,
        &admin_token(),
        exact.etag.as_deref(),
        Some(&document),
        &namespace,
    )
    .await;
    assert_eq!(replaced.status, 200, "{}", replaced.body);
    for (table, identity_columns, expected, expected_count, expected_ids) in [
        (
            "proxies",
            "id AS fixture_id",
            " opaque-original ",
            1,
            &["sql"][..],
        ),
        (
            "plugin_configs",
            "id AS fixture_id",
            " opaque-original ",
            2,
            &["hand-added", "sql-generated"][..],
        ),
        (
            "proxy_plugins",
            "proxy_id, plugin_config_id AS fixture_id",
            "operator",
            2,
            &["hand-added", "sql-generated"][..],
        ),
    ] {
        let rows = sqlx::query(&format!(
            "SELECT {identity_columns}, deployment_future_metadata FROM {table} \
             WHERE namespace = {placeholder}"
        ))
        .bind(&namespace)
        .fetch_all(&pool)
        .await
        .unwrap();
        let row_count = rows.len();
        assert_eq!(row_count, expected_count, "{table} row count");
        let expected_bytes = expected.as_bytes();
        let mut identities = Vec::new();
        for row in rows {
            let fixture_id: String = row.try_get("fixture_id").unwrap();
            identities.push(fixture_id);
            if table == "proxy_plugins" {
                let proxy_id: String = row.try_get("proxy_id").unwrap();
                assert_eq!(proxy_id, "sql");
            }
            let value = row.try_get_raw("deployment_future_metadata").unwrap();
            assert!(!value.is_null(), "{table} metadata unexpectedly NULL");
            let bytes = match value.type_info().kind() {
                AnyTypeInfoKind::Text => row
                    .try_get::<String, _>("deployment_future_metadata")
                    .unwrap()
                    .into_bytes(),
                AnyTypeInfoKind::Blob => row
                    .try_get::<Vec<u8>, _>("deployment_future_metadata")
                    .unwrap(),
                kind => panic!("{table} metadata has unexpected Any kind {kind:?}"),
            };
            assert_eq!(bytes, expected_bytes, "{table} metadata bytes");
        }
        identities.sort();
        let expected_ids: Vec<String> = expected_ids.iter().map(|id| (*id).to_string()).collect();
        assert_eq!(identities, expected_ids, "{table} row identities");
    }
}
