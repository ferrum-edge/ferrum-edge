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
use ferrum_edge::config::db_backend::DatabaseBackend;
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

async fn make_store(dir: &TempDir) -> Arc<dyn DatabaseBackend> {
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
    Arc::new(store)
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
    send_ns(
        method,
        base,
        path,
        token,
        if_match,
        body,
        "ferrum",
    )
    .await
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
        complete.body["credentials"]["jwt"].as_array().unwrap().len(),
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
    // Model an older stored row that current HTTP admission would reject.
    db.create_consumer(&consumer).await.unwrap();
    let (base, _shutdown) = start_admin(admin_state(db, JWT_SECRET)).await;
    let complete = get(&base, "/consumers/historical/verification").await;
    assert_eq!(complete.status, 200, "{}", complete.body);
    assert_eq!(complete.body, serde_json::to_value(&consumer).unwrap());
    let backup = get(&base, "/backup?conditional=true").await;
    assert_eq!(backup.status, 200, "{}", backup.body);
    assert_eq!(backup.body["consumers"][0], complete.body);
    assert_eq!(
        backup.body["conditional"]["row_etags"]["consumers"]["historical"],
        complete.etag.unwrap()
    );
    let archival = get(&base, "/backup").await;
    assert_eq!(archival.status, 200, "{}", archival.body);
    assert!(archival.body["consumers"][0]["credentials"]["jwt"][0]["algorithm"].is_null());
    assert!(archival.body["consumers"][0]["credentials"]["hmac_auth"].is_array());
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
    assert!(get(&base, "/backup").await.body.get("conditional").is_none());
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
    assert_eq!(statuses, [200, 412], "first: {}; second: {}", a.body, b.body);
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
    assert_eq!(deleted.status, 200);
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
        get_ns(&base, "/backup?conditional=true", &namespace).await.etag,
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
        get_ns(&base, "/proxies/shared-proxy", &namespace).await.status,
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
        get_ns(&base, "/backup?conditional=true", &namespace).await.etag,
        current.etag
    );
}

#[tokio::test]
async fn standalone_mongo_refuses_conditional_snapshots_and_restore_without_io() {
    use ferrum_edge::config::db_backend::{
        AtomicBatchGraph, BatchConfigWriteMode, ConditionalNamespaceRestore,
        NamespaceConfigAdmissionLeaseRef, atomic_batch_unsupported,
    };

    let store = ferrum_edge::_test_support::mongo_store_new_unconnected_for_test(vec![]).unwrap();
    let error = match store.load_conditional_namespace_snapshot("ferrum").await {
        Ok(_) => panic!("standalone snapshot must be refused"),
        Err(error) => error,
    };
    assert!(atomic_batch_unsupported(&error).is_some());
    let expected = json!({});
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
        expected: &expected,
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
    let spec_id = opened.body["api_specs"]["items"][0]["id"]
        .as_str()
        .unwrap();
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
    let expected = db
        .load_conditional_namespace_snapshot(&namespace)
        .await
        .unwrap()
        .representation()
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
        expected: &expected,
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
        .representation()
        .unwrap();
    // A matching state with a released admission lease cannot commit either.
    assert!(
        db.release_namespace_config_admission_lease(&namespace, &owner)
            .await
            .unwrap()
    );
    restore.expected = &current;
    let error = db
        .restore_namespace_conditionally(&restore, &BatchConfigWriteMode::Admission)
        .await
        .unwrap_err();
    assert!(is_batch_admission_lease_lost(&error), "{error}");
    assert_eq!(
        db.load_conditional_namespace_snapshot(&namespace)
            .await
            .unwrap()
            .representation()
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
        .representation()
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
    restore.expected = &empty;
    db.restore_namespace_conditionally(&restore, &BatchConfigWriteMode::Admission)
        .await
        .unwrap();
    assert_eq!(
        db.load_conditional_namespace_snapshot(&namespace)
            .await
            .unwrap()
            .representation()
            .unwrap(),
        empty
    );
    assert!(
        db.release_namespace_config_admission_lease(&namespace, &owner)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn sqlite_conditional_restore_checks_state_and_lease_inside_the_transaction() {
    let dir = TempDir::new().unwrap();
    let db = make_store(&dir).await;
    assert_transaction_precondition(db.as_ref()).await;
}

#[tokio::test]
#[ignore = "Requires a MongoDB replica set supplied by MONGO_URL"]
async fn mongo_replica_set_conditional_restore_checks_state_and_lease_in_transaction() {
    let url = std::env::var("MONGO_URL").expect("MONGO_URL with replicaSet is required");
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
}

#[tokio::test]
#[ignore = "Requires PostgreSQL supplied by POSTGRES_URL"]
async fn postgres_conditional_restore_checks_state_and_lease_in_transaction() {
    let url = std::env::var("POSTGRES_URL").expect("POSTGRES_URL is required");
    let db = DatabaseStore::connect_with_pool_config(
        "postgres",
        &url,
        DbPoolConfig::default(),
    )
    .await
    .unwrap();
    assert_transaction_precondition(&db).await;
}

#[tokio::test]
#[ignore = "Requires MySQL supplied by MYSQL_URL"]
async fn mysql_conditional_restore_checks_state_and_lease_in_transaction() {
    let url = std::env::var("MYSQL_URL").expect("MYSQL_URL is required");
    let db = DatabaseStore::connect_with_pool_config(
        "mysql",
        &url,
        DbPoolConfig::default(),
    )
    .await
    .unwrap();
    assert_transaction_precondition(&db).await;
}
