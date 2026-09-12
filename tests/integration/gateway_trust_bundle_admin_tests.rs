//! Admin-surface coverage for the namespace-keyed gateway trust-bundle
//! resource (issue #3727).
//!
//! What is proved here is what only the real HTTP path can prove:
//!
//! - the stored namespace and the default id come from the authenticated
//!   `X-Ferrum-Namespace` header, never from the request body;
//! - `updated_by` is the verified JWT subject, never a body value;
//! - a backup carries the trust section and a restore of it round-trips the
//!   material, with `revision` staying server-assigned;
//! - a PRESENT-but-empty section is an explicit revocation;
//! - a section with more than one record for the target namespace is refused
//!   BEFORE the destructive clear, so a bad payload cannot leave a partially
//!   mutated trust generation behind.

use crate::scaffolding::port_registry::TestSocket;

use arc_swap::ArcSwap;
use base64::Engine;
use chrono::Utc;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::gateway_trust::{
    GatewayTrustBundleRecord, MAX_AUDIT_ACTOR_CHARS, MAX_X509_AUTHORITIES_PER_BUNDLE,
    record_trust_generation_published, reset_observability_for_tests,
};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;

const JWT_SECRET: &str = "test-secret-key-for-trust-bundles-32chars!!";
const JWT_ISSUER: &str = "test-ferrum-edge";

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: JWT_SECRET.to_string(),
        issuer: JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn admin_token(subject: &str) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": JWT_ISSUER,
        "sub": subject,
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .expect("token encodes")
}

fn test_pool_config() -> DbPoolConfig {
    DbPoolConfig {
        max_connections: 2,
        min_connections: 0,
        acquire_timeout_seconds: 5,
        idle_timeout_seconds: 60,
        max_lifetime_seconds: 300,
        connect_timeout_seconds: 5,
        statement_timeout_seconds: 0,
    }
}

async fn make_store(dir: &TempDir) -> DatabaseStore {
    let db_path = dir
        .path()
        .join(format!("trust-admin-{}.db", uuid::Uuid::new_v4()));
    let url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    DatabaseStore::connect_with_pool_config("sqlite", &url, test_pool_config())
        .await
        .expect("connect sqlite store")
}

fn admin_state(db: DatabaseStore) -> AdminState {
    AdminState {
        db: Some(Arc::new(db)),
        jwt_manager: jwt_manager(),
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
        external_ref_policy: std::sync::Arc::new(
            ferrum_edge::admin::api_specs::ExternalRefProcessPolicy::default(),
        ),
        external_ref_loader: std::sync::Arc::new(
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

fn root_ca_der_base64(common_name: &str) -> String {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("test CA key generates");
    let mut params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("test CA params build");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    let cert = params.self_signed(&key).expect("test CA self-signs");
    base64::engine::general_purpose::STANDARD.encode(cert.der())
}

async fn post_json(base: &str, path: &str, namespace: &str, body: Value) -> (u16, Value) {
    post_json_as(base, path, namespace, "restore-admin", body).await
}

async fn post_json_as(
    base: &str,
    path: &str,
    namespace: &str,
    subject: &str,
    body: Value,
) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(format!("{base}{path}"))
        .bearer_auth(admin_token(subject))
        .header("X-Ferrum-Namespace", namespace)
        .json(&body)
        .send()
        .await
        .expect("POST succeeds");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

async fn get_json(base: &str, path: &str, namespace: &str) -> (u16, Value) {
    let response = reqwest::Client::new()
        .get(format!("{base}{path}"))
        .bearer_auth(admin_token("restore-admin"))
        .header("X-Ferrum-Namespace", namespace)
        .send()
        .await
        .expect("GET succeeds");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

async fn put_json(base: &str, path: &str, namespace: &str, body: Value) -> (u16, Value) {
    let response = reqwest::Client::new()
        .put(format!("{base}{path}"))
        .bearer_auth(admin_token("restore-admin"))
        .header("X-Ferrum-Namespace", namespace)
        .json(&body)
        .send()
        .await
        .expect("PUT succeeds");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

async fn delete_resource(base: &str, path: &str, namespace: &str) -> u16 {
    reqwest::Client::new()
        .delete(format!("{base}{path}"))
        .bearer_auth(admin_token("restore-admin"))
        .header("X-Ferrum-Namespace", namespace)
        .send()
        .await
        .expect("DELETE succeeds")
        .status()
        .as_u16()
}

fn bundle_body(trust_domain: &str, authority: &str) -> Value {
    json!({
        "local": {
            "trust_domain": trust_domain,
            "x509_authorities": [authority],
        }
    })
}

// ── Server-owned namespace and id ───────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_hostile_body_namespace_influences_neither_the_stored_namespace_nor_the_id() {
    let dir = TempDir::new().expect("temp dir");
    let (base, _shutdown) = start_admin(admin_state(make_store(&dir).await)).await;
    let authority = root_ca_der_base64("root");

    // The body claims another tenant and omits `id`. The stored record must be
    // keyed entirely by the authenticated header value.
    let (status, created) = post_json(
        &base,
        "/gateway-trust-bundles",
        "tenant-a",
        json!({
            "namespace": "tenant-b",
            "trust_domain": "a.local",
            "updated_by": "attacker",
            "bundle": bundle_body("a.local", &authority),
        }),
    )
    .await;
    assert_eq!(status, 201, "create must succeed: {created}");
    assert_eq!(created["namespace"], "tenant-a");
    assert_eq!(
        created["id"], "tenant-a",
        "an omitted id must default to the SERVER-selected namespace, not the body's"
    );
    assert_eq!(
        created["updated_by"], "restore-admin",
        "attribution must come from the verified JWT subject"
    );
    assert!(
        created["revision"].as_u64().unwrap_or_default() >= 1,
        "the create body must carry a backend-assigned positive revision, got {}",
        created["revision"]
    );

    // tenant-b must have received nothing at all.
    let (status, listed) = get_json(&base, "/gateway-trust-bundles", "tenant-b").await;
    assert_eq!(status, 200);
    assert_eq!(
        listed["data"].as_array().map(Vec::len).unwrap_or_default(),
        0,
        "the body namespace must not have created a record in another tenant"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_overlong_jwt_subject_is_rejected_on_create_and_restore_without_truncation() {
    let dir = TempDir::new().expect("temp dir");
    let (base, _shutdown) = start_admin(admin_state(make_store(&dir).await)).await;
    let authority = root_ca_der_base64("root");
    let at_cap = "é".repeat(MAX_AUDIT_ACTOR_CHARS);
    let overlong = "é".repeat(MAX_AUDIT_ACTOR_CHARS + 1);
    assert_eq!(at_cap.chars().count(), MAX_AUDIT_ACTOR_CHARS);
    assert_eq!(overlong.chars().count(), MAX_AUDIT_ACTOR_CHARS + 1);
    assert!(
        at_cap.len() > MAX_AUDIT_ACTOR_CHARS,
        "fixture must exceed 255 UTF-8 bytes so a byte cap would reject it"
    );
    let create_body = json!({
        "trust_domain": "cluster.local",
        "bundle": bundle_body("cluster.local", &authority),
    });

    let (status, created) = post_json_as(
        &base,
        "/gateway-trust-bundles",
        "cap-ok",
        &at_cap,
        create_body.clone(),
    )
    .await;
    assert_eq!(
        status, 201,
        "a 255-character subject must be admitted: {created}"
    );
    assert_eq!(
        created["updated_by"].as_str(),
        Some(at_cap.as_str()),
        "attribution at the character cap must be stored in full"
    );

    let (status, body) = post_json_as(
        &base,
        "/gateway-trust-bundles",
        "cap-over",
        &overlong,
        json!({
            "trust_domain": "cluster.local",
            "updated_by": "short-body-actor",
            "bundle": bundle_body("cluster.local", &authority),
        }),
    )
    .await;
    assert_eq!(
        status, 400,
        "an overlong JWT subject must be refused: {body}"
    );
    let rendered = body.to_string();
    assert!(
        rendered.contains("updated_by exceeds"),
        "expected an audit-actor bound error, got {body}"
    );
    assert!(
        !rendered.contains(&overlong) && !rendered.contains('é'),
        "admission diagnostics must not echo or truncate the overlong subject"
    );
    let (status, listed) = get_json(&base, "/gateway-trust-bundles", "cap-over").await;
    assert_eq!(status, 200);
    assert_eq!(
        listed["data"].as_array().map(Vec::len).unwrap_or_default(),
        0,
        "an overlong actor must not persist on any backend"
    );

    let (status, created) = post_json(
        &base,
        "/gateway-trust-bundles",
        "hostile-body",
        json!({
            "trust_domain": "cluster.local",
            "updated_by": overlong,
            "bundle": bundle_body("cluster.local", &authority),
        }),
    )
    .await;
    assert_eq!(
        status, 201,
        "a hostile overlong body updated_by must not be authoritative: {created}"
    );
    assert_eq!(
        created["updated_by"], "restore-admin",
        "attribution must come from the verified JWT subject, not the body"
    );

    let (status, created) = post_json(
        &base,
        "/gateway-trust-bundles",
        "ferrum",
        create_body.clone(),
    )
    .await;
    assert_eq!(status, 201, "create must succeed: {created}");
    let revision = created["revision"].as_u64().expect("numeric revision");
    let (status, backup) = get_json(&base, "/backup", "ferrum").await;
    assert_eq!(status, 200);

    let (status, body) =
        post_json_as(&base, "/restore?confirm=true", "ferrum", &overlong, backup).await;
    assert_eq!(
        status, 400,
        "an overlong restoring subject must be refused: {body}"
    );
    let rendered = body.to_string();
    assert!(
        rendered.contains("updated_by exceeds"),
        "expected an audit-actor bound error on restore, got {body}"
    );
    assert!(
        !rendered.contains(&overlong) && !rendered.contains('é'),
        "restore diagnostics must not echo or truncate the overlong subject"
    );
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("NOT deleted"),
        "the refusal must happen before the destructive clear: {body}"
    );
    let (status, after) = get_json(&base, "/gateway-trust-bundles/ferrum", "ferrum").await;
    assert_eq!(status, 200, "the refused restore must not revoke trust");
    assert_eq!(after["revision"].as_u64(), Some(revision));
    assert_eq!(after["updated_by"], "restore-admin");
}

// ── Authoritative write responses ───────────────────────────────────────────

/// A successful `POST` and `PUT` must report the revision the STORE assigned.
///
/// The generic write path used to serialize the request-side resource after
/// persistence, so a create answered `revision: 0` (the body default) and an
/// update answered the client's *expectation* — neither of which the store had
/// written. An admin client that echoed the response back on its next rotation
/// would then lose the compare-and-set for no reason.
#[tokio::test(flavor = "multi_thread")]
async fn create_and_update_bodies_carry_the_authoritative_stored_revision() {
    let dir = TempDir::new().expect("temp dir");
    let (base, _shutdown) = start_admin(admin_state(make_store(&dir).await)).await;
    let root_a = root_ca_der_base64("root-a");

    let (status, created) = post_json(
        &base,
        "/gateway-trust-bundles",
        "ferrum",
        json!({
            "trust_domain": "cluster.local",
            "bundle": bundle_body("cluster.local", &root_a),
        }),
    )
    .await;
    assert_eq!(status, 201, "create must succeed: {created}");
    let created_revision = created["revision"]
        .as_u64()
        .expect("the create body must carry a numeric revision");
    assert!(
        created_revision >= 1,
        "a create must not answer the request-side default of 0"
    );

    let (status, fetched) = get_json(&base, "/gateway-trust-bundles/ferrum", "ferrum").await;
    assert_eq!(status, 200);
    assert_eq!(
        fetched["revision"].as_u64(),
        Some(created_revision),
        "the 201 body must carry the same revision a following GET observes"
    );

    // Rotate, echoing the revision that was read. The 200 body must carry the
    // NEW revision, not the expectation that was sent.
    let root_b = root_ca_der_base64("root-b");
    let (status, updated) = put_json(
        &base,
        "/gateway-trust-bundles/ferrum",
        "ferrum",
        json!({
            "trust_domain": "cluster.local",
            "revision": created_revision,
            "bundle": bundle_body("cluster.local", &root_b),
        }),
    )
    .await;
    assert_eq!(status, 200, "rotation must succeed: {updated}");
    let updated_revision = updated["revision"]
        .as_u64()
        .expect("the update body must carry a numeric revision");
    assert!(
        updated_revision > created_revision,
        "the 200 body must carry the newly assigned revision, not the expectation"
    );

    let (status, fetched) = get_json(&base, "/gateway-trust-bundles/ferrum", "ferrum").await;
    assert_eq!(status, 200);
    assert_eq!(
        fetched["revision"].as_u64(),
        Some(updated_revision),
        "the 200 body must carry the same revision a following GET observes"
    );

    // The revision the response advertised is immediately usable as the next
    // expectation — the practical consequence of reporting the stored value.
    let root_c = root_ca_der_base64("root-c");
    let (status, again) = put_json(
        &base,
        "/gateway-trust-bundles/ferrum",
        "ferrum",
        json!({
            "trust_domain": "cluster.local",
            "revision": updated_revision,
            "bundle": bundle_body("cluster.local", &root_c),
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "the advertised revision must be a valid expectation: {again}"
    );
}

/// End-to-end ABA refusal on the real admin surface: a client reads the record,
/// another actor revokes and recreates it, and the client's later `PUT` with the
/// revision it read must be a `409` that leaves the replacement intact.
#[tokio::test(flavor = "multi_thread")]
async fn a_stale_pre_delete_revision_is_refused_over_the_admin_api() {
    let dir = TempDir::new().expect("temp dir");
    let (base, _shutdown) = start_admin(admin_state(make_store(&dir).await)).await;
    let original = root_ca_der_base64("original-root");

    let (status, created) = post_json(
        &base,
        "/gateway-trust-bundles",
        "ferrum",
        json!({
            "trust_domain": "cluster.local",
            "bundle": bundle_body("cluster.local", &original),
        }),
    )
    .await;
    assert_eq!(status, 201, "create must succeed: {created}");
    let stale_revision = created["revision"].as_u64().expect("numeric revision");

    assert_eq!(
        delete_resource(&base, "/gateway-trust-bundles/ferrum", "ferrum").await,
        204
    );

    let replacement = root_ca_der_base64("replacement-root");
    let (status, recreated) = post_json(
        &base,
        "/gateway-trust-bundles",
        "ferrum",
        json!({
            "trust_domain": "cluster.local",
            "bundle": bundle_body("cluster.local", &replacement),
        }),
    )
    .await;
    assert_eq!(status, 201, "recreate must succeed: {recreated}");
    let replacement_revision = recreated["revision"].as_u64().expect("numeric revision");
    assert!(
        replacement_revision > stale_revision,
        "a recreated singleton must not reuse the deleted incarnation's revision"
    );

    let attacker = root_ca_der_base64("attacker-root");
    let (status, conflict) = put_json(
        &base,
        "/gateway-trust-bundles/ferrum",
        "ferrum",
        json!({
            "trust_domain": "cluster.local",
            "revision": stale_revision,
            "bundle": bundle_body("cluster.local", &attacker),
        }),
    )
    .await;
    assert_eq!(
        status, 409,
        "a stale pre-delete expectation must not commit: {conflict}"
    );
    assert_eq!(conflict["expected_revision"].as_u64(), Some(stale_revision));
    assert_eq!(
        conflict["current_revision"].as_u64(),
        Some(replacement_revision)
    );

    let (status, stored) = get_json(&base, "/gateway-trust-bundles/ferrum", "ferrum").await;
    assert_eq!(status, 200);
    assert_eq!(
        stored["bundle"]["local"]["x509_authorities"][0], replacement,
        "the recreated incarnation's roots must survive the stale write"
    );
    assert_eq!(stored["revision"].as_u64(), Some(replacement_revision));
}

// ── Backup / restore round trip ─────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_backup_round_trips_the_trust_resource_with_server_assigned_revisions() {
    reset_observability_for_tests();
    let dir = TempDir::new().expect("temp dir");
    let (base, _shutdown) = start_admin(admin_state(make_store(&dir).await)).await;
    let authority = root_ca_der_base64("root");

    let (status, _) = post_json(
        &base,
        "/gateway-trust-bundles",
        "ferrum",
        json!({
            "trust_domain": "cluster.local",
            "bundle": bundle_body("cluster.local", &authority),
        }),
    )
    .await;
    assert_eq!(status, 201);

    let (status, backup) = get_json(&base, "/backup", "ferrum").await;
    assert_eq!(status, 200);
    let section = backup["gateway_trust_bundles"]
        .as_array()
        .expect("a database-backed backup carries the trust section");
    assert_eq!(section.len(), 1);
    assert_eq!(section[0]["trust_domain"], "cluster.local");
    assert_eq!(backup["counts"]["gateway_trust_bundles"], 1);

    // Restore the backup verbatim.
    let (status, restored) = post_json(&base, "/restore?confirm=true", "ferrum", backup).await;
    assert_eq!(status, 200, "restore must succeed: {restored}");
    assert_eq!(restored["restored"]["gateway_trust_bundles"], 1);

    let (status, after) = get_json(&base, "/gateway-trust-bundles/ferrum", "ferrum").await;
    assert_eq!(status, 200);
    assert_eq!(after["trust_domain"], "cluster.local");
    assert_eq!(
        after["bundle"]["local"]["x509_authorities"][0], authority,
        "the restored material must be byte-identical"
    );
    assert!(
        after["revision"].as_u64().unwrap_or_default() >= 2,
        "revision is server-assigned and monotonic across a restore, got {}",
        after["revision"]
    );

    // A committed row is still only a candidate. This admin-only fixture has no
    // polling/publication loop, so status must not claim the restored revision
    // is live merely because it can read it from the database.
    let (status, view) = get_json(&base, "/gateway-trust/status", "ferrum").await;
    assert_eq!(status, 200);
    assert_eq!(view["configured"], false);
    assert!(view["bundle"].is_null());

    // Record the same seam the CP poller reaches after validation + ArcSwap.
    // Only then may status expose this revision as the live generation.
    let published: GatewayTrustBundleRecord =
        serde_json::from_value(after.clone()).expect("stored record decodes");
    record_trust_generation_published(
        std::slice::from_ref(&published),
        None,
        Utc::now().timestamp().max(0) as u64,
    );
    let (status, view) = get_json(&base, "/gateway-trust/status", "ferrum").await;
    assert_eq!(status, 200);
    assert_eq!(view["configured"], true);
    assert_eq!(view["bundle"]["revision"], after["revision"]);
    let generation = view["generation"].as_str().expect("a generation identity");
    assert!(!generation.is_empty());
    assert!(
        !generation.contains(&authority[..16]),
        "the generation identity is a digest and must not carry material"
    );
    assert!(view["process"]["published_revision"].is_null());
    reset_observability_for_tests();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resource_filtered_backup_does_not_export_or_import_trust() {
    let dir = TempDir::new().expect("temp dir");
    let (base, _shutdown) = start_admin(admin_state(make_store(&dir).await)).await;
    let authority = root_ca_der_base64("root");

    let (status, created) = post_json(
        &base,
        "/gateway-trust-bundles",
        "ferrum",
        json!({
            "trust_domain": "cluster.local",
            "bundle": bundle_body("cluster.local", &authority),
        }),
    )
    .await;
    assert_eq!(status, 201, "create must succeed: {created}");
    let revision = created["revision"].as_u64().expect("numeric revision");

    // `gateway_trust_bundles` is deliberately not a resource-filter token.
    // A proxy-only artifact is commonly replayed through POST /batch and must
    // not carry a hidden security-state mutation outside the caller's scope.
    let (status, partial) = get_json(&base, "/backup?resources=proxies", "ferrum").await;
    assert_eq!(status, 200, "filtered backup must succeed: {partial}");
    assert!(
        partial.get("gateway_trust_bundles").is_none(),
        "a resource-filtered backup must omit trust rather than silently widening its scope"
    );
    assert_eq!(partial["counts"]["gateway_trust_bundles"], 0);

    let (status, imported) = post_json(&base, "/batch", "ferrum", partial).await;
    assert_eq!(
        status, 201,
        "the partial artifact must remain batch-compatible: {imported}"
    );

    let (status, after) = get_json(&base, "/gateway-trust-bundles/ferrum", "ferrum").await;
    assert_eq!(status, 200);
    assert_eq!(after["revision"].as_u64(), Some(revision));
    assert_eq!(after["bundle"]["local"]["x509_authorities"][0], authority);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_present_but_empty_section_revokes_and_an_absent_one_does_not() {
    let dir = TempDir::new().expect("temp dir");
    let (base, _shutdown) = start_admin(admin_state(make_store(&dir).await)).await;
    let authority = root_ca_der_base64("root");

    let (status, _) = post_json(
        &base,
        "/gateway-trust-bundles",
        "ferrum",
        json!({
            "trust_domain": "cluster.local",
            "bundle": bundle_body("cluster.local", &authority),
        }),
    )
    .await;
    assert_eq!(status, 201);

    let (status, backup) = get_json(&base, "/backup", "ferrum").await;
    assert_eq!(status, 200);

    // An ABSENT section says nothing about trust: restoring a backup taken
    // before the resource existed must not revoke a namespace's roots.
    let mut legacy = backup.clone();
    legacy
        .as_object_mut()
        .expect("backup is an object")
        .remove("gateway_trust_bundles");
    let (status, body) = post_json(&base, "/restore?confirm=true", "ferrum", legacy).await;
    assert_eq!(status, 200, "legacy restore must succeed: {body}");
    let (status, _) = get_json(&base, "/gateway-trust-bundles/ferrum", "ferrum").await;
    assert_eq!(
        status, 200,
        "an absent trust section must leave the record in place"
    );

    // A PRESENT-but-empty section is an explicit revocation.
    let mut revoking = backup.clone();
    revoking["gateway_trust_bundles"] = json!([]);
    let (status, body) = post_json(&base, "/restore?confirm=true", "ferrum", revoking).await;
    assert_eq!(status, 200, "revoking restore must succeed: {body}");
    assert_eq!(body["restored"]["gateway_trust_bundles"], 0);
    let (status, _) = get_json(&base, "/gateway-trust-bundles/ferrum", "ferrum").await;
    assert_eq!(
        status, 404,
        "a present-but-empty section must revoke the namespace's record"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn more_than_one_record_is_refused_before_anything_is_deleted() {
    let dir = TempDir::new().expect("temp dir");
    let (base, _shutdown) = start_admin(admin_state(make_store(&dir).await)).await;
    let authority = root_ca_der_base64("root");

    let (status, _) = post_json(
        &base,
        "/gateway-trust-bundles",
        "ferrum",
        json!({
            "trust_domain": "cluster.local",
            "bundle": bundle_body("cluster.local", &authority),
        }),
    )
    .await;
    assert_eq!(status, 201);

    let (status, backup) = get_json(&base, "/backup", "ferrum").await;
    assert_eq!(status, 200);

    // Two records for one namespace: the reconciler must not silently take the
    // first, because which one wins would then depend on payload order.
    let mut hostile = backup.clone();
    let mut second = backup["gateway_trust_bundles"][0].clone();
    second["id"] = json!("second");
    second["namespace"] = json!("tenant-b");
    hostile["gateway_trust_bundles"] = json!([backup["gateway_trust_bundles"][0], second]);

    let (status, body) = post_json(&base, "/restore?confirm=true", "ferrum", hostile).await;
    assert_eq!(
        status, 400,
        "a non-singleton section must be refused: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("NOT deleted"),
        "the refusal must happen before the destructive clear: {body}"
    );

    // Nothing was mutated: the original generation is intact.
    let (status, after) = get_json(&base, "/gateway-trust-bundles/ferrum", "ferrum").await;
    assert_eq!(status, 200, "the refused restore must not revoke trust");
    assert_eq!(
        after["revision"], 1,
        "and must not bump the revision either"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn over_count_trust_material_is_refused_before_deep_parser_diagnostics() {
    let dir = TempDir::new().expect("temp dir");
    let (base, _shutdown) = start_admin(admin_state(make_store(&dir).await)).await;
    let authorities = vec!["not-a-certificate"; MAX_X509_AUTHORITIES_PER_BUNDLE + 1];

    let (status, body) = post_json(
        &base,
        "/gateway-trust-bundles",
        "ferrum",
        json!({
            "trust_domain": "cluster.local",
            "bundle": {
                "local": {
                    "trust_domain": "cluster.local",
                    "x509_authorities": authorities,
                }
            },
        }),
    )
    .await;
    assert_eq!(status, 400, "over-count material must be refused: {body}");
    let error = body["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("x509 authorities"),
        "expected an authority-count error, got {body}"
    );
    assert!(
        !error.contains("parseable X.509")
            && !error.contains("invalid base64")
            && !error.contains("TrustBundleSet."),
        "over-count admission must not invoke deep parsers: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn restore_refuses_over_count_trust_before_clear_and_without_deep_parser_diagnostics() {
    let dir = TempDir::new().expect("temp dir");
    let (base, _shutdown) = start_admin(admin_state(make_store(&dir).await)).await;
    let authority = root_ca_der_base64("root");

    let (status, created) = post_json(
        &base,
        "/gateway-trust-bundles",
        "ferrum",
        json!({
            "trust_domain": "cluster.local",
            "bundle": bundle_body("cluster.local", &authority),
        }),
    )
    .await;
    assert_eq!(status, 201, "create must succeed: {created}");
    let revision = created["revision"].as_u64().expect("numeric revision");

    let (status, mut backup) = get_json(&base, "/backup", "ferrum").await;
    assert_eq!(status, 200);
    let hostile = vec!["not-a-certificate"; MAX_X509_AUTHORITIES_PER_BUNDLE + 1];
    backup["gateway_trust_bundles"][0]["bundle"]["local"]["x509_authorities"] = json!(hostile);

    let (status, body) = post_json(&base, "/restore?confirm=true", "ferrum", backup).await;
    assert_eq!(
        status, 400,
        "over-count restore material must be refused: {body}"
    );
    let rendered = body.to_string();
    assert!(
        rendered.contains("x509 authorities"),
        "expected an authority-count error, got {body}"
    );
    assert!(
        !rendered.contains("parseable X.509")
            && !rendered.contains("invalid base64")
            && !rendered.contains("TrustBundleSet."),
        "over-count restore must not invoke deep parsers: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("NOT deleted"),
        "the refusal must happen before the destructive clear: {body}"
    );

    let (status, after) = get_json(&base, "/gateway-trust-bundles/ferrum", "ferrum").await;
    assert_eq!(status, 200, "the refused restore must not revoke trust");
    assert_eq!(after["revision"].as_u64(), Some(revision));
    assert_eq!(after["bundle"]["local"]["x509_authorities"][0], authority);
}

// ── Backup audit evidence ───────────────────────────────────────────────────

/// Newest successful `GET /backup` security audit record for `namespace`.
async fn latest_backup_audit_event(base: &str, namespace: &str) -> Value {
    let (status, body) = get_json(base, "/audit?action=backup&limit=20", namespace).await;
    assert_eq!(status, 200, "audit list must succeed: {body}");
    let listed = body["items"].clone();
    let items = listed.as_array().expect("audit items array");
    for item in items {
        if item["action"] == "backup" && item["outcome"] == "success" {
            return item.clone();
        }
    }
    panic!("no successful backup audit event was recorded: {body}");
}

/// A full database export releases unredacted trust roots, so the success
/// audit record must show that they left the gateway — as a count only.
#[tokio::test(flavor = "multi_thread")]
async fn a_full_export_audits_the_released_trust_count_without_material() {
    let dir = TempDir::new().expect("temp dir");
    let (base, _shutdown) = start_admin(admin_state(make_store(&dir).await)).await;
    let authority = root_ca_der_base64("root");

    let (status, created) = post_json(
        &base,
        "/gateway-trust-bundles",
        "ferrum",
        json!({
            "trust_domain": "cluster.local",
            "bundle": bundle_body("cluster.local", &authority),
        }),
    )
    .await;
    assert_eq!(status, 201, "create must succeed: {created}");

    let (status, backup) = get_json(&base, "/backup", "ferrum").await;
    assert_eq!(status, 200);
    assert_eq!(backup["counts"]["gateway_trust_bundles"], 1);

    let event = latest_backup_audit_event(&base, "ferrum").await;
    assert_eq!(event["diff"]["data_source"], "database");
    let audited = event["diff"]["counts"]["gateway_trust_bundles"].clone();
    assert_eq!(audited, backup["counts"]["gateway_trust_bundles"]);
    assert_eq!(
        audited, 1,
        "the audit must record the exported rows: {event}"
    );

    // Count only: no certificate bytes, PEM, subjects, or revisions.
    let rendered = serde_json::to_string(&event).expect("event serializes");
    assert!(
        !rendered.contains(&authority[..24]),
        "trust material leaked into the backup audit record: {rendered}"
    );
    assert!(
        !rendered.contains("x509_authorities") && !rendered.contains("cluster.local"),
        "the audit record must not describe trust beyond a count: {rendered}"
    );
}

/// An export that omits the trust section must audit `0` even while the
/// namespace still holds a trust row: the count describes the payload that was
/// released, never what the namespace happens to store.
#[tokio::test(flavor = "multi_thread")]
async fn an_omitted_trust_section_audits_zero_while_the_row_survives() {
    let dir = TempDir::new().expect("temp dir");
    let (base, _shutdown) = start_admin(admin_state(make_store(&dir).await)).await;
    let authority = root_ca_der_base64("root");

    let (status, created) = post_json(
        &base,
        "/gateway-trust-bundles",
        "ferrum",
        json!({
            "trust_domain": "cluster.local",
            "bundle": bundle_body("cluster.local", &authority),
        }),
    )
    .await;
    assert_eq!(status, 201, "create must succeed: {created}");

    let (status, partial) = get_json(&base, "/backup?resources=proxies", "ferrum").await;
    assert_eq!(status, 200, "filtered backup must succeed: {partial}");
    assert!(partial.get("gateway_trust_bundles").is_none());
    assert_eq!(partial["counts"]["gateway_trust_bundles"], 0);

    let event = latest_backup_audit_event(&base, "ferrum").await;
    assert_eq!(event["diff"]["resources"], json!(["proxies"]));
    let audited = event["diff"]["counts"]["gateway_trust_bundles"].clone();
    assert_eq!(audited, 0, "an omitted section must audit zero: {event}");

    // The stored row is untouched; the `0` describes the export only.
    let (status, after) = get_json(&base, "/gateway-trust-bundles/ferrum", "ferrum").await;
    assert_eq!(status, 200);
    assert_eq!(after["bundle"]["local"]["x509_authorities"][0], authority);
}
