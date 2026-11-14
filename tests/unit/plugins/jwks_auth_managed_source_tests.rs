//! `jwks_auth` / `oidc_relying_party` managed JWKS sources (issue #7277):
//! `providers[].jwks_source: managed://jwks/<id>#jwks`.
//!
//! Covers the reference grammar and its static validation, the mapping of a
//! managed record onto the fresh/grace/expired trust model, and end-to-end
//! verification, rotation, and withdrawal through the process managed TLS
//! store and the shared JWKS cache.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ferrum_edge::ConsumerIndex;
use ferrum_edge::plugins::utils::jwks_cache::{cached_store, refresh_managed_jwks_stores};
use ferrum_edge::plugins::utils::jwks_store::{
    JwksFailureClass, JwksKeyStore, JwksTrustState, canonical_managed_jwks_source,
    check_managed_jwks_source, validate_jwks_document,
};
use ferrum_edge::plugins::{Plugin, PluginResult, jwks_auth::JwksAuth, validate_plugin_config};
use ferrum_edge::tls::managed::{ManagedTlsRecord, ManagedTlsStore};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};

use super::jwks_auth_support::{cache_test_lock, default_client, make_ctx};
use super::plugin_utils::{assert_continue, assert_reject};

const ISSUER: &str = "https://managed-idp.example.com";

/// One P-256 signing key: its public JWK and the matching encoder.
struct SigningKey {
    kid: String,
    jwk: Value,
    encoding: EncodingKey,
}

fn signing_key(kid: &str) -> SigningKey {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("P-256 key");
    let point = key_pair.public_key_raw();
    assert_eq!(point.len(), 65, "uncompressed P-256 point");
    SigningKey {
        kid: kid.to_string(),
        jwk: json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "use": "sig",
            "kid": kid,
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&point[33..]),
        }),
        encoding: EncodingKey::from_ec_pem(key_pair.serialize_pem().as_bytes())
            .expect("EC encoding key"),
    }
}

fn jwks_document(keys: &[&SigningKey]) -> String {
    let keys: Vec<Value> = keys.iter().map(|key| key.jwk.clone()).collect();
    json!({ "keys": keys }).to_string()
}

fn token(key: &SigningKey, subject: &str) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key.kid.clone());
    let claims = json!({
        "iss": ISSUER,
        "sub": subject,
        "exp": chrono::Utc::now().timestamp() + 3600,
    });
    encode(&header, &claims, &key.encoding).expect("sign token")
}

fn unique_id(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
}

fn managed_config(source: &str) -> Value {
    json!({
        "providers": [{
            "issuer": ISSUER,
            "jwks_source": source
        }]
    })
}

async fn authenticate(plugin: &JwksAuth, bearer: &str) -> PluginResult {
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {bearer}"));
    plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await
}

fn tempdir_store() -> (tempfile::TempDir, Arc<ManagedTlsStore>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = ManagedTlsStore::open_with_limits(dir.path(), 1024 * 1024, 64, None)
        .expect("open managed store");
    (dir, Arc::new(store))
}

fn upsert_jwks(store: &ManagedTlsStore, id: &str, document: String) {
    store
        .upsert(
            ManagedTlsRecord::new_jwks(id.to_string(), id.to_string(), None, document),
            true,
        )
        .expect("upsert managed JWKS");
}

// ─── Reference grammar ──────────────────────────────────────────────────

#[test]
fn every_managed_jwks_spelling_canonicalizes_to_one_source() {
    for spelling in [
        "managed://jwks/idp-a#jwks",
        "managed://jwks/idp-a",
        "managed://idp-a#jwks",
        "managed://jwks/idp-a#jwks-json",
        "managed://jwks/idp-a#jwks_json",
    ] {
        assert_eq!(
            canonical_managed_jwks_source(spelling).as_deref(),
            Ok("managed://jwks/idp-a#jwks"),
            "{spelling} must canonicalize"
        );
        let plugin = JwksAuth::new(&managed_config(spelling), default_client())
            .unwrap_or_else(|error| panic!("{spelling} must be admitted: {error}"));
        assert_eq!(
            plugin.active_jwks_uris(),
            vec!["managed://jwks/idp-a#jwks".to_string()],
            "two spellings of one record must share one key store"
        );
        assert!(
            plugin.warmup_hostnames().is_empty(),
            "a managed source is read locally and is never a DNS warmup host"
        );
    }
}

#[test]
fn non_managed_and_non_jwks_references_are_refused_at_config_load() {
    let cases: &[(Value, &str)] = &[
        (
            json!("vault://secret/data/idp#jwks"),
            "scheme is not supported",
        ),
        (json!("k8s://ns/idp#jwks.json"), "scheme is not supported"),
        (
            json!("/etc/ferrum/jwks.json"),
            "file paths and inline material",
        ),
        (
            json!("managed://certificates/idp-a#cert"),
            "not a usable JWKS reference",
        ),
        (
            json!("managed://jwks/idp-a#ca"),
            "not a usable JWKS reference",
        ),
        (
            json!("managed://certificates/idp-a#jwks"),
            "not a usable JWKS reference",
        ),
        (
            json!("managed://jwks/idp-a#bogus"),
            "not a usable JWKS reference",
        ),
        (
            json!("managed://jwks/idp-a#jwks?poll=5s"),
            "takes no `?` options",
        ),
        (
            json!("managed://jwks/idp-a?kind=jwks"),
            "takes no `?` options",
        ),
        (json!(""), "must not be empty"),
        (json!(" managed://jwks/idp-a#jwks"), "whitespace"),
        (json!(42), "must be a `managed://jwks/<id>#jwks` string"),
    ];
    for (value, expected) in cases {
        let error = JwksAuth::new(&managed_config_value(value.clone()), default_client())
            .err()
            .unwrap_or_else(|| panic!("{value} must be refused"));
        assert!(
            error.contains("`provider[0].jwks_source`") && error.contains(expected),
            "{value}: expected {expected:?} in {error:?}"
        );
        assert!(
            validate_plugin_config("jwks_auth", &managed_config_value(value.clone())).is_err(),
            "admission must refuse {value}"
        );
    }
}

fn managed_config_value(source: Value) -> Value {
    json!({ "providers": [{ "issuer": ISSUER, "jwks_source": source }] })
}

#[test]
fn jwks_source_is_one_of_the_mutually_exclusive_key_sources() {
    for (field, value) in [
        ("jwks_uri", json!("https://idp.example.com/jwks.json")),
        (
            "discovery_url",
            json!("https://idp.example.com/.well-known/openid-configuration"),
        ),
        ("jwks", json!({"keys": []})),
    ] {
        let mut config = managed_config("managed://jwks/idp-a#jwks");
        config["providers"][0][field] = value;
        let error = JwksAuth::new(&config, default_client())
            .err()
            .unwrap_or_else(|| panic!("jwks_source with {field} must be refused"));
        assert!(
            error.contains("exactly one of") && error.contains("`jwks_source`"),
            "{field}: {error}"
        );
    }

    let error = JwksAuth::new(
        &json!({"providers": [{"issuer": ISSUER}]}),
        default_client(),
    )
    .err()
    .expect("a provider needs a key source");
    assert!(error.contains("`jwks_source`"), "{error}");
}

#[test]
fn managed_providers_follow_the_max_stale_rules_of_refreshable_sources() {
    let mut config = managed_config("managed://jwks/idp-a#jwks");
    // At least the default 900-second refresh interval.
    config["providers"][0]["jwks_max_stale_seconds"] = json!(1800);
    JwksAuth::new(&config, default_client())
        .expect("jwks_max_stale_seconds bounds an unreadable managed store");

    let mut config = managed_config("managed://jwks/idp-a#jwks");
    config["jwks_refresh_interval_secs"] = json!(900);
    config["providers"][0]["jwks_max_stale_seconds"] = json!(60);
    let error = JwksAuth::new(&config, default_client())
        .err()
        .expect("refresh interval above max-stale must be refused");
    assert!(error.contains("jwks_refresh_interval_secs"), "{error}");
}

// ─── Document admission ─────────────────────────────────────────────────

#[test]
fn jwks_documents_are_admitted_only_with_a_usable_signing_key() {
    let key = signing_key("doc-key");
    assert_eq!(
        validate_jwks_document(jwks_document(&[&key]).as_bytes()),
        Ok(1)
    );
    // A usable key beside an unusable one is admitted; the unusable one is
    // skipped exactly as a fetched document's would be.
    let mixed = json!({"keys": [key.jwk, {"kty": "oct", "k": "dGVzdA", "kid": "sym"}]});
    assert_eq!(validate_jwks_document(mixed.to_string().as_bytes()), Ok(1));

    for (document, expected) in [
        (json!({"keys": []}).to_string(), "no usable signing key"),
        (
            json!({"keys": [{"kty": "oct", "k": "dGVzdA", "kid": "sym"}]}).to_string(),
            "no usable signing key",
        ),
        (json!({"not_keys": []}).to_string(), "not valid JWKS JSON"),
        ("not json".to_string(), "not valid JWKS JSON"),
        ("x".repeat(1024 * 1024 + 1), "byte limit"),
    ] {
        let error = validate_jwks_document(document.as_bytes())
            .expect_err("unusable document must be refused");
        assert!(error.contains(expected), "{expected}: {error}");
    }
}

// ─── Trust mapping ──────────────────────────────────────────────────────

#[tokio::test]
async fn managed_record_is_fresh_while_present_and_withdrawn_when_deleted() {
    let (_dir, store) = tempdir_store();
    let id = unique_id("trust");
    let source = format!("managed://jwks/{id}#jwks");
    let keys = JwksKeyStore::new_managed_with_store(source, Arc::clone(&store));
    keys.configure_trust_policy(Duration::from_secs(60), Duration::from_secs(600));
    assert!(keys.is_managed() && keys.is_refreshable());

    // Nothing read yet, and nothing in the store: no trust.
    assert_eq!(keys.health_snapshot().trust_state, JwksTrustState::Expired);
    keys.fetch_keys()
        .await
        .expect_err("a missing record is not a key set");
    let health = keys.health_snapshot();
    assert_eq!(health.trust_state, JwksTrustState::Expired);
    assert_eq!(health.last_failure, Some(JwksFailureClass::Empty));
    assert!(keys.trusted_keys().is_none());

    let first = signing_key("first");
    upsert_jwks(&store, &id, jwks_document(&[&first]));
    assert_eq!(keys.fetch_keys().await, Ok(1));
    assert_eq!(keys.health_snapshot().trust_state, JwksTrustState::Fresh);
    assert!(
        keys.grace_deadline().is_none(),
        "a present managed record never ages into grace on a timer"
    );
    let trusted = keys.trusted_keys().expect("fresh keys are trusted");
    assert!(trusted.contains_key("first"));

    // Rotation replaces the key set wholesale.
    let second = signing_key("second");
    upsert_jwks(&store, &id, jwks_document(&[&second]));
    assert_eq!(keys.fetch_keys().await, Ok(1));
    let trusted = keys.trusted_keys().expect("rotated keys are trusted");
    assert!(trusted.contains_key("second") && !trusted.contains_key("first"));

    // Deletion withdraws every key at once (fail closed, like an expired
    // remote set), with no grace.
    store.delete(&id).expect("delete record");
    keys.fetch_keys()
        .await
        .expect_err("a deleted record withdraws the key set");
    let health = keys.health_snapshot();
    assert_eq!(health.trust_state, JwksTrustState::Expired);
    assert_eq!(health.retained_key_count, 0);
    assert!(keys.trusted_keys().is_none());

    // A record of another kind under the same id is not a key set either.
    store
        .upsert(
            ManagedTlsRecord::new_ca_bundle(id.clone(), id.clone(), None, "ca".to_string()),
            false,
        )
        .expect("ca bundle under the same id");
    keys.fetch_keys()
        .await
        .expect_err("a wrong-kind record withdraws the key set");
    assert!(keys.trusted_keys().is_none());
    store.delete(&id).expect("delete ca bundle");

    // Restoring the record restores trust.
    upsert_jwks(&store, &id, jwks_document(&[&second]));
    assert_eq!(keys.fetch_keys().await, Ok(1));
    assert_eq!(keys.health_snapshot().trust_state, JwksTrustState::Fresh);
}

#[tokio::test]
async fn keyless_record_withdraws_the_key_set() {
    let (_dir, store) = tempdir_store();
    let id = unique_id("keyless");
    let keys = JwksKeyStore::new_managed_with_store(
        format!("managed://jwks/{id}#jwks"),
        Arc::clone(&store),
    );
    let key = signing_key("only");
    upsert_jwks(&store, &id, jwks_document(&[&key]));
    keys.fetch_keys().await.expect("usable record");

    // Written out of band (admission would refuse it): a record whose only
    // key is unusable is an authoritative "no key set".
    upsert_jwks(
        &store,
        &id,
        json!({"keys": [{"kty": "oct", "k": "dGVzdA", "kid": "sym"}]}).to_string(),
    );
    keys.fetch_keys().await.expect_err("keyless record");
    assert_eq!(
        keys.health_snapshot().last_failure,
        Some(JwksFailureClass::UnusableKeys)
    );
    assert!(keys.trusted_keys().is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn unreadable_store_keeps_last_keys_in_grace_until_max_stale() {
    let (dir, store) = tempdir_store();
    let id = unique_id("unreadable");
    let keys = JwksKeyStore::new_managed_with_store(
        format!("managed://jwks/{id}#jwks"),
        Arc::clone(&store),
    );
    keys.configure_trust_policy(Duration::from_millis(100), Duration::from_secs(2));
    let key = signing_key("kept");
    upsert_jwks(&store, &id, jwks_document(&[&key]));
    keys.fetch_keys().await.expect("usable record");

    // Replace the shared document with one that cannot be parsed (a new
    // inode, as a torn or foreign write on a shared volume would leave). The
    // record's presence is now unknown, not refuted.
    let document = dir.path().join("managed-tls.json");
    let replacement = dir.path().join("managed-tls.json.replacement");
    std::fs::write(&replacement, b"{ not json").expect("write replacement");
    std::fs::rename(&replacement, &document).expect("replace document");

    keys.fetch_keys().await.expect_err("store is unreadable");
    let health = keys.health_snapshot();
    assert_eq!(health.trust_state, JwksTrustState::Grace);
    assert_eq!(health.last_failure, Some(JwksFailureClass::Transport));
    assert!(
        keys.trusted_keys()
            .is_some_and(|trusted| trusted.contains_key("kept")),
        "the last-read keys stay usable while the store cannot be read"
    );

    tokio::time::sleep(Duration::from_millis(2_200)).await;
    assert_eq!(
        keys.health_snapshot().trust_state,
        JwksTrustState::Expired,
        "retention is bounded by max_stale"
    );
    assert!(keys.trusted_keys().is_none());
}

// ─── End to end through the process store and the shared cache ──────────

#[tokio::test]
#[serial_test::serial(jwks_remote_global_cache)]
async fn jwks_auth_verifies_rotates_and_refuses_with_a_managed_record() {
    let _guard = cache_test_lock().lock().await;
    let store = ferrum_edge::tls::managed::global_store().expect("process managed store");
    let id = unique_id("e2e");
    let source = format!("managed://jwks/{id}#jwks");
    let config = managed_config(&source);

    // Presence check before the record exists names the missing id.
    let errors = ferrum_edge::plugins::jwks_auth::managed_jwks_source_errors(&config);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("does not exist"), "{errors:?}");

    let old = signing_key("old");
    upsert_jwks(&store, &id, jwks_document(&[&old]));
    assert!(
        ferrum_edge::plugins::jwks_auth::managed_jwks_source_errors(&config).is_empty(),
        "an existing usable record passes the presence check"
    );

    let plugin = JwksAuth::new(&config, default_client()).expect("managed provider");
    plugin
        .start_background_tasks()
        .expect("runtime starts the shared store");
    plugin.commit_background_tasks();
    plugin.warmup_jwks().await;
    let shared = cached_store(&source).expect("managed store joins the shared cache");
    assert!(shared.is_managed());

    assert_continue(authenticate(&plugin, &token(&old, "alice")).await);

    // Rotation step 1: publish the new key beside the old one. The re-read
    // the admin API performs after a write makes it effective immediately.
    let new = signing_key("new");
    upsert_jwks(&store, &id, jwks_document(&[&old, &new]));
    assert!(refresh_managed_jwks_stores().await >= 1);
    assert_continue(authenticate(&plugin, &token(&old, "alice")).await);
    assert_continue(authenticate(&plugin, &token(&new, "alice")).await);

    // Another node's write (no local re-read): the first token naming the
    // unknown `kid` fails closed and triggers one out-of-band re-read, so a
    // later request verifies. This runs before any other unknown `kid` is
    // presented, so the per-store cooldown window is still open.
    let third = signing_key("third");
    upsert_jwks(&store, &id, jwks_document(&[&old, &new, &third]));
    assert_reject(
        authenticate(&plugin, &token(&third, "alice")).await,
        Some(401),
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if matches!(
            authenticate(&plugin, &token(&third, "alice")).await,
            PluginResult::Continue
        ) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "an unknown kid must trigger a re-read of the managed record"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // Rotation step 2: retire the old key; it is refused as soon as the
    // re-read completes.
    upsert_jwks(&store, &id, jwks_document(&[&new, &third]));
    refresh_managed_jwks_stores().await;
    assert_reject(
        authenticate(&plugin, &token(&old, "alice")).await,
        Some(401),
    );
    assert_continue(authenticate(&plugin, &token(&new, "alice")).await);

    // Deletion withdraws every key: tokens are refused like an expired set.
    store.delete(&id).expect("delete record");
    refresh_managed_jwks_stores().await;
    assert_reject(
        authenticate(&plugin, &token(&new, "alice")).await,
        Some(401),
    );
    assert_eq!(
        shared.health_snapshot().trust_state,
        JwksTrustState::Expired
    );

    // Restoring the record restores verification.
    upsert_jwks(&store, &id, jwks_document(&[&new]));
    refresh_managed_jwks_stores().await;
    assert_continue(authenticate(&plugin, &token(&new, "alice")).await);
    store.delete(&id).expect("cleanup");
}

// ─── Process-global state (isolated child processes) ────────────────────

/// Run this test binary's `test_name` alone in a child process with `env`
/// set, and require that it ran and passed. The process managed TLS store and
/// the plugin HTTP client build counter are process-global, so a regression
/// that depends on their first use or on an exact count needs its own process.
fn run_in_child_process(test_name: &str, env: &[(&str, &std::ffi::OsStr)]) {
    let exe = std::env::current_exe().expect("current test executable");
    let mut command = std::process::Command::new(exe);
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command
        .args(["--exact", test_name, "--nocapture"])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run child test");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{test_name} child failed: {}",
        String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(4096)])
    );
    assert!(
        stdout.contains("1 passed"),
        "{test_name} child must run exactly that test"
    );
}

/// A process managed TLS store that cannot be opened at first use (a torn or
/// unparseable `managed-tls.json`) must not be latched for the process
/// lifetime: once the document is repaired, the next read opens it, the
/// presence check passes, and a managed key store regains trust without a
/// restart (sol F1 / dsf F1 on #7373).
#[tokio::test]
async fn process_store_that_failed_to_open_is_reopened_after_repair() {
    const CHILD_DIR_ENV: &str = "FERRUM_TEST_MANAGED_JWKS_STORE_RECOVERY_DIR";
    const TEST_NAME: &str = "unit::plugins::jwks_auth_managed_source_tests::process_store_that_failed_to_open_is_reopened_after_repair";

    let Some(dir) = std::env::var_os(CHILD_DIR_ENV) else {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("managed-tls.json"), b"{ not json")
            .expect("write unparseable store document");
        run_in_child_process(
            TEST_NAME,
            &[
                (CHILD_DIR_ENV, dir.path().as_os_str()),
                ("FERRUM_TLS_MANAGED_STORE_PATH", dir.path().as_os_str()),
            ],
        );
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let id = unique_id("reopen");
    let source = format!("managed://jwks/{id}#jwks");

    // First use: the document cannot be parsed, so the store cannot be opened.
    ferrum_edge::tls::managed::global_store().expect_err("unparseable store document");
    let error = check_managed_jwks_source(&source).expect_err("store is unavailable");
    assert!(error.contains("could not be opened"), "{error}");
    let keys = JwksKeyStore::new_managed(source.clone(), default_client());
    keys.fetch_keys().await.expect_err("store is unavailable");
    assert_eq!(
        keys.health_snapshot().last_failure,
        Some(JwksFailureClass::Transport)
    );

    // Repair: replace the document with a valid store holding the record.
    std::fs::remove_file(dir.join("managed-tls.json")).expect("remove torn document");
    let repaired = ManagedTlsStore::open_with_limits(&dir, 1024 * 1024, 64, None)
        .expect("open repaired store");
    let key = signing_key("after-repair");
    upsert_jwks(&repaired, &id, jwks_document(&[&key]));

    // The process store is opened again rather than reporting the cached
    // failure, and every consumer recovers.
    ferrum_edge::tls::managed::global_store().expect("repaired store opens");
    assert_eq!(check_managed_jwks_source(&source), Ok(1));
    assert_eq!(keys.fetch_keys().await, Ok(1));
    assert_eq!(keys.health_snapshot().trust_state, JwksTrustState::Fresh);
    assert!(
        keys.trusted_keys()
            .is_some_and(|trusted| trusted.contains_key("after-repair"))
    );
}

/// A managed key store never dials, so constructing managed providers, and
/// starting the shared managed stores, builds no plugin HTTP client: a
/// config-load validation sweep must build a bounded number of clients, not
/// one per managed provider (issue #4116; dsf F5 on #7373).
#[tokio::test]
async fn managed_providers_build_no_plugin_http_client() {
    const CHILD_ENV: &str = "FERRUM_TEST_MANAGED_JWKS_CLIENT_BUILDS_CHILD";
    const TEST_NAME: &str = "unit::plugins::jwks_auth_managed_source_tests::managed_providers_build_no_plugin_http_client";

    if std::env::var_os(CHILD_ENV).is_none() {
        run_in_child_process(TEST_NAME, &[(CHILD_ENV, std::ffi::OsStr::new("1"))]);
        return;
    }

    let config = json!({
        "providers": [
            { "issuer": "https://idp-a.example.com", "jwks_source": "managed://jwks/builds-a#jwks" },
            { "issuer": "https://idp-b.example.com", "jwks_source": "managed://jwks/builds-b#jwks" },
            { "issuer": "https://idp-c.example.com", "jwks_source": "managed://jwks/builds-c#jwks" }
        ]
    });
    let client = default_client();
    let before = ferrum_edge::_test_support::plugin_http_client_builds_for_test();

    for _ in 0..4 {
        JwksAuth::new(&config, client.clone()).expect("managed providers");
    }
    let plugin = JwksAuth::new(&config, client.clone()).expect("managed providers");
    plugin
        .start_background_tasks()
        .expect("runtime starts the shared managed stores");
    for source in [
        "managed://jwks/builds-a#jwks",
        "managed://jwks/builds-b#jwks",
        "managed://jwks/builds-c#jwks",
    ] {
        assert!(
            cached_store(source).is_some_and(|store| store.is_managed()),
            "{source} joins the shared cache"
        );
    }

    assert_eq!(
        ferrum_edge::_test_support::plugin_http_client_builds_for_test() - before,
        0,
        "managed key stores must reuse the caller's client, never build one"
    );
}

#[test]
fn oidc_relying_party_accepts_a_managed_jwks_source_with_explicit_endpoints() {
    let base = json!({
        "providers": [{
            "issuer": ISSUER,
            "authorization_endpoint": "https://managed-idp.example.com/authorize",
            "token_endpoint": "https://managed-idp.example.com/token",
            "jwks_source": "managed://jwks/rp-keys#jwks",
            "client_id": "ferrum-gateway",
            "client_auth": { "method": "client_secret_post", "client_secret": "secret" },
            "scopes": ["openid"],
            "redirect_uri": "https://app.example.com/oauth/callback"
        }],
        "session": {
            "store": "cookie",
            "encryption_secret": "9f3a7c1e5b2d8406a1c9e7f3b5d20486"
        },
        "behavior": {
            "trusted_redirect_hosts": ["app.example.com"]
        }
    });
    validate_plugin_config("oidc_relying_party", &base)
        .expect("explicit endpoints with a managed JWKS source are admitted");
    assert_eq!(
        ferrum_edge::plugins::oidc_relying_party::managed_jwks_source(&base).as_deref(),
        Some("managed://jwks/rp-keys#jwks")
    );

    let mut with_uri = base.clone();
    with_uri["providers"][0]["jwks_uri"] = json!("https://managed-idp.example.com/jwks");
    let error = validate_plugin_config("oidc_relying_party", &with_uri)
        .expect_err("jwks_uri and jwks_source are exclusive");
    assert!(error.contains("at most one of"), "{error}");

    let mut with_discovery = base.clone();
    let provider = with_discovery["providers"][0]
        .as_object_mut()
        .expect("provider object");
    provider.remove("authorization_endpoint");
    provider.remove("token_endpoint");
    with_discovery["providers"][0]["discovery_url"] =
        json!("https://managed-idp.example.com/.well-known/openid-configuration");
    let error = validate_plugin_config("oidc_relying_party", &with_discovery)
        .expect_err("discovery_url and jwks_source are exclusive");
    assert!(
        error.contains("conflicts with explicit endpoints"),
        "{error}"
    );

    let mut wrong_kind = base.clone();
    wrong_kind["providers"][0]["jwks_source"] = json!("managed://ca-bundles/rp-keys");
    let error = validate_plugin_config("oidc_relying_party", &wrong_kind)
        .expect_err("a non-JWKS reference is refused");
    assert!(error.contains("`provider[0].jwks_source`"), "{error}");
}
