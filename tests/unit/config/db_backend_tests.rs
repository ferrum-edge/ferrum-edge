use chrono::Utc;
use ferrum_edge::_test_support::admin_mtls_dns_admission_drop_should_release;
use ferrum_edge::config::db_backend::{
    AtomicClearVerification, DeleteAllResourcesError, DeleteMode, IncrementalResult,
    NamespaceResourceCounts, NamespacedResourceId, classify_atomic_clear_verification,
    extract_db_hostname, extract_known_ids, redact_url,
};
use ferrum_edge::config::types::GatewayConfig;
use std::collections::HashMap;

#[test]
fn ambiguous_atomic_clear_verification_classifies_all_outcomes() {
    let prior = NamespaceResourceCounts {
        proxies: 2,
        consumers: 3,
        plugin_configs: 4,
        upstreams: 5,
        api_specs: 1,
    };

    assert_eq!(
        classify_atomic_clear_verification(prior, Ok::<_, ()>(NamespaceResourceCounts::default())),
        AtomicClearVerification::ClearCommitted
    );
    assert_eq!(
        classify_atomic_clear_verification(prior, Ok::<_, ()>(prior)),
        AtomicClearVerification::PriorCountsStillVisible
    );
    assert_eq!(
        classify_atomic_clear_verification(prior, Err::<NamespaceResourceCounts, _>(())),
        AtomicClearVerification::UnknownOutcome
    );
    assert_eq!(
        classify_atomic_clear_verification(
            NamespaceResourceCounts::default(),
            Ok::<_, ()>(NamespaceResourceCounts::default()),
        ),
        AtomicClearVerification::PriorCountsStillVisible,
        "an empty prior namespace is still ambiguous while its clear can commit later"
    );
}

#[test]
fn delayed_unknown_clear_cannot_admit_a_post_verification_write() {
    let prior = NamespaceResourceCounts {
        proxies: 1,
        consumers: 1,
        plugin_configs: 1,
        upstreams: 1,
        api_specs: 1,
    };

    // Model an UnknownTransactionCommitResult whose clear is still delayed
    // when verification runs. Seeing the prior counts is only a point-in-time
    // observation; the transaction may become visible after this read.
    let verification = classify_atomic_clear_verification(prior, Ok::<_, ()>(prior));
    assert_eq!(
        verification,
        AtomicClearVerification::PriorCountsStillVisible
    );
    assert!(
        verification.requires_guard_retention(),
        "the namespace guard must remain held while the delayed clear can still commit"
    );

    // A retained guard rejects the hypothetical writer that arrives after
    // verification. If that writer were admitted, the delayed clear below
    // could erase a successful response.
    let guard_released = admin_mtls_dns_admission_drop_should_release(
        true,
        !verification.requires_guard_retention(),
    );
    assert!(!guard_released);

    let mut visible_post_verification_writes = u8::from(guard_released);
    let acknowledged_writes = visible_post_verification_writes;
    // The delayed transaction now commits and clears the namespace.
    visible_post_verification_writes = 0;
    assert_eq!(
        visible_post_verification_writes, acknowledged_writes,
        "no admitted post-verification write may be lost to a delayed clear"
    );
}

#[test]
fn delete_error_preserves_unknown_commit_result() {
    let error = DeleteAllResourcesError::with_unknown_commit_result(
        DeleteMode::Atomic,
        anyhow::anyhow!("commit acknowledgement lost"),
    );
    assert_eq!(error.mode(), DeleteMode::Atomic);
    assert!(error.has_unknown_commit_result());
}

// ---------------------------------------------------------------------------
// extract_db_hostname — tests for MongoDB URLs
// ---------------------------------------------------------------------------

#[test]
fn extract_hostname_mongodb_url() {
    let url = "mongodb://user:pass@mongo.example.com:27017/ferrum";
    assert_eq!(
        extract_db_hostname(url),
        Some("mongo.example.com".to_string())
    );
}

#[test]
fn extract_hostname_mongodb_srv_url() {
    let url = "mongodb+srv://user:pass@cluster0.abc123.mongodb.net/ferrum";
    assert_eq!(
        extract_db_hostname(url),
        Some("cluster0.abc123.mongodb.net".to_string())
    );
}

#[test]
fn extract_hostname_mongodb_ip_literal() {
    let url = "mongodb://user:pass@192.168.1.100:27017/ferrum";
    assert_eq!(extract_db_hostname(url), None);
}

#[test]
fn extract_hostname_mongodb_localhost() {
    let url = "mongodb://localhost:27017/ferrum";
    assert_eq!(extract_db_hostname(url), Some("localhost".to_string()));
}

#[test]
fn extract_hostname_mongodb_with_options() {
    let url = "mongodb://user:pass@mongo.internal:27017/ferrum?authSource=admin&tls=true";
    assert_eq!(extract_db_hostname(url), Some("mongo.internal".to_string()));
}

#[test]
fn extract_hostname_mongodb_multi_host_uses_first_dns_host() {
    let url = "mongodb://user:pass@mongo1.internal:27017,mongo2.internal:27017,mongo3.internal:27017/ferrum?replicaSet=rs0";
    assert_eq!(
        extract_db_hostname(url),
        Some("mongo1.internal".to_string())
    );
}

#[test]
fn extract_hostname_mongodb_multi_host_first_ip_literal_returns_none() {
    let url = "mongodb://user:pass@192.0.2.10:27017,mongo2.internal:27017/ferrum?replicaSet=rs0";
    assert_eq!(extract_db_hostname(url), None);
}

#[test]
fn extract_hostname_mongodb_multi_host_without_ports_uses_first_host() {
    // Seed lists that omit explicit ports are accepted by the `url` crate as a
    // single comma-joined host; DNS rotation must still track the first seed
    // host rather than the unresolvable combined authority.
    let url = "mongodb://user:pass@mongo1.internal,mongo2.internal,mongo3.internal/ferrum";
    assert_eq!(
        extract_db_hostname(url),
        Some("mongo1.internal".to_string())
    );
}

#[test]
fn extract_hostname_mongodb_multi_host_without_ports_first_ip_returns_none() {
    let url = "mongodb://user:pass@192.0.2.10,mongo2.internal/ferrum?replicaSet=rs0";
    assert_eq!(extract_db_hostname(url), None);
}

// ---------------------------------------------------------------------------
// redact_url — tests for MongoDB URLs
// ---------------------------------------------------------------------------

#[test]
fn redact_mongodb_url_hides_credentials() {
    let url = "mongodb://myuser:supersecret@mongo.example.com:27017/ferrum?authSource=admin";
    let redacted = redact_url(url);
    assert!(!redacted.contains("supersecret"));
    assert!(!redacted.contains("myuser"));
    assert!(redacted.contains("mongo.example.com"));
    assert!(redacted.contains("27017"));
}

#[test]
fn redact_mongodb_srv_url() {
    let url = "mongodb+srv://user:pass@cluster0.abc123.mongodb.net/ferrum";
    let redacted = redact_url(url);
    assert!(!redacted.contains("pass"));
    assert!(redacted.contains("cluster0.abc123.mongodb.net"));
}

#[test]
fn redact_url_hides_sensitive_query_credentials() {
    let url = concat!(
        "postgres://db.example.com:5432/ferrum?",
        "user=alice&password=supersecret&sslpassword=tls-secret&",
        "token=bearer-token&sslmode=require"
    );
    let redacted = redact_url(url);

    assert!(!redacted.contains("alice"));
    assert!(!redacted.contains("supersecret"));
    assert!(!redacted.contains("tls-secret"));
    assert!(!redacted.contains("bearer-token"));

    let parsed = url::Url::parse(&redacted).expect("redacted URL should parse");
    let pairs: HashMap<String, String> = parsed.query_pairs().into_owned().collect();
    assert_eq!(pairs.get("user").map(String::as_str), Some("***"));
    assert_eq!(pairs.get("password").map(String::as_str), Some("***"));
    assert_eq!(pairs.get("sslpassword").map(String::as_str), Some("***"));
    assert_eq!(pairs.get("token").map(String::as_str), Some("***"));
    assert_eq!(pairs.get("sslmode").map(String::as_str), Some("require"));
}

#[test]
fn redact_url_hides_mongodb_and_sqlite_query_secrets() {
    let mongo =
        redact_url("mongodb://mongo.example.com:27017/ferrum?authSource=admin&password=leakytoken");
    assert!(!mongo.contains("leakytoken"));
    let parsed_mongo = url::Url::parse(&mongo).expect("redacted MongoDB URL should parse");
    let mongo_pairs: HashMap<String, String> = parsed_mongo.query_pairs().into_owned().collect();
    assert_eq!(
        mongo_pairs.get("authSource").map(String::as_str),
        Some("admin")
    );
    assert_eq!(mongo_pairs.get("password").map(String::as_str), Some("***"));

    let sqlite = redact_url("sqlite://ferrum.db?key=supersecret&mode=rwc");
    assert!(!sqlite.contains("supersecret"));
    let parsed_sqlite = url::Url::parse(&sqlite).expect("redacted SQLite URL should parse");
    let sqlite_pairs: HashMap<String, String> = parsed_sqlite.query_pairs().into_owned().collect();
    assert_eq!(sqlite_pairs.get("key").map(String::as_str), Some("***"));
    assert_eq!(sqlite_pairs.get("mode").map(String::as_str), Some("rwc"));
}

#[test]
fn redact_url_handles_mongodb_multi_host_replica_set_urls() {
    let redacted = redact_url(
        "mongodb://user:secretpass@host1:27017,host2:27017,host3:27017/ferrum?replicaSet=rs0&password=query-secret",
    );

    assert!(!redacted.contains("user"));
    assert!(!redacted.contains("secretpass"));
    assert!(!redacted.contains("query-secret"));
    assert!(redacted.starts_with("mongodb://***@host1:27017,host2:27017,host3:27017/ferrum?"));
    assert!(redacted.contains("replicaSet=rs0"));
    assert!(redacted.contains("password=***"));
}

#[test]
fn redact_url_matches_sensitive_query_keys_case_insensitively() {
    let redacted = redact_url("postgres://db.example.com/ferrum?Password=secret&Api_Key=token");
    assert!(!redacted.contains("secret"));
    assert!(!redacted.contains("token"));

    let parsed = url::Url::parse(&redacted).expect("redacted URL should parse");
    let pairs: HashMap<String, String> = parsed.query_pairs().into_owned().collect();
    assert_eq!(pairs.get("Password").map(String::as_str), Some("***"));
    assert_eq!(pairs.get("Api_Key").map(String::as_str), Some("***"));
}

#[test]
fn redact_url_hides_mongodb_keyfile_password_alias() {
    // MongoDB's `tlsCertificateKeyFilePassword` carries the private key file's
    // passphrase; it is recognized as a DB TLS URL option and logged via
    // `redact_url` on the FERRUM_DB_TLS_MODE warning path, so it must be
    // redacted even though it is not in the exact-key list.
    let redacted = redact_url(concat!(
        "mongodb://mongo.example.com:27017/ferrum?",
        "tls=true&tlsCertificateKeyFile=/certs/client.pem&",
        "tlsCertificateKeyFilePassword=keyfile-secret"
    ));
    assert!(
        !redacted.contains("keyfile-secret"),
        "key-file password leaked: {redacted}"
    );

    let parsed = url::Url::parse(&redacted).expect("redacted URL should parse");
    let pairs: HashMap<String, String> = parsed.query_pairs().into_owned().collect();
    assert_eq!(
        pairs
            .get("tlsCertificateKeyFilePassword")
            .map(String::as_str),
        Some("***")
    );
    // The certificate/key file *path* is not a secret and must be preserved so
    // the redacted log remains actionable.
    assert_eq!(
        pairs.get("tlsCertificateKeyFile").map(String::as_str),
        Some("/certs/client.pem")
    );
    assert_eq!(pairs.get("tls").map(String::as_str), Some("true"));
}

#[test]
fn redact_url_redacts_credential_substring_aliases() {
    // OAuth-style aliases reach the substring matcher after separator
    // normalization.
    let redacted = redact_url(concat!(
        "postgres://db.example.com/ferrum?",
        "Client-Secret=cs&access.token=at&Refresh_Token=rt&credential=cr&sslmode=require"
    ));
    for leaked in ["=cs", "=at", "=rt", "=cr"] {
        assert!(!redacted.contains(leaked), "leaked {leaked}: {redacted}");
    }

    let parsed = url::Url::parse(&redacted).expect("redacted URL should parse");
    let pairs: HashMap<String, String> = parsed.query_pairs().into_owned().collect();
    assert_eq!(pairs.get("Client-Secret").map(String::as_str), Some("***"));
    assert_eq!(pairs.get("access.token").map(String::as_str), Some("***"));
    assert_eq!(pairs.get("Refresh_Token").map(String::as_str), Some("***"));
    assert_eq!(pairs.get("credential").map(String::as_str), Some("***"));
    // Non-secret TLS options remain untouched.
    assert_eq!(pairs.get("sslmode").map(String::as_str), Some("require"));
}

#[test]
fn redact_url_hides_percent_encoded_sensitive_query_keys() {
    let redacted = redact_url(concat!(
        "postgres://db.example.com/ferrum?",
        "pass%77ord=supersecret&client%5Fsecret=client-secret&sslmode=require"
    ));
    assert!(
        !redacted.contains("supersecret"),
        "password leaked: {redacted}"
    );
    assert!(
        !redacted.contains("client-secret"),
        "client secret leaked: {redacted}"
    );

    let parsed = url::Url::parse(&redacted).expect("redacted URL should parse");
    let pairs: HashMap<String, String> = parsed.query_pairs().into_owned().collect();
    assert_eq!(pairs.get("password").map(String::as_str), Some("***"));
    assert_eq!(pairs.get("client_secret").map(String::as_str), Some("***"));
    assert_eq!(pairs.get("sslmode").map(String::as_str), Some("require"));
}

#[test]
fn redact_url_redacts_mongodb_semicolon_separated_options() {
    // MongoDB accepts `;` as an option separator; the `url` crate's query parser
    // only splits on `&`, so a `;`-joined credential must still be redacted.
    // No-port seed list parses successfully and flows through the OK arm.
    let redacted = redact_url(
        "mongodb://u:p@db0,db1/ferrum?replicaSet=rs0;password=query-secret;authSource=admin",
    );
    assert!(
        !redacted.contains("query-secret"),
        "semicolon password leaked: {redacted}"
    );
    assert!(redacted.contains("replicaSet=rs0"));
    assert!(redacted.contains("password=***"));
    assert!(redacted.contains("authSource=admin"));

    // Explicit ports make the authority unparseable, exercising the multi-host
    // fallback redactor on the same `;`-separated option string.
    let redacted_ports =
        redact_url("mongodb://u:p@db0:27017,db1:27017/ferrum?replicaSet=rs0;password=query-secret");
    assert!(
        !redacted_ports.contains("query-secret"),
        "semicolon password leaked via fallback: {redacted_ports}"
    );
    assert!(redacted_ports.contains("password=***"));
    assert!(redacted_ports.contains("replicaSet=rs0"));
}

#[test]
fn redact_url_hides_percent_encoded_mongodb_option_keys_in_fallback() {
    let redacted = redact_url(
        "mongodb://u:p@db0:27017,db1:27017/ferrum?replicaSet=rs0;pass%77ord=query-secret",
    );
    assert!(
        !redacted.contains("query-secret"),
        "encoded fallback password leaked: {redacted}"
    );
    assert!(redacted.contains("pass%77ord=***"));
    assert!(redacted.contains("replicaSet=rs0"));
}

#[test]
fn redact_url_redacts_mongodb_auth_mechanism_properties_tokens() {
    // MONGODB-AWS temporary credentials carry the session token inside the
    // `authMechanismProperties` value; the key itself is not sensitive, so the
    // credential-bearing property values must be redacted.
    let redacted = redact_url(concat!(
        "mongodb://u:p@db0,db1/ferrum?authMechanism=MONGODB-AWS&",
        "authMechanismProperties=AWS_SESSION_TOKEN:sessiontoken,",
        "AWS_SECRET_ACCESS_KEY:topsecret,CANONICALIZE_HOST_NAME:true"
    ));
    assert!(
        !redacted.contains("sessiontoken"),
        "AWS session token leaked: {redacted}"
    );
    assert!(
        !redacted.contains("topsecret"),
        "AWS secret access key leaked: {redacted}"
    );
    assert!(redacted.contains("AWS_SESSION_TOKEN:***"));
    assert!(redacted.contains("AWS_SECRET_ACCESS_KEY:***"));
    // Benign properties remain for observability.
    assert!(redacted.contains("CANONICALIZE_HOST_NAME:true"));

    // Same option carried through the multi-host fallback (explicit ports).
    let redacted_ports = redact_url(concat!(
        "mongodb://u:p@db0:27017,db1:27017/ferrum?authMechanism=MONGODB-AWS&",
        "authMechanismProperties=AWS_SESSION_TOKEN:sessiontoken"
    ));
    assert!(
        !redacted_ports.contains("sessiontoken"),
        "AWS session token leaked via fallback: {redacted_ports}"
    );
    assert!(redacted_ports.contains("AWS_SESSION_TOKEN:***"));
}

// ---------------------------------------------------------------------------
// extract_known_ids — tests
// ---------------------------------------------------------------------------

#[test]
fn extract_known_ids_empty_config() {
    let config = GatewayConfig::default();
    let (proxy_ids, consumer_ids, plugin_config_ids, upstream_ids) = extract_known_ids(&config);
    assert!(proxy_ids.is_empty());
    assert!(consumer_ids.is_empty());
    assert!(plugin_config_ids.is_empty());
    assert!(upstream_ids.is_empty());
}

#[test]
fn extract_known_ids_with_data() {
    // Use serde to construct test objects without needing Default
    let mut config = GatewayConfig::default();
    let proxy1: ferrum_edge::config::types::Proxy = serde_json::from_value(serde_json::json!({
        "id": "proxy-1",
        "name": "test-1",
        "listen_path": "/test1",
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": 8080
    }))
    .unwrap();
    let proxy2: ferrum_edge::config::types::Proxy = serde_json::from_value(serde_json::json!({
        "id": "proxy-2",
        "name": "test-2",
        "listen_path": "/test2",
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": 8081
    }))
    .unwrap();
    let consumer: ferrum_edge::config::types::Consumer =
        serde_json::from_value(serde_json::json!({
            "id": "consumer-1",
            "username": "test-user",
            "credentials": {}
        }))
        .unwrap();

    config.proxies.push(proxy1);
    config.proxies.push(proxy2);
    config.consumers.push(consumer);

    let (proxy_ids, consumer_ids, plugin_config_ids, upstream_ids) = extract_known_ids(&config);
    assert_eq!(proxy_ids.len(), 2);
    assert!(proxy_ids.contains("proxy-1"));
    assert!(proxy_ids.contains("proxy-2"));
    assert_eq!(consumer_ids.len(), 1);
    assert!(consumer_ids.contains("consumer-1"));
    assert!(plugin_config_ids.is_empty());
    assert!(upstream_ids.is_empty());
}

// ---------------------------------------------------------------------------
// extract_db_hostname — existing SQL URL patterns still work
// ---------------------------------------------------------------------------

#[test]
fn extract_hostname_postgres_url_via_free_fn() {
    let url = "postgres://user:pass@db.example.com:5432/ferrum";
    assert_eq!(extract_db_hostname(url), Some("db.example.com".to_string()));
}

#[test]
fn extract_hostname_sqlite_returns_none_via_free_fn() {
    assert_eq!(extract_db_hostname("sqlite://ferrum.db"), None);
}

// ---------------------------------------------------------------------------
// IncrementalResult::is_empty — incremental polling empty detection
// ---------------------------------------------------------------------------

#[test]
fn incremental_result_is_empty_when_default() {
    let result = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    assert!(result.is_empty());
}

#[test]
fn incremental_result_deserializes_legacy_delta_without_sequence_cursor() {
    let result: IncrementalResult = serde_json::from_value(serde_json::json!({
        "added_or_modified_proxies": [],
        "removed_proxy_ids": [],
        "added_or_modified_consumers": [],
        "removed_consumer_ids": [],
        "added_or_modified_plugin_configs": [],
        "removed_plugin_config_ids": [],
        "added_or_modified_upstreams": [],
        "removed_upstream_ids": [],
        "poll_timestamp": "2026-06-21T00:00:00Z"
    }))
    .expect("legacy incremental deltas without sequence_cursor must deserialize");

    assert_eq!(result.sequence_cursor, 0);
    assert!(result.is_empty());
}

#[test]
fn incremental_result_not_empty_with_added_proxy() {
    let proxy: ferrum_edge::config::types::Proxy = serde_json::from_value(serde_json::json!({
        "id": "p1",
        "listen_path": "/api",
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": 8080
    }))
    .unwrap();
    let result = IncrementalResult {
        added_or_modified_proxies: vec![proxy],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    assert!(!result.is_empty());
}

#[test]
fn incremental_result_not_empty_with_removed_proxy_id() {
    let result = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![NamespacedResourceId::new("ferrum", "p1")],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    assert!(!result.is_empty());
}

#[test]
fn incremental_result_not_empty_with_removed_consumer() {
    let result = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![NamespacedResourceId::new("ferrum", "c1")],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    assert!(!result.is_empty());
}

#[test]
fn incremental_result_decodes_legacy_removed_consumer_ids() {
    // Same-major.minor rolling upgrade: a legacy peer may send bare removal IDs.
    // Decode must accept them (unqualified) and qualification must scope them to
    // the already-authorized subscription namespace — not reject at serde time.
    let result = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 1,
        poll_timestamp: Utc::now(),
    };
    let mut value = serde_json::to_value(result).unwrap();
    value["removed_consumer_ids"] = serde_json::json!(["c1"]);

    let mut decoded: IncrementalResult = serde_json::from_value(value).unwrap();
    assert_eq!(
        decoded.removed_consumer_ids,
        vec![NamespacedResourceId::new("", "c1")]
    );
    assert_eq!(decoded.qualify_unqualified_removals("ferrum"), 1);
    assert_eq!(
        decoded.removed_consumer_ids,
        vec![NamespacedResourceId::new("ferrum", "c1")]
    );

    // Entries that are neither a bare string nor a namespace-qualified object
    // remain unclassifiable and must fail closed at decode.
    let mut malformed = serde_json::to_value(IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 1,
        poll_timestamp: Utc::now(),
    })
    .unwrap();
    malformed["removed_consumer_ids"] = serde_json::json!([{"unexpected_key": 1}]);
    assert!(serde_json::from_value::<IncrementalResult>(malformed).is_err());
}

#[test]
fn incremental_result_not_empty_with_removed_plugin_config() {
    let result = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![NamespacedResourceId::new("ferrum", "pc1")],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    assert!(!result.is_empty());
}

#[test]
fn incremental_result_not_empty_with_removed_upstream() {
    let result = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![NamespacedResourceId::new("ferrum", "u1")],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    assert!(!result.is_empty());
}

#[test]
fn incremental_result_not_empty_with_added_consumer() {
    let consumer: ferrum_edge::config::types::Consumer =
        serde_json::from_value(serde_json::json!({
            "id": "c1",
            "username": "alice",
            "credentials": {}
        }))
        .unwrap();
    let result = IncrementalResult {
        added_or_modified_proxies: vec![],
        removed_proxy_ids: vec![],
        added_or_modified_consumers: vec![consumer],
        removed_consumer_ids: vec![],
        added_or_modified_plugin_configs: vec![],
        removed_plugin_config_ids: vec![],
        added_or_modified_upstreams: vec![],
        removed_upstream_ids: vec![],
        sequence_cursor: 0,
        poll_timestamp: Utc::now(),
    };
    assert!(!result.is_empty());
}
