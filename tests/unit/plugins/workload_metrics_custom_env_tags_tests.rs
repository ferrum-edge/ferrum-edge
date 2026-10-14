//! External coverage for Istio Telemetry `custom_env_tags` resolution and the
//! credential-exfiltration boundary on environment variable names.
//!
//! Construction uses the injected lookup seam so these tests never mutate the
//! process environment (`set_var` / `remove_var`).

use std::collections::HashMap;
use std::ffi::OsString;

use ferrum_edge::_test_support::workload_metrics_new_with_env_lookup_for_test;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;

const ENV_VAR: &str = "FERRUM_TEST_WORKLOAD_METRICS_EXTERNAL_ENV_TAG";

async fn metadata_after_before_proxy(plugin: &impl Plugin) -> HashMap<String, String> {
    let mut ctx = RequestContext::new("10.0.0.2".to_string(), "GET".to_string(), "/".to_string());
    let mut headers = HashMap::new();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    ctx.metadata
}

#[tokio::test]
async fn custom_env_tags_present_overrides_literal_default() {
    let plugin = workload_metrics_new_with_env_lookup_for_test(
        &json!({
            "custom_tags": {"cluster": "fallback"},
            "custom_env_tags": {"cluster": ENV_VAR}
        }),
        |name| {
            if name == ENV_VAR {
                Ok("live".to_string())
            } else {
                Err(std::env::VarError::NotPresent)
            }
        },
    )
    .expect("present env resolves");
    let metadata = metadata_after_before_proxy(&plugin).await;
    assert_eq!(metadata.get("cluster").map(String::as_str), Some("live"));
}

#[tokio::test]
async fn custom_env_tags_missing_keeps_default() {
    let plugin = workload_metrics_new_with_env_lookup_for_test(
        &json!({
            "custom_tags": {"cluster": "fallback"},
            "custom_env_tags": {"cluster": ENV_VAR}
        }),
        |_| Err(std::env::VarError::NotPresent),
    )
    .expect("missing env keeps default");
    let metadata = metadata_after_before_proxy(&plugin).await;
    assert_eq!(
        metadata.get("cluster").map(String::as_str),
        Some("fallback")
    );
}

#[tokio::test]
async fn custom_env_tags_missing_without_default_omits_tag() {
    let plugin = workload_metrics_new_with_env_lookup_for_test(
        &json!({
            "custom_env_tags": {"region": "FERRUM_TEST_WORKLOAD_METRICS_ENV_ABSENT"}
        }),
        |_| Err(std::env::VarError::NotPresent),
    )
    .expect("missing without default constructs");
    let metadata = metadata_after_before_proxy(&plugin).await;
    assert!(!metadata.contains_key("region"));
}

#[tokio::test]
async fn custom_env_tags_empty_present_is_resolved_value() {
    let plugin = workload_metrics_new_with_env_lookup_for_test(
        &json!({
            "custom_tags": {"cluster": "fallback"},
            "custom_env_tags": {"cluster": ENV_VAR}
        }),
        |name| {
            if name == ENV_VAR {
                Ok(String::new())
            } else {
                Err(std::env::VarError::NotPresent)
            }
        },
    )
    .expect("empty present value resolves");
    let metadata = metadata_after_before_proxy(&plugin).await;
    assert_eq!(metadata.get("cluster").map(String::as_str), Some(""));
}

#[test]
fn custom_env_tags_oversized_resolved_value_fails_closed_without_echo() {
    let secret_value = "x".repeat(1025);
    let error = workload_metrics_new_with_env_lookup_for_test(
        &json!({
            "custom_env_tags": {"cluster": ENV_VAR}
        }),
        |name| {
            if name == ENV_VAR {
                Ok(secret_value.clone())
            } else {
                Err(std::env::VarError::NotPresent)
            }
        },
    )
    .err()
    .expect("oversized value fails closed");
    assert!(
        error.contains("exceeds 1024 bytes"),
        "expected size rejection, got {error}"
    );
    assert!(!error.contains(&"x".repeat(32)));
    assert!(!error.contains(ENV_VAR));
    assert!(!error.contains(&secret_value));
}

#[test]
fn custom_env_tags_non_unicode_fails_closed_without_echo() {
    let error = workload_metrics_new_with_env_lookup_for_test(
        &json!({
            "custom_env_tags": {"cluster": ENV_VAR}
        }),
        |name| {
            if name == ENV_VAR {
                Err(std::env::VarError::NotUnicode(OsString::from(
                    "not-utf8-marker",
                )))
            } else {
                Err(std::env::VarError::NotPresent)
            }
        },
    )
    .err()
    .expect("non-Unicode value fails closed");
    assert!(
        error.contains("is not valid UTF-8"),
        "expected UTF-8 rejection, got {error}"
    );
    assert!(!error.contains(ENV_VAR));
    assert!(!error.contains("not-utf8-marker"));
}

#[test]
fn custom_env_tags_reject_credential_bypass_spellings_without_echo() {
    let cases = [
        "AWS_SECRET-KEY",
        "myPassword",
        "AccessToken",
        "sessiontoken",
        "ClientId",
        "awssecretkey",
        "AWSACCESSKEYID",
        "AWSSECRETACCESSKEY",
        "MYCLIENTSECRETJSON",
        "VENDORTOKENVALUE",
        "GOOGLEAPPLICATIONCREDENTIALSJSON",
        "DATABASEURL",
        "MongoUri",
        "client_secret",
        "FERRUM_ADMIN_JWT_SECRET",
        "AWS_SESSION_TOKEN",
        "AZURE_CLIENT_ID",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "FERRUM_DB_URL",
        "DATABASE_CONNECTION_STRING",
        "AUTHORIZATION",
        "SESSION_COOKIE",
        "SESSIONCOOKIE",
        "AUTHORIZATIONHEADER",
        "BEARERHEADER",
        "COOKIEJAR",
        "SETCOOKIE",
        "CSRFTOKENVALUE",
        "CACHE_REQUEST_HEADERS_SNAPSHOT",
        "CLAIM_HEADER_SUBJECT",
        "LAST_EVENT_ID",
        // Credential classes outside every exact list (issue #6619).
        "GPG_PASSPHRASE",
        "HSM_PIN",
        "USER_SESSION_ID",
        "SESSIONIDENTIFIER",
        "TOTP_SEED",
        "DB_PWD",
        "SIGNING_KEY",
        "WEBHOOK_SIGNATURE",
        "CLIENT_ASSERTION",
        "ID_JWT",
        "ASSERTION_VALUE",
        "PRIVATEKEY",
        "ENCRYPTIONKEY",
        "HSMPIN",
        "TOTPSEED",
        "PRIVATE_RSA_KEY",
        "HSM_PIN_ASSERTION_OUT_OF_SCOPE",
        "PRIVATEECCKEY",
        "PRIVATEPKCS12KEY",
        "AWSACCESS_KEY",
        "VENDORPIN",
        "VENDORPINVALUE",
        "USERSID",
        "IDJWS",
    ];

    for env_var in cases {
        let error = workload_metrics_new_with_env_lookup_for_test(
            &json!({
                "custom_env_tags": {"dimension": env_var}
            }),
            |_| Err(std::env::VarError::NotPresent),
        )
        .err()
        .unwrap_or_else(|| panic!("expected credential rejection for {env_var}"));
        assert!(
            error.contains("cannot copy a credential-bearing environment variable"),
            "expected credential rejection for {env_var}, got {error}"
        );
        assert!(
            !error.contains(env_var),
            "rejected environment name must not be echoed: {error}"
        );
        assert!(
            !error.contains("live-secret-value"),
            "resolved values must not appear in errors"
        );
    }
}

#[test]
fn custom_env_tags_allow_ordinary_istio_ferrum_dimension_names() {
    for env_var in ["ISTIO_META_CLUSTER_ID", "ISTIO_META_ZONE", "FERRUM_REGION"] {
        workload_metrics_new_with_env_lookup_for_test(
            &json!({
                "custom_env_tags": {"dimension": env_var}
            }),
            |_| Err(std::env::VarError::NotPresent),
        )
        .unwrap_or_else(|error| {
            panic!("ordinary dimension {env_var} must remain allowed, got {error}")
        });
    }
}

#[test]
fn custom_env_tags_do_not_reject_incidental_benign_fragments() {
    // Bounded classifier must not reject ordinary dimension names merely
    // because a short credential fragment occurs inside an unrelated token.
    // (Names that the shared metadata redaction substring list already rejects,
    // such as anything containing `secret`, are out of scope here.)
    for env_var in [
        "AUTHENTICATION_MODE",
        "KEYBOARD_LAYOUT",
        "SECRETION_RATE",
        "SECRETARIAT_REGION",
        "CLUSTER_ID",
        "CLIENT_NAME",
        "CLIENTIDENTITY_MODE",
        "REDIS_HOST",
        "DATABASE_NAME",
    ] {
        workload_metrics_new_with_env_lookup_for_test(
            &json!({
                "custom_env_tags": {"dimension": env_var}
            }),
            |_| Err(std::env::VarError::NotPresent),
        )
        .unwrap_or_else(|error| {
            panic!("benign name {env_var} must not be rejected as credential-bearing, got {error}")
        });
    }
}

#[test]
fn custom_env_tags_overlong_name_rejected_before_echo() {
    let overlong = format!("A{}", "B".repeat(256));
    assert!(overlong.len() > 256);
    let error = workload_metrics_new_with_env_lookup_for_test(
        &json!({
            "custom_env_tags": {"dimension": overlong}
        }),
        |_| Err(std::env::VarError::NotPresent),
    )
    .err()
    .expect("overlong env name fails closed");
    assert!(
        error.contains("invalid environment variable name"),
        "expected length rejection, got {error}"
    );
    assert!(!error.contains(&overlong));
    assert!(!error.contains("BBB"));
}

#[test]
fn custom_env_tags_credential_shaped_invalid_syntax_prefers_credential_diagnostic() {
    // Credential classification precedes portable-syntax diagnostics so
    // `AWS_SECRET-KEY` never echoes through the invalid-name path.
    let error = workload_metrics_new_with_env_lookup_for_test(
        &json!({
            "custom_env_tags": {"dimension": "AWS_SECRET-KEY"}
        }),
        |_| Err(std::env::VarError::NotPresent),
    )
    .err()
    .expect("credential-shaped invalid syntax fails closed");
    assert!(
        error.contains("cannot copy a credential-bearing environment variable"),
        "expected credential diagnostic first, got {error}"
    );
    assert!(!error.contains("AWS_SECRET-KEY"));
    assert!(!error.contains("invalid environment variable name"));
}

#[test]
fn custom_header_tags_reject_credential_class_header_names() {
    for header in [
        "x-session-id",
        "x-csrf",
        "x-privatekey",
        "x-client-assertion",
        "x-hsm-pin",
        // Header names are normalized to lowercase before classification.
        "x-hsmPin",
        "x-totpSeed",
        "x-private-rsa-key",
        "x-csrfValue",
        "x-vendorPin",
        "x-awsaccess-key",
        "x-private-rsapem-key",
        "x-privateecckey",
        "x-vendorPinValue",
        "x-userSid",
        "x-idJws",
    ] {
        let error = workload_metrics_new_with_env_lookup_for_test(
            &json!({
                "custom_header_tags": {"dimension": header}
            }),
            |_| Err(std::env::VarError::NotPresent),
        )
        .err()
        .unwrap_or_else(|| panic!("expected sensitive-header rejection for {header}"));
        assert!(
            error.contains("cannot copy sensitive header"),
            "expected sensitive-header rejection for {header}, got {error}"
        );
    }
}

#[test]
fn credential_class_tag_destinations_are_rejected_separately_from_sources() {
    let error = workload_metrics_new_with_env_lookup_for_test(
        &json!({
            "custom_env_tags": {"session_id": "ISTIO_META_ZONE"}
        }),
        |_| Err(std::env::VarError::NotPresent),
    )
    .err()
    .expect("a credential-class tag name must be refused");
    assert!(error.contains("reserved or sensitive"), "{error}");
}
