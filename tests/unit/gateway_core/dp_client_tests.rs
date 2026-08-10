//! Tests for DP gRPC client public API.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ferrum_edge::grpc::dp_client::{
    DpCpConnectionState, GrpcJwtSecret, generate_dp_jwt, generate_dp_jwt_with_issuer,
};

#[test]
fn connection_state_new_disconnected() {
    let state = DpCpConnectionState::new_disconnected("http://cp:50051");
    assert!(!state.connected);
    assert_eq!(state.cp_url, "http://cp:50051");
    assert!(state.is_primary);
    assert!(state.last_config_received_at.is_none());
    assert!(state.connected_since.is_none());
}

#[test]
fn grpc_jwt_secret_stores_and_retrieves() {
    let secret = GrpcJwtSecret::new("my-secret-key".to_string());
    assert_eq!(secret.as_str(), "my-secret-key");
}

#[test]
fn grpc_jwt_secret_clone() {
    let secret = GrpcJwtSecret::new("test".to_string());
    let cloned = secret.clone();
    assert_eq!(cloned.as_str(), "test");
}

#[test]
fn grpc_jwt_external_token_errors_do_not_disclose_source_path() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("missing-token-source-sentinel");
    let secret = GrpcJwtSecret::new("unused".to_string())
        .with_token_file(Some(missing.to_string_lossy().into_owned()));
    let error = secret
        .mint("node-1", Some("default"), None)
        .expect_err("a missing external token must fail")
        .to_string();
    assert!(error.contains("failed to read FERRUM_DP_CP_GRPC_TOKEN_FILE"));
    assert!(!error.contains("missing-token-source-sentinel"), "{error}");

    let empty = temp.path().join("empty-token-source-sentinel");
    std::fs::write(&empty, b" \n").unwrap();
    let secret = GrpcJwtSecret::new("unused".to_string())
        .with_token_file(Some(empty.to_string_lossy().into_owned()));
    let error = secret
        .mint("node-1", Some("default"), None)
        .expect_err("an empty external token must fail")
        .to_string();
    assert_eq!(error, "FERRUM_DP_CP_GRPC_TOKEN_FILE is empty");
    assert!(!error.contains("empty-token-source-sentinel"), "{error}");
}

#[test]
fn grpc_jwt_external_token_is_reread_for_every_connection_attempt() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("projected-token");
    std::fs::write(&source, b"first-token\n").unwrap();
    let credential = GrpcJwtSecret::new("unused".to_string())
        .with_token_file(Some(source.to_string_lossy().into_owned()));

    assert_eq!(
        credential.mint("node-1", Some("default"), None).unwrap(),
        "first-token"
    );
    std::fs::write(&source, b"second-token\n").unwrap();
    assert_eq!(
        credential.mint("node-1", Some("default"), None).unwrap(),
        "second-token"
    );
}

#[test]
fn generate_dp_jwt_produces_valid_token() {
    let token = generate_dp_jwt("test-secret", "node-1").unwrap();
    assert!(!token.is_empty());

    // Verify the token can be decoded with the same secret
    let key = jsonwebtoken::DecodingKey::from_secret(b"test-secret");
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_exp = true;
    let decoded = jsonwebtoken::decode::<serde_json::Value>(&token, &key, &validation).unwrap();
    assert_eq!(decoded.claims["sub"], "node-1");
    assert_eq!(decoded.claims["role"], "data_plane");
    assert!(decoded.claims["exp"].is_number());
    assert!(decoded.claims["iat"].is_number());
}

#[test]
fn generate_dp_jwt_different_nodes_produce_different_tokens() {
    let token1 = generate_dp_jwt("secret", "node-1").unwrap();
    let token2 = generate_dp_jwt("secret", "node-2").unwrap();
    assert_ne!(token1, token2);
}

#[test]
fn generate_dp_jwt_wrong_secret_fails_validation() {
    let token = generate_dp_jwt("correct-secret", "node-1").unwrap();
    let key = jsonwebtoken::DecodingKey::from_secret(b"wrong-secret");
    let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    let result = jsonwebtoken::decode::<serde_json::Value>(&token, &key, &validation);
    assert!(result.is_err());
}

/// Default-issuer minting must include the `iss` claim with the documented
/// default. Regression-protects the issuer enforcement security fix: a
/// reverted DP that drops `iss` would silently fail to authenticate to the
/// CP and this test would catch it before deploy.
#[test]
fn generate_dp_jwt_includes_default_iss_claim() {
    let token = generate_dp_jwt("test-secret", "node-1").unwrap();
    let key = jsonwebtoken::DecodingKey::from_secret(b"test-secret");
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_exp = true;
    // Allow any issuer for this decode — we only want to read the claim.
    validation.required_spec_claims = std::collections::HashSet::new();
    let decoded = jsonwebtoken::decode::<serde_json::Value>(&token, &key, &validation).unwrap();
    assert_eq!(decoded.claims["iss"], "ferrum-edge-cp-dp");
}

/// Custom-issuer minting must propagate the operator-supplied issuer into
/// the `iss` claim verbatim.
#[test]
fn generate_dp_jwt_with_custom_issuer_propagates_iss() {
    let token = generate_dp_jwt_with_issuer("test-secret", "node-1", "custom-fleet.cp-dp").unwrap();
    let key = jsonwebtoken::DecodingKey::from_secret(b"test-secret");
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_exp = true;
    validation.required_spec_claims = std::collections::HashSet::new();
    let decoded = jsonwebtoken::decode::<serde_json::Value>(&token, &key, &validation).unwrap();
    assert_eq!(decoded.claims["iss"], "custom-fleet.cp-dp");
}

// --- startup_ready guard for should_race_primary ---

/// Reproduces the exact `is_none_or` + `Acquire` guard used in the reconnect
/// loop to decide whether the primary-retry timer is armed. The timer must
/// NOT fire while the DP has never received a config snapshot (i.e.
/// `startup_ready` is `Some(false)`).
#[test]
fn should_race_primary_blocked_until_startup_ready() {
    // Simulates the three states the reconnect loop can see:

    // 1. None — caller did not pass a startup_ready flag (single-URL path).
    //    Timer should arm because readiness gating is opt-in.
    let none_ready: Option<Arc<AtomicBool>> = None;
    let result = none_ready
        .as_ref()
        .is_none_or(|r| r.load(Ordering::Acquire));
    assert!(result, "None should allow the timer to arm");

    // 2. Some(false) — DP has not yet applied its first snapshot.
    //    Timer must NOT arm; disconnecting from fallback would leave the DP
    //    with zero config.
    let not_ready = Some(Arc::new(AtomicBool::new(false)));
    let result = not_ready.as_ref().is_none_or(|r| r.load(Ordering::Acquire));
    assert!(!result, "Some(false) must block the timer");

    // 3. Some(true) — first snapshot applied (possibly on a previous connection).
    //    Timer should arm; cached config keeps the DP operational.
    let ready = Some(Arc::new(AtomicBool::new(true)));
    let result = ready.as_ref().is_none_or(|r| r.load(Ordering::Acquire));
    assert!(result, "Some(true) should allow the timer to arm");
}

// Note: memory ordering correctness (Acquire/Release on startup_ready) is a
// code-review property, not a unit-testable property on most hardware.
// x86 provides acquire semantics on all loads by default, and thread::spawn +
// join provides a happens-before edge that masks ordering bugs. A cross-thread
// test would pass even with Relaxed and therefore proves nothing. The correct
// ordering is enforced by review: Release in connect_and_subscribe_with_startup_ready,
// Acquire in the should_race_primary guard and the admin /health endpoint.
