//! Tests for DP gRPC client public API.

use ferrum_edge::grpc::dp_client::{DpCpConnectionState, GrpcJwtSecret, generate_dp_jwt};

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
