//! CP/DP gRPC JWT issuer shape (issue #5554).
//!
//! `jsonwebtoken` matches a multi-valued `iss` by set intersection, so a
//! signed token whose `iss` is an array containing the expected issuer used to
//! authenticate. RFC 7519 §4.1.1 allows exactly one StringOrURI.

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};

use ferrum_edge::grpc::cp_server::DEFAULT_CP_DP_JWT_ISSUER;
use ferrum_edge::grpc::cp_trust::{CpDpVerifier, CpDpVerifierStore, TenantAuthRejectReason};
use ferrum_edge::grpc::dp_client::generate_dp_jwt_with_issuer;
use ferrum_edge::time_compat::UtcTimestamp;

const TEST_SECRET: &str = "test-cp-dp-grpc-jwt-secret-iss-shape";

fn bearer_metadata(token: &str) -> tonic::metadata::MetadataMap {
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert(
        "authorization",
        tonic::metadata::MetadataValue::try_from(format!("Bearer {token}"))
            .expect("bearer token is valid metadata"),
    );
    metadata
}

fn mint_with_iss(iss: Value, subject: &str) -> String {
    let now = UtcTimestamp::now().unix_timestamp();
    let claims = json!({
        "sub": subject,
        "iat": now,
        "exp": now + 3600,
        "iss": iss,
        "role": "data_plane",
    });
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(TEST_SECRET.as_bytes()).unwrap(),
    )
    .expect("test JWT must encode")
}

fn verify(token: &str) -> Result<(), tonic::Status> {
    let store = CpDpVerifierStore::new(CpDpVerifier::SharedSecret(TEST_SECRET.to_string()));
    let snapshot = store.load();
    snapshot
        .verify_and_bind_grpc_identity(
            &bearer_metadata(token),
            DEFAULT_CP_DP_JWT_ISSUER,
            None,
            &store,
        )
        .map(|_| ())
}

#[test]
fn string_iss_matching_expected_issuer_authenticates() {
    let token = generate_dp_jwt_with_issuer(TEST_SECRET, "iss-string", DEFAULT_CP_DP_JWT_ISSUER)
        .expect("string-iss token must mint");
    verify(&token).expect("a plain string iss must still authenticate");
}

#[test]
fn array_iss_containing_expected_issuer_is_rejected() {
    let token = mint_with_iss(json!([DEFAULT_CP_DP_JWT_ISSUER, "other"]), "iss-array");
    let status = verify(&token).expect_err("array iss must not authenticate");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
    assert_eq!(
        status.message(),
        TenantAuthRejectReason::TokenValidation.as_status_message()
    );
    assert!(
        !status.message().contains(DEFAULT_CP_DP_JWT_ISSUER) && !status.message().contains("other"),
        "rejection must not echo the iss claim, got: {}",
        status.message()
    );
}

#[test]
fn object_and_number_iss_are_rejected() {
    for (iss, subject) in [
        (json!({"iss": DEFAULT_CP_DP_JWT_ISSUER}), "iss-object"),
        (json!(42), "iss-number"),
    ] {
        let status =
            verify(&mint_with_iss(iss, subject)).expect_err("non-string iss must not authenticate");
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
        assert_eq!(
            status.message(),
            TenantAuthRejectReason::TokenValidation.as_status_message()
        );
    }
}
