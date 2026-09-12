//! Tests for AWS Secrets Manager secret resolution.
//!
//! These test the reference parsing and env var detection logic.
//! Actual AWS connectivity tests require AWS credentials.

use ferrum_edge::secrets::resolve_secret;

use crate::unit::env_lock::with_env_vars_async;

#[test]
fn test_aws_ref_conflict_with_direct_value() {
    with_env_vars_async(
        &[
            ("FERRUM_TEST_AWS_A", "direct-value"),
            ("FERRUM_TEST_AWS_A_AWS", "my-secret-name"),
        ],
        || async {
            let result = resolve_secret("FERRUM_TEST_AWS_A").await;
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.contains("Multiple secret sources"));
        },
    );
}
