//! Tests for GCP Secret Manager secret resolution.

use ferrum_edge::secrets::resolve_secret;

use crate::unit::env_lock::with_env_vars_async;

#[test]
fn test_gcp_ref_conflict_with_direct_value() {
    with_env_vars_async(
        &[
            ("FERRUM_TEST_GCP_A", "direct-value"),
            (
                "FERRUM_TEST_GCP_A_GCP",
                "projects/myproj/secrets/s/versions/latest",
            ),
        ],
        || async {
            let result = resolve_secret("FERRUM_TEST_GCP_A").await;
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.contains("Multiple secret sources"));
        },
    );
}
