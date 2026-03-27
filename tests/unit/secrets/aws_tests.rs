//! Tests for AWS Secrets Manager secret resolution.
//!
//! These test the reference parsing and env var detection logic.
//! Actual AWS connectivity tests require AWS credentials.

use ferrum_gateway::secrets::resolve_secret;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn with_env_vars_async<F, Fut>(vars: &[(&str, &str)], f: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let _guard = ENV_LOCK.lock().unwrap();
    for (k, v) in vars {
        unsafe {
            std::env::set_var(k, v);
        }
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(f());
    for (k, _) in vars {
        unsafe {
            std::env::remove_var(k);
        }
    }
}

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
