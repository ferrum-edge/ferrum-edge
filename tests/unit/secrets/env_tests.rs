use ferrum_edge::secrets::env::resolve;

use crate::unit::env_lock::EnvGuard;

#[test]
fn resolve_returns_value_when_set() {
    let env = EnvGuard::new(&[]);
    let key = "FERRUM_TEST_SECRET_ENV_RESOLVE_SET_12345";
    env.set(key, "my-secret-value");
    assert_eq!(resolve(key), Some("my-secret-value".to_string()));
    env.unset(key);
}

#[test]
fn resolve_returns_none_when_unset() {
    let _env = EnvGuard::new(&[]);
    assert_eq!(resolve("FERRUM_TEST_SECRET_DEFINITELY_NOT_SET_XYZ"), None);
}

#[test]
fn resolve_returns_none_when_empty() {
    let env = EnvGuard::new(&[]);
    let key = "FERRUM_TEST_SECRET_ENV_RESOLVE_EMPTY_12345";
    env.set(key, "");
    assert_eq!(resolve(key), None);
    env.unset(key);
}
