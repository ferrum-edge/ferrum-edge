use ferrum_edge::plugins::PluginHttpClient;
use ferrum_edge::plugins::utils::jwks_cache::{clear_jwks_cache, get_or_create_jwks_store};
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

fn client() -> PluginHttpClient {
    PluginHttpClient::default()
}

fn cache_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[tokio::test]
async fn test_same_jwks_uri_reuses_cached_store() {
    let _guard = cache_test_lock().lock().unwrap();
    clear_jwks_cache();

    let first = get_or_create_jwks_store(
        "https://issuer.example.com/.well-known/jwks.json",
        &client(),
        Duration::from_secs(300),
    );
    let second = get_or_create_jwks_store(
        "https://issuer.example.com/.well-known/jwks.json",
        &client(),
        Duration::from_secs(30),
    );

    assert!(Arc::ptr_eq(&first, &second));
    clear_jwks_cache();
}

#[tokio::test]
async fn test_different_jwks_uris_get_distinct_store_entries() {
    let _guard = cache_test_lock().lock().unwrap();
    clear_jwks_cache();

    let first = get_or_create_jwks_store(
        "https://issuer-a.example.com/.well-known/jwks.json",
        &client(),
        Duration::from_secs(300),
    );
    let second = get_or_create_jwks_store(
        "https://issuer-b.example.com/.well-known/jwks.json",
        &client(),
        Duration::from_secs(300),
    );

    assert!(!Arc::ptr_eq(&first, &second));
    clear_jwks_cache();
}

#[tokio::test]
async fn test_clear_jwks_cache_forces_store_recreation() {
    let _guard = cache_test_lock().lock().unwrap();
    clear_jwks_cache();

    let first = get_or_create_jwks_store(
        "https://issuer.example.com/.well-known/jwks.json",
        &client(),
        Duration::from_secs(300),
    );
    clear_jwks_cache();
    let second = get_or_create_jwks_store(
        "https://issuer.example.com/.well-known/jwks.json",
        &client(),
        Duration::from_secs(300),
    );

    assert!(!Arc::ptr_eq(&first, &second));
    clear_jwks_cache();
}
