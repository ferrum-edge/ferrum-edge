use ferrum_edge::plugins::PluginHttpClient;
use ferrum_edge::plugins::utils::jwks_cache::{
    clear_jwks_cache, get_or_create_jwks_store, retain_active_uris,
};
use std::collections::HashSet;
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

#[tokio::test]
async fn test_retain_active_uris_removes_stale_entries() {
    let _guard = cache_test_lock().lock().unwrap();
    clear_jwks_cache();

    let uri_a = "https://issuer-a.example.com/.well-known/jwks.json";
    let uri_b = "https://issuer-b.example.com/.well-known/jwks.json";
    let uri_c = "https://issuer-c.example.com/.well-known/jwks.json";

    let store_a = get_or_create_jwks_store(uri_a, &client(), Duration::from_secs(300));
    let _store_b = get_or_create_jwks_store(uri_b, &client(), Duration::from_secs(300));
    let store_c = get_or_create_jwks_store(uri_c, &client(), Duration::from_secs(300));

    // Keep only A and C — B should be evicted
    let active: HashSet<String> = [uri_a.to_string(), uri_c.to_string()].into();
    retain_active_uris(&active);

    // A and C should still return the same store instances (cache hit)
    let store_a2 = get_or_create_jwks_store(uri_a, &client(), Duration::from_secs(300));
    let store_c2 = get_or_create_jwks_store(uri_c, &client(), Duration::from_secs(300));
    assert!(Arc::ptr_eq(&store_a, &store_a2));
    assert!(Arc::ptr_eq(&store_c, &store_c2));

    // B should be a brand new store (was evicted, recreated on access)
    let store_b2 = get_or_create_jwks_store(uri_b, &client(), Duration::from_secs(300));
    assert!(!Arc::ptr_eq(&_store_b, &store_b2));

    clear_jwks_cache();
}

#[tokio::test]
async fn test_retain_active_uris_empty_set_clears_all() {
    let _guard = cache_test_lock().lock().unwrap();
    clear_jwks_cache();

    let uri = "https://issuer.example.com/.well-known/jwks.json";
    let original = get_or_create_jwks_store(uri, &client(), Duration::from_secs(300));

    // Empty active set — everything should be removed
    retain_active_uris(&HashSet::new());

    let recreated = get_or_create_jwks_store(uri, &client(), Duration::from_secs(300));
    assert!(!Arc::ptr_eq(&original, &recreated));

    clear_jwks_cache();
}
