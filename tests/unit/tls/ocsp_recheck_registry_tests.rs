//! Private registry tests, compiled by ocsp_recheck under cfg(test). Each test
//! owns its registry so capacity pressure cannot retire another test's staples.

use super::*;
use rustls::server::ResolvesServerCert;
use std::io::Cursor;

fn resolver() -> Arc<AcmeTlsAlpnResolver> {
    let certs = rustls_pemfile::certs(&mut Cursor::new(include_bytes!("../../certs/server.crt")))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut key_pem = Cursor::new(include_bytes!("../../certs/server.key"));
    let key = rustls_pemfile::private_key(&mut key_pem).unwrap().unwrap();
    let key = rustls::crypto::ring::default_provider()
        .key_provider
        .load_private_key(key)
        .unwrap();
    let mut certified = rustls::sign::CertifiedKey::new(certs, key);
    // Acceptance/DER validation is tested separately. These bytes let us
    // observe whether the actual serving resolver still attaches a response.
    certified.ocsp = Some(vec![1, 2, 3]);
    Arc::new(AcmeTlsAlpnResolver::new(Arc::new(certified)))
}

fn has_staple(resolver: &AcmeTlsAlpnResolver) -> bool {
    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    let mut client =
        rustls::ClientConnection::new(Arc::new(client_config), "localhost".try_into().unwrap())
            .unwrap();
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    let mut acceptor = rustls::server::Acceptor::default();
    acceptor.read_tls(&mut Cursor::new(hello)).unwrap();
    let accepted = acceptor
        .accept()
        .map_err(|(error, _)| error)
        .unwrap()
        .unwrap();
    resolver
        .resolve(accepted.client_hello())
        .unwrap()
        .ocsp
        .is_some()
}

fn entry(resolver: &Arc<AcmeTlsAlpnResolver>, source: &str, next_update: i64) -> TrackedStaple {
    TrackedStaple {
        resolver: Arc::downgrade(resolver),
        configured_source_id: source.to_string(),
        display_source_id: "redacted-test-source".to_string(),
        next_update,
        warning_days: 0,
        latest_for_source: true,
    }
}

#[test]
fn capacity_retires_the_oldest_live_resolver_and_keeps_the_bound() {
    let mut state = RegistryState::default();
    let resolvers: Vec<_> = (0..=MAX_TRACKED_STAPLES).map(|_| resolver()).collect();
    for (index, resolver) in resolvers.iter().take(MAX_TRACKED_STAPLES).enumerate() {
        state.register(entry(resolver, &format!("source-{index}"), 200));
    }
    assert_eq!(state.tracked.len(), MAX_TRACKED_STAPLES);
    assert!(resolvers.iter().all(|resolver| has_staple(resolver)));
    assert!(state.dropped.is_empty());

    state.register(entry(&resolvers[MAX_TRACKED_STAPLES], "overflow", 300));
    assert_eq!(state.tracked.len(), MAX_TRACKED_STAPLES);
    assert!(
        !has_staple(&resolvers[0]),
        "eviction must change the serving key"
    );
    assert!(resolvers[1..].iter().all(|resolver| has_staple(resolver)));
    assert_eq!(state.dropped, vec![("source-0".to_string(), 200)]);

    assert_eq!(state.recheck(199, None).dropped, 0);
    assert_eq!(state.recheck(200, None).dropped, MAX_TRACKED_STAPLES - 1);
    assert_eq!(state.tracked.len(), 1);
    assert!(
        resolvers[..MAX_TRACKED_STAPLES]
            .iter()
            .all(|resolver| !has_staple(resolver))
    );
    assert!(has_staple(&resolvers[MAX_TRACKED_STAPLES]));
    assert_eq!(state.recheck(300, None).dropped, 1);
    assert_eq!(state.recheck(301, None), RecheckOutcome::default());
    assert_eq!(state.dropped.len(), MAX_TRACKED_STAPLES);
}

#[test]
fn dead_generations_are_pruned_before_retiring_any_live_staple() {
    let mut state = RegistryState::default();
    let mut resolvers: Vec<_> = (0..MAX_TRACKED_STAPLES).map(|_| resolver()).collect();
    for (index, resolver) in resolvers.iter().enumerate() {
        state.register(entry(resolver, &format!("source-{index}"), 200));
    }
    drop(resolvers.remove(0));
    let newest = resolver();
    state.register(entry(&newest, "newest", 300));
    assert_eq!(state.tracked.len(), MAX_TRACKED_STAPLES);
    assert!(state.dropped.is_empty());
    assert!(resolvers.iter().all(|resolver| has_staple(resolver)));
    assert!(has_staple(&newest));
}

#[test]
fn same_source_eviction_and_expiry_cannot_hide_the_newer_generation() {
    let mut state = RegistryState::default();
    let old = resolver();
    state.register(entry(&old, "same", 200));
    let pinned: Vec<_> = (1..MAX_TRACKED_STAPLES).map(|_| resolver()).collect();
    for (index, resolver) in pinned.iter().enumerate() {
        state.register(entry(resolver, &format!("other-{index}"), 200));
    }
    let new = resolver();
    state.register(entry(&new, "same", 300));
    assert!(!has_staple(&old));
    assert!(has_staple(&new));
    assert!(!state.dropped.iter().any(|(source, _)| source == "same"));
    assert_eq!(state.recheck(200, Some("same")).tracked, 1);
    assert_eq!(state.recheck(300, Some("same")).dropped, 1);
    assert!(state.dropped.contains(&("same".to_string(), 300)));

    // A still-pinned older generation can expire AFTER the newest generation.
    // Its later retirement must not overwrite the newest source deadline.
    let older = resolver();
    let newer = resolver();
    state.register(entry(&older, "reordered", 500));
    state.register(entry(&newer, "reordered", 400));
    state.recheck(400, Some("reordered"));
    state.recheck(500, Some("reordered"));
    assert!(state.dropped.contains(&("reordered".to_string(), 400)));
    assert!(!state.dropped.contains(&("reordered".to_string(), 500)));
}

#[test]
fn an_older_expiry_does_not_report_a_fresh_same_source_staple_as_dropped() {
    let mut state = RegistryState::default();
    let old = resolver();
    let new = resolver();
    state.register(entry(&old, "same", 200));
    state.register(entry(&new, "same", 300));
    assert_eq!(state.recheck(200, None).dropped, 1);
    assert!(!has_staple(&old));
    assert!(has_staple(&new));
    assert!(state.dropped.is_empty());
    assert_eq!(state.recheck(300, None).dropped, 1);
    assert_eq!(state.dropped, vec![("same".to_string(), 300)]);
}

#[test]
fn concurrent_registration_recheck_and_inventory_stay_bounded_and_retire_every_resolver() {
    let registry = Arc::new(Registry::default());
    let barrier = Arc::new(std::sync::Barrier::new(4));
    let (send, receive) = std::sync::mpsc::channel();
    let mut threads = Vec::new();
    for worker in 0..4 {
        let registry = Arc::clone(&registry);
        let barrier = Arc::clone(&barrier);
        let send = send.clone();
        threads.push(std::thread::spawn(move || {
            let mut retained = Vec::new();
            barrier.wait();
            for generation in 0..MAX_TRACKED_STAPLES {
                let resolver = resolver();
                registry.lock().register(entry(
                    &resolver,
                    &format!("source-{worker}-{generation}"),
                    200,
                ));
                assert_eq!(registry.lock().recheck(199, None).dropped, 0);
                let state = registry.lock();
                assert!(state.tracked.len() <= MAX_TRACKED_STAPLES);
                assert!(state.dropped.len() <= MAX_TRACKED_STAPLES);
                drop(state);
                retained.push(resolver);
            }
            send.send(retained).unwrap();
        }));
    }
    let mut retained = Vec::new();
    for _ in 0..4 {
        retained.extend(
            receive
                .recv_timeout(Duration::from_secs(10))
                .expect("no deadlock"),
        );
    }
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(registry.lock().tracked.len(), MAX_TRACKED_STAPLES);
    assert_eq!(registry.lock().recheck(200, None).dropped, MAX_TRACKED_STAPLES);
    assert!(retained.iter().all(|resolver| !has_staple(resolver)));
    assert!(registry.lock().tracked.is_empty());
    assert_eq!(registry.lock().dropped.len(), MAX_TRACKED_STAPLES);
}

#[test]
fn a_poisoned_registry_does_not_disable_retirement_or_enrollment() {
    let registry = Registry::default();
    let old = resolver();
    registry.lock().register(entry(&old, "old", 200));
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _state = registry.lock();
        panic!("poison this isolated registry");
    }));
    let new = resolver();
    registry.lock().register(entry(&new, "new", 300));
    assert_eq!(registry.lock().recheck(200, None).dropped, 1);
    assert!(!has_staple(&old));
    assert!(has_staple(&new));
}
