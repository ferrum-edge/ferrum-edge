//! Workload attestor tests.

use super::env_guard::EnvGuard;
use ferrum_edge::identity::attestation::{
    AttestError, Attestor, PeerInfo,
    static_id::{StaticAttestor, StaticAttestorConfig},
    unix::{UnixAttestor, UnixAttestorConfig, UnixIdentityRule, parse_identity_rule},
};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};

#[test]
fn static_attestor_refuses_without_opt_in() {
    let guard = EnvGuard::new(&["FERRUM_MESH_PRODUCTION_MODE", "FERRUM_MESH_ALLOW_STATIC_ID"]);
    guard.unset("FERRUM_MESH_PRODUCTION_MODE");
    guard.unset("FERRUM_MESH_ALLOW_STATIC_ID");
    let id = SpiffeId::new("spiffe://td/ns/foo").unwrap();
    let result = StaticAttestor::new(StaticAttestorConfig { spiffe_id: id });
    assert!(matches!(result, Err(AttestError::Config(_))));
}

#[test]
fn static_attestor_refuses_in_production() {
    let guard = EnvGuard::new(&["FERRUM_MESH_PRODUCTION_MODE", "FERRUM_MESH_ALLOW_STATIC_ID"]);
    guard.set("FERRUM_MESH_PRODUCTION_MODE", "true");
    guard.set("FERRUM_MESH_ALLOW_STATIC_ID", "true");
    let id = SpiffeId::new("spiffe://td/ns/foo").unwrap();
    let result = StaticAttestor::new(StaticAttestorConfig { spiffe_id: id });
    assert!(matches!(result, Err(AttestError::Config(_))));
}

// Use a synchronous test (not tokio::test) so the env guard is held for the
// whole construction; the async attestor call doesn't need the guard.
#[test]
fn static_attestor_returns_configured_id() {
    let guard = EnvGuard::new(&["FERRUM_MESH_PRODUCTION_MODE", "FERRUM_MESH_ALLOW_STATIC_ID"]);
    guard.unset("FERRUM_MESH_PRODUCTION_MODE");
    guard.set("FERRUM_MESH_ALLOW_STATIC_ID", "true");
    let id = SpiffeId::new("spiffe://td/ns/foo").unwrap();
    let attestor = StaticAttestor::new(StaticAttestorConfig {
        spiffe_id: id.clone(),
    })
    .expect("dev opt-in succeeds");
    drop(guard);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime
        .block_on(attestor.attest(&PeerInfo::default()))
        .unwrap();
    assert_eq!(result.spiffe_id, id);
}

// ── Unix peer creds ───────────────────────────────────────────────────────

#[tokio::test]
async fn unix_attestor_matches_uid_rule() {
    let trust_domain = TrustDomain::new("td").unwrap();
    let id = SpiffeId::new("spiffe://td/ns/foo/sa/uid-101").unwrap();
    let cfg = UnixAttestorConfig {
        trust_domain,
        rules: vec![UnixIdentityRule {
            require_uid: 101,
            spiffe_id: id.clone(),
        }],
    };
    let attestor = UnixAttestor::new(cfg).unwrap();
    let peer = PeerInfo {
        pid: Some(0),
        uid: Some(101),
        gid: Some(101),
    };
    let identity = attestor.attest(&peer).await.unwrap();
    assert_eq!(identity.spiffe_id, id);
}

#[tokio::test]
async fn unix_attestor_refuses_a_peer_whose_uid_matches_no_rule() {
    let trust_domain = TrustDomain::new("td").unwrap();
    let cfg = UnixAttestorConfig {
        trust_domain: trust_domain.clone(),
        rules: vec![
            parse_identity_rule("uid:101=spiffe://td/ns/foo/sa/uid-101", &trust_domain).unwrap(),
        ],
    };
    let attestor = UnixAttestor::new(cfg).unwrap();
    let peer = PeerInfo {
        pid: Some(4242),
        uid: Some(102),
        gid: Some(101),
    };
    let result = attestor.attest(&peer).await;
    assert!(matches!(result, Err(AttestError::Failed(_))));
}

#[tokio::test]
async fn unix_attestor_returns_not_applicable_without_creds() {
    let trust_domain = TrustDomain::new("td").unwrap();
    let id = SpiffeId::new("spiffe://td/ns/foo/sa/no-creds").unwrap();
    let cfg = UnixAttestorConfig {
        trust_domain,
        rules: vec![UnixIdentityRule {
            require_uid: 0,
            spiffe_id: id,
        }],
    };
    let attestor = UnixAttestor::new(cfg).unwrap();
    let peer = PeerInfo::default();
    let result = attestor.attest(&peer).await;
    assert!(matches!(result, Err(AttestError::NotApplicable)));
}

#[tokio::test]
async fn unix_attestor_rejects_rule_outside_trust_domain() {
    let trust_domain = TrustDomain::new("td").unwrap();
    let id = SpiffeId::new("spiffe://other/ns/foo/sa/x").unwrap();
    let result = UnixAttestor::new(UnixAttestorConfig {
        trust_domain,
        rules: vec![UnixIdentityRule {
            require_uid: 0,
            spiffe_id: id,
        }],
    });
    assert!(matches!(result, Err(AttestError::Config(_))));
}

#[test]
fn unix_attestor_rejects_sha256_only_identity_rule() {
    let trust_domain = TrustDomain::new("td").unwrap();
    let entry = format!(
        "sha256:{}=spiffe://td/ns/foo/sa/shared-binary",
        "a".repeat(64)
    );

    let result = parse_identity_rule(&entry, &trust_domain);

    assert!(matches!(result, Err(AttestError::Config(message)) if message.contains("sha256-only")));
}
