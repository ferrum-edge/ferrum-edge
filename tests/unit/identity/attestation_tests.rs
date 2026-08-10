//! Workload attestor tests.

use super::env_guard::EnvGuard;
use async_trait::async_trait;
use ferrum_edge::identity::attestation::{
    AttestError, Attestor, PeerInfo,
    k8s_psat::{K8sPsatAttestor, K8sPsatAttestorConfig, TokenReviewResult, TokenReviewer},
    spiffe_jwt_svid::{JwtSvidAttestor, JwtSvidAttestorConfig, JwtSvidValidator},
    static_id::{StaticAttestor, StaticAttestorConfig},
    unix::{UnixAttestor, UnixAttestorConfig, UnixIdentityRule, parse_identity_rule},
};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use std::sync::Arc;

// ── K8s PSAT ──────────────────────────────────────────────────────────────

struct MockReviewer {
    result: Result<TokenReviewResult, String>,
}

#[async_trait]
impl TokenReviewer for MockReviewer {
    async fn review(&self, _token: &str) -> Result<TokenReviewResult, String> {
        self.result.clone()
    }
}

#[tokio::test]
async fn k8s_psat_happy_path() {
    let trust_domain = TrustDomain::new("cluster.local").unwrap();
    let reviewer = Arc::new(MockReviewer {
        result: Ok(TokenReviewResult {
            authenticated: true,
            namespace: "production".into(),
            service_account: "ferrum-gateway".into(),
            pod_name: Some("ferrum-gateway-7d8".into()),
            pod_uid: Some("uuid-1".into()),
        }),
    });
    let config = K8sPsatAttestorConfig::istio_default(trust_domain.clone(), reviewer);
    let attestor = K8sPsatAttestor::new(config).unwrap();
    let peer = PeerInfo {
        bearer_token: Some("eyJhbG...test-token".to_string()),
        ..Default::default()
    };
    let identity = attestor.attest(&peer).await.expect("attestation succeeds");
    assert_eq!(
        identity.spiffe_id.as_str(),
        "spiffe://cluster.local/ns/production/sa/ferrum-gateway"
    );
    assert_eq!(
        identity.selectors.get("k8s:namespace"),
        Some(&"production".to_string())
    );
}

#[tokio::test]
async fn k8s_psat_rejects_unauthenticated_token() {
    let trust_domain = TrustDomain::new("cluster.local").unwrap();
    let reviewer = Arc::new(MockReviewer {
        result: Ok(TokenReviewResult {
            authenticated: false,
            namespace: "production".into(),
            service_account: "ferrum-gateway".into(),
            pod_name: None,
            pod_uid: None,
        }),
    });
    let config = K8sPsatAttestorConfig::istio_default(trust_domain, reviewer);
    let attestor = K8sPsatAttestor::new(config).unwrap();
    let peer = PeerInfo {
        bearer_token: Some("not-real".into()),
        ..Default::default()
    };
    let result = attestor.attest(&peer).await;
    assert!(matches!(result, Err(AttestError::Failed(_))));
}

#[tokio::test]
async fn k8s_psat_returns_not_applicable_without_token() {
    let trust_domain = TrustDomain::new("cluster.local").unwrap();
    let reviewer = Arc::new(MockReviewer {
        result: Ok(TokenReviewResult {
            authenticated: true,
            namespace: "production".into(),
            service_account: "ferrum-gateway".into(),
            pod_name: None,
            pod_uid: None,
        }),
    });
    let config = K8sPsatAttestorConfig::istio_default(trust_domain, reviewer);
    let attestor = K8sPsatAttestor::new(config).unwrap();
    let peer = PeerInfo::default();
    let result = attestor.attest(&peer).await;
    assert!(matches!(result, Err(AttestError::NotApplicable)));
}

#[tokio::test]
async fn k8s_psat_enforces_namespace_allowlist() {
    let trust_domain = TrustDomain::new("cluster.local").unwrap();
    let reviewer = Arc::new(MockReviewer {
        result: Ok(TokenReviewResult {
            authenticated: true,
            namespace: "playground".into(),
            service_account: "x".into(),
            pod_name: None,
            pod_uid: None,
        }),
    });
    let config = K8sPsatAttestorConfig {
        trust_domain,
        spiffe_id_template: "spiffe://{trust_domain}/ns/{namespace}/sa/{serviceaccount}"
            .to_string(),
        reviewer,
        allowed_namespaces: vec!["production".into()],
        allowed_service_accounts: Vec::new(),
    };
    let attestor = K8sPsatAttestor::new(config).unwrap();
    let peer = PeerInfo {
        bearer_token: Some("t".into()),
        ..Default::default()
    };
    let result = attestor.attest(&peer).await;
    assert!(matches!(result, Err(AttestError::Failed(_))));
}

#[tokio::test]
async fn k8s_psat_rejects_namespace_with_path_separator() {
    // Defence-in-depth: a TokenReview response that smuggles `/` in the
    // namespace must not produce a wrong-shaped SPIFFE ID via template
    // substitution. The DNS-1123 label check rejects it before substitution.
    let trust_domain = TrustDomain::new("cluster.local").unwrap();
    let reviewer = Arc::new(MockReviewer {
        result: Ok(TokenReviewResult {
            authenticated: true,
            namespace: "evil/sa/admin".into(),
            service_account: "victim".into(),
            pod_name: None,
            pod_uid: None,
        }),
    });
    let config = K8sPsatAttestorConfig::istio_default(trust_domain, reviewer);
    let attestor = K8sPsatAttestor::new(config).unwrap();
    let peer = PeerInfo {
        bearer_token: Some("t".into()),
        ..Default::default()
    };
    let err = attestor.attest(&peer).await.unwrap_err();
    match err {
        AttestError::Failed(msg) => {
            assert!(
                msg.contains("DNS-1123") && msg.contains("namespace"),
                "expected DNS-1123 namespace rejection, got: {msg}"
            );
        }
        other => panic!("expected AttestError::Failed, got {other:?}"),
    }
}

#[tokio::test]
async fn k8s_psat_rejects_serviceaccount_with_uppercase() {
    let trust_domain = TrustDomain::new("cluster.local").unwrap();
    let reviewer = Arc::new(MockReviewer {
        result: Ok(TokenReviewResult {
            authenticated: true,
            namespace: "production".into(),
            service_account: "Capitalized".into(),
            pod_name: None,
            pod_uid: None,
        }),
    });
    let config = K8sPsatAttestorConfig::istio_default(trust_domain, reviewer);
    let attestor = K8sPsatAttestor::new(config).unwrap();
    let peer = PeerInfo {
        bearer_token: Some("t".into()),
        ..Default::default()
    };
    let err = attestor.attest(&peer).await.unwrap_err();
    assert!(matches!(err, AttestError::Failed(ref msg) if msg.contains("service_account")));
}

#[tokio::test]
async fn k8s_psat_rejects_namespace_starting_with_hyphen() {
    let trust_domain = TrustDomain::new("cluster.local").unwrap();
    let reviewer = Arc::new(MockReviewer {
        result: Ok(TokenReviewResult {
            authenticated: true,
            namespace: "-leading-hyphen".into(),
            service_account: "ok".into(),
            pod_name: None,
            pod_uid: None,
        }),
    });
    let config = K8sPsatAttestorConfig::istio_default(trust_domain, reviewer);
    let attestor = K8sPsatAttestor::new(config).unwrap();
    let peer = PeerInfo {
        bearer_token: Some("t".into()),
        ..Default::default()
    };
    let err = attestor.attest(&peer).await.unwrap_err();
    assert!(matches!(err, AttestError::Failed(_)));
}

#[tokio::test]
async fn k8s_psat_accepts_realistic_pod_name() {
    // Realistic pod names like `app-deploy-7b4f6c5dcd-zk8r9` must still pass
    // — they're valid DNS-1123 labels even though they look long.
    let trust_domain = TrustDomain::new("cluster.local").unwrap();
    let reviewer = Arc::new(MockReviewer {
        result: Ok(TokenReviewResult {
            authenticated: true,
            namespace: "production".into(),
            service_account: "app".into(),
            pod_name: Some("app-deploy-7b4f6c5dcd-zk8r9".into()),
            pod_uid: Some("uuid-x".into()),
        }),
    });
    let config = K8sPsatAttestorConfig::istio_default(trust_domain, reviewer);
    let attestor = K8sPsatAttestor::new(config).unwrap();
    let peer = PeerInfo {
        bearer_token: Some("t".into()),
        ..Default::default()
    };
    let identity = attestor
        .attest(&peer)
        .await
        .expect("realistic pod name passes");
    assert_eq!(
        identity.spiffe_id.as_str(),
        "spiffe://cluster.local/ns/production/sa/app"
    );
}

// ── Static ────────────────────────────────────────────────────────────────

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

// ── JWT-SVID federation ───────────────────────────────────────────────────

struct MockJwtValidator {
    return_id: Result<SpiffeId, String>,
}

#[async_trait]
impl JwtSvidValidator for MockJwtValidator {
    async fn validate(&self, _jwt: &str, _audience: &str) -> Result<SpiffeId, String> {
        self.return_id.clone()
    }
}

#[tokio::test]
async fn jwt_svid_attestor_accepts_federated_id() {
    let federated = TrustDomain::new("partner.example").unwrap();
    let id = SpiffeId::new("spiffe://partner.example/ns/foo/sa/bar").unwrap();
    let validator = Arc::new(MockJwtValidator {
        return_id: Ok(id.clone()),
    });
    let attestor = JwtSvidAttestor::new(JwtSvidAttestorConfig {
        federated_trust_domains: vec![federated.clone()],
        audience: "ferrum-mesh".to_string(),
        validator,
    })
    .expect("config valid");
    let peer = PeerInfo {
        bearer_token: Some("aaa.bbb.ccc".into()),
        ..Default::default()
    };
    let result = attestor.attest(&peer).await.expect("federation succeeds");
    assert_eq!(result.spiffe_id, id);
}

#[tokio::test]
async fn jwt_svid_attestor_rejects_non_federated_id() {
    let federated = TrustDomain::new("partner.example").unwrap();
    let id = SpiffeId::new("spiffe://stranger.example/ns/foo").unwrap();
    let validator = Arc::new(MockJwtValidator { return_id: Ok(id) });
    let attestor = JwtSvidAttestor::new(JwtSvidAttestorConfig {
        federated_trust_domains: vec![federated],
        audience: "ferrum-mesh".to_string(),
        validator,
    })
    .unwrap();
    let peer = PeerInfo {
        bearer_token: Some("aaa.bbb.ccc".into()),
        ..Default::default()
    };
    let result = attestor.attest(&peer).await;
    assert!(matches!(result, Err(AttestError::Failed(_))));
}

#[tokio::test]
async fn jwt_svid_attestor_returns_not_applicable_for_non_jwt() {
    let federated = TrustDomain::new("partner.example").unwrap();
    let validator = Arc::new(MockJwtValidator {
        return_id: Err("never called".into()),
    });
    let attestor = JwtSvidAttestor::new(JwtSvidAttestorConfig {
        federated_trust_domains: vec![federated],
        audience: "ferrum-mesh".to_string(),
        validator,
    })
    .unwrap();
    let peer = PeerInfo {
        bearer_token: Some("not-a-jwt".into()),
        ..Default::default()
    };
    let result = attestor.attest(&peer).await;
    assert!(matches!(result, Err(AttestError::NotApplicable)));
}

// ── Unix peer creds ───────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
#[tokio::test]
async fn unix_attestor_matches_uid_rule() {
    let trust_domain = TrustDomain::new("td").unwrap();
    let id = SpiffeId::new("spiffe://td/ns/foo/sa/uid-101").unwrap();
    let cfg = UnixAttestorConfig {
        trust_domain,
        rules: vec![UnixIdentityRule {
            require_uid: Some(101),
            require_binary_sha256: None,
            spiffe_id: id.clone(),
        }],
    };
    let attestor = UnixAttestor::new(cfg).unwrap();
    let peer = PeerInfo {
        pid: Some(0),
        uid: Some(101),
        gid: Some(101),
        ..Default::default()
    };
    let identity = attestor.attest(&peer).await.unwrap();
    assert_eq!(identity.spiffe_id, id);
}

#[tokio::test]
async fn unix_attestor_returns_not_applicable_without_creds() {
    let trust_domain = TrustDomain::new("td").unwrap();
    let id = SpiffeId::new("spiffe://td/ns/foo/sa/no-creds").unwrap();
    let cfg = UnixAttestorConfig {
        trust_domain,
        rules: vec![UnixIdentityRule {
            require_uid: Some(0),
            require_binary_sha256: None,
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
            require_uid: Some(0),
            require_binary_sha256: None,
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

#[test]
fn unix_attestor_rejects_programmatic_rule_without_uid() {
    let trust_domain = TrustDomain::new("td").unwrap();
    let result = UnixAttestor::new(UnixAttestorConfig {
        trust_domain,
        rules: vec![UnixIdentityRule {
            require_uid: None,
            require_binary_sha256: Some("a".repeat(64)),
            spiffe_id: SpiffeId::new("spiffe://td/ns/foo/sa/shared-binary").unwrap(),
        }],
    });

    assert!(
        matches!(result, Err(AttestError::Config(message)) if message.contains("kernel-attested uid"))
    );
}
