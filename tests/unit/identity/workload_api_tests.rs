//! Workload-API client + server tests.
//!
//! We exercise the in-process service handler directly (without binding a
//! Unix socket) so the test stays portable across the supported targets.
//! End-to-end UDS round-trip tests live in `tests/integration/` (deferred to
//! later phases — Phase A only needs the trait wiring to compile and behave
//! correctly under unit-test scope).

use async_trait::async_trait;
use ferrum_edge::identity::attestation::{Attestor, PeerInfo, WorkloadIdentity};
use ferrum_edge::identity::ca::{
    CaError, CertificateAuthority, IssuanceRequest, PublishedJwtAuthority, PublishedTrustBundle,
    SignedSvid,
};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::identity::workload_api::server::WorkloadApiService;
use std::collections::HashMap;
use std::sync::Arc;
use tonic::Request;

fn workload_request<T>(payload: T) -> Request<T> {
    let mut req = Request::new(payload);
    req.metadata_mut().insert(
        "workload.spiffe.io",
        tonic::metadata::AsciiMetadataValue::from_static("true"),
    );
    req
}

fn workload_request_with_bearer<T>(payload: T, bearer: &str) -> Request<T> {
    let mut req = workload_request(payload);
    let value = format!("Bearer {bearer}");
    req.metadata_mut().insert(
        "authorization",
        tonic::metadata::AsciiMetadataValue::try_from(value.as_str())
            .expect("bearer authorization metadata must be ASCII"),
    );
    req
}

// ── CA stub ──────────────────────────────────────────────────────────────

struct StubCa {
    trust_domain: TrustDomain,
    /// Counter so each issuance produces a different "cert".
    counter: std::sync::atomic::AtomicU64,
}

#[async_trait]
impl CertificateAuthority for StubCa {
    async fn issue_svid(&self, req: IssuanceRequest) -> Result<SignedSvid, CaError> {
        let n = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (id, ttl) = match req {
            IssuanceRequest::Generate {
                spiffe_id,
                ttl_secs,
            } => (spiffe_id, ttl_secs),
            IssuanceRequest::Csr {
                spiffe_id,
                ttl_secs,
                ..
            } => (spiffe_id, ttl_secs),
        };
        Ok(SignedSvid {
            spiffe_id: id,
            cert_chain_der: vec![format!("stub-cert-{n}").into_bytes()],
            private_key_pkcs8_der: b"stub-key".to_vec().into(),
            not_after: chrono::Utc::now() + chrono::Duration::seconds(ttl as i64),
        })
    }

    async fn trust_bundle(&self, td: &TrustDomain) -> Result<PublishedTrustBundle, CaError> {
        if td != &self.trust_domain {
            return Err(CaError::UnknownTrustDomain(td.to_string()));
        }
        Ok(PublishedTrustBundle {
            trust_domain: self.trust_domain.clone(),
            roots_der: vec![b"stub-root".to_vec()],
            refresh_hint_secs: Some(60),
        })
    }

    async fn jwt_authorities(
        &self,
        _td: &TrustDomain,
    ) -> Result<Vec<PublishedJwtAuthority>, CaError> {
        Ok(Vec::new())
    }
}

struct FederatedStubCa {
    trust_domain: TrustDomain,
    federated_roots: HashMap<String, Vec<u8>>,
    counter: std::sync::atomic::AtomicU64,
}

#[async_trait]
impl CertificateAuthority for FederatedStubCa {
    async fn issue_svid(&self, req: IssuanceRequest) -> Result<SignedSvid, CaError> {
        let n = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (id, ttl) = match req {
            IssuanceRequest::Generate {
                spiffe_id,
                ttl_secs,
            } => (spiffe_id, ttl_secs),
            IssuanceRequest::Csr {
                spiffe_id,
                ttl_secs,
                ..
            } => (spiffe_id, ttl_secs),
        };
        Ok(SignedSvid {
            spiffe_id: id,
            cert_chain_der: vec![format!("stub-cert-{n}").into_bytes()],
            private_key_pkcs8_der: b"stub-key".to_vec().into(),
            not_after: chrono::Utc::now() + chrono::Duration::seconds(ttl as i64),
        })
    }

    async fn trust_bundle(&self, td: &TrustDomain) -> Result<PublishedTrustBundle, CaError> {
        if td == &self.trust_domain {
            return Ok(PublishedTrustBundle {
                trust_domain: self.trust_domain.clone(),
                roots_der: vec![b"local-root".to_vec()],
                refresh_hint_secs: Some(60),
            });
        }
        let root = self
            .federated_roots
            .get(td.as_str())
            .ok_or_else(|| CaError::UnknownTrustDomain(td.to_string()))?;
        Ok(PublishedTrustBundle {
            trust_domain: td.clone(),
            roots_der: vec![root.clone()],
            refresh_hint_secs: Some(60),
        })
    }

    async fn jwt_authorities(
        &self,
        _td: &TrustDomain,
    ) -> Result<Vec<PublishedJwtAuthority>, CaError> {
        Ok(Vec::new())
    }
}

// ── Stub attestor ────────────────────────────────────────────────────────

struct StubAttestor {
    id: SpiffeId,
}

#[async_trait]
impl Attestor for StubAttestor {
    fn kind(&self) -> &'static str {
        "stub"
    }
    async fn attest(
        &self,
        _peer: &PeerInfo,
    ) -> Result<WorkloadIdentity, ferrum_edge::identity::attestation::AttestError> {
        Ok(WorkloadIdentity {
            spiffe_id: self.id.clone(),
            selectors: HashMap::new(),
            attestor_kind: "stub".to_string(),
        })
    }
}

struct CountingAttestor {
    id: SpiffeId,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl Attestor for CountingAttestor {
    fn kind(&self) -> &'static str {
        "counting"
    }

    async fn attest(
        &self,
        _peer: &PeerInfo,
    ) -> Result<WorkloadIdentity, ferrum_edge::identity::attestation::AttestError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(WorkloadIdentity {
            spiffe_id: self.id.clone(),
            selectors: HashMap::new(),
            attestor_kind: "counting".to_string(),
        })
    }
}

/// Stateful attestor whose successive calls return scripted outcomes.
/// Used to model revocation and identity remapping across rotation epochs.
struct ScriptedAttestor {
    outcomes: Arc<
        std::sync::Mutex<Vec<Result<SpiffeId, ferrum_edge::identity::attestation::AttestError>>>,
    >,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl ScriptedAttestor {
    fn new(
        outcomes: Vec<Result<SpiffeId, ferrum_edge::identity::attestation::AttestError>>,
    ) -> Self {
        Self {
            outcomes: Arc::new(std::sync::Mutex::new(outcomes)),
            calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}

#[async_trait]
impl Attestor for ScriptedAttestor {
    fn kind(&self) -> &'static str {
        "scripted"
    }

    async fn attest(
        &self,
        _peer: &PeerInfo,
    ) -> Result<WorkloadIdentity, ferrum_edge::identity::attestation::AttestError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let next = {
            let mut guard = self
                .outcomes
                .lock()
                .expect("scripted attestor mutex poisoned");
            if guard.is_empty() {
                return Err(ferrum_edge::identity::attestation::AttestError::Failed(
                    "scripted attestor exhausted".to_string(),
                ));
            }
            guard.remove(0)
        };
        next.map(|spiffe_id| WorkloadIdentity {
            spiffe_id,
            selectors: HashMap::new(),
            attestor_kind: "scripted".to_string(),
        })
    }
}

/// Attestor that records the peer identity presented on every call and only
/// succeeds when the bearer matches the expected retained transport identity.
struct PeerRecordingAttestor {
    id: SpiffeId,
    expected_bearer: String,
    seen_bearers: Arc<std::sync::Mutex<Vec<Option<String>>>>,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl Attestor for PeerRecordingAttestor {
    fn kind(&self) -> &'static str {
        "peer_recording"
    }

    async fn attest(
        &self,
        peer: &PeerInfo,
    ) -> Result<WorkloadIdentity, ferrum_edge::identity::attestation::AttestError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.seen_bearers
            .lock()
            .expect("peer recording mutex poisoned")
            .push(peer.bearer_token.clone());
        match peer.bearer_token.as_deref() {
            Some(token) if token == self.expected_bearer => Ok(WorkloadIdentity {
                spiffe_id: self.id.clone(),
                selectors: HashMap::new(),
                attestor_kind: "peer_recording".to_string(),
            }),
            _ => Err(ferrum_edge::identity::attestation::AttestError::Failed(
                "peer identity mismatch".to_string(),
            )),
        }
    }
}

/// Attestor that always fails — used to pin the bundle-only entitlement
/// boundary (public trust material must not require attestation).
struct AlwaysDenyAttestor;

#[async_trait]
impl Attestor for AlwaysDenyAttestor {
    fn kind(&self) -> &'static str {
        "always_deny"
    }

    async fn attest(
        &self,
        _peer: &PeerInfo,
    ) -> Result<WorkloadIdentity, ferrum_edge::identity::attestation::AttestError> {
        Err(ferrum_edge::identity::attestation::AttestError::Failed(
            "revoked".to_string(),
        ))
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn workload_api_service_constructs_with_attestor_and_ca() {
    let trust_domain = TrustDomain::new("td.test").unwrap();
    let ca: Arc<dyn CertificateAuthority> = Arc::new(StubCa {
        trust_domain: trust_domain.clone(),
        counter: std::sync::atomic::AtomicU64::new(0),
    });
    let id = SpiffeId::from_parts(&trust_domain, "ns/test/sa/foo").unwrap();
    let attestor: Arc<dyn Attestor> = Arc::new(StubAttestor { id: id.clone() });

    let svc = WorkloadApiService::new(vec![attestor], ca, trust_domain.clone(), 600);
    assert_eq!(svc.trust_domain, trust_domain);
    assert_eq!(svc.svid_ttl_secs, 600);
    assert_eq!(svc.attestors.len(), 1);
}

#[tokio::test]
async fn workload_api_streams_federated_x509_bundles() {
    use ferrum_edge::identity::workload_api::proto::X509BundlesRequest;
    use ferrum_edge::identity::workload_api::proto::X509svidRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use tokio_stream::StreamExt;

    let trust_domain = TrustDomain::new("td.test").unwrap();
    let partner_domain = TrustDomain::new("partner.test").unwrap();
    let ca: Arc<dyn CertificateAuthority> = Arc::new(FederatedStubCa {
        trust_domain: trust_domain.clone(),
        federated_roots: HashMap::from([(
            partner_domain.as_str().to_string(),
            b"partner-root".to_vec(),
        )]),
        counter: std::sync::atomic::AtomicU64::new(0),
    });
    let id = SpiffeId::from_parts(&trust_domain, "ns/test/sa/foo").unwrap();
    let attestor: Arc<dyn Attestor> = Arc::new(StubAttestor { id });
    let svc = WorkloadApiService::new(vec![attestor], ca, trust_domain.clone(), 600)
        .with_federated_trust_domains(vec![partner_domain.clone()]);

    let svid_resp = svc
        .fetch_x509svid(workload_request(X509svidRequest {}))
        .await
        .unwrap();
    let svid_msg = svid_resp
        .into_inner()
        .next()
        .await
        .expect("x509 svid response")
        .expect("x509 svid success");
    assert_eq!(
        svid_msg
            .federated_bundles
            .get(partner_domain.as_str())
            .map(Vec::as_slice),
        Some(&b"partner-root"[..])
    );

    let bundle_resp = svc
        .fetch_x509_bundles(workload_request(X509BundlesRequest {}))
        .await
        .unwrap();
    let bundle_msg = bundle_resp
        .into_inner()
        .next()
        .await
        .expect("x509 bundles response")
        .expect("x509 bundles success");
    assert_eq!(
        bundle_msg
            .bundles
            .get(trust_domain.as_str())
            .map(Vec::as_slice),
        Some(&b"local-root"[..])
    );
    assert_eq!(
        bundle_msg
            .bundles
            .get(partner_domain.as_str())
            .map(Vec::as_slice),
        Some(&b"partner-root"[..])
    );
}

#[tokio::test]
async fn attest_chain_returns_first_success() {
    use ferrum_edge::identity::attestation::{AttestError, attest_chain};
    let id = SpiffeId::new("spiffe://td/ns/foo").unwrap();

    struct Skip;
    #[async_trait::async_trait]
    impl Attestor for Skip {
        fn kind(&self) -> &'static str {
            "skip"
        }
        async fn attest(&self, _: &PeerInfo) -> Result<WorkloadIdentity, AttestError> {
            Err(AttestError::NotApplicable)
        }
    }

    let attestors: Vec<Arc<dyn Attestor>> =
        vec![Arc::new(Skip), Arc::new(StubAttestor { id: id.clone() })];
    let result = attest_chain(&attestors, &PeerInfo::default())
        .await
        .unwrap();
    assert_eq!(result.spiffe_id, id);
}

#[tokio::test]
async fn attest_chain_aggregates_failures() {
    use ferrum_edge::identity::attestation::{AttestError, attest_chain};

    struct Skip;
    #[async_trait::async_trait]
    impl Attestor for Skip {
        fn kind(&self) -> &'static str {
            "skip"
        }
        async fn attest(&self, _: &PeerInfo) -> Result<WorkloadIdentity, AttestError> {
            Err(AttestError::NotApplicable)
        }
    }

    let attestors: Vec<Arc<dyn Attestor>> = vec![Arc::new(Skip), Arc::new(Skip)];
    let result = attest_chain(&attestors, &PeerInfo::default()).await;
    assert!(matches!(result, Err(AttestError::Failed(_))));
}

#[tokio::test]
async fn attest_chain_rejects_empty() {
    use ferrum_edge::identity::attestation::{AttestError, attest_chain};
    let attestors: Vec<Arc<dyn Attestor>> = Vec::new();
    let result = attest_chain(&attestors, &PeerInfo::default()).await;
    assert!(matches!(result, Err(AttestError::Config(_))));
}

// ── SvidFetchHandle::wait_for_first_svid race regression ─────────────────

/// Build a minimally-valid `SvidBundle` for handle tests. The `install`
/// path doesn't inspect contents, so the cert/key are placeholder bytes.
fn dummy_bundle() -> ferrum_edge::identity::SvidBundle {
    use ferrum_edge::identity::{SvidBundle, TrustBundle, TrustBundleSet};
    let id = SpiffeId::new("spiffe://td.test/ns/foo/sa/bar").unwrap();
    let trust_domain = TrustDomain::new("td.test").unwrap();
    SvidBundle {
        spiffe_id: id,
        cert_chain_der: vec![b"placeholder-cert".to_vec()],
        private_key_pkcs8_der: b"placeholder-key".to_vec().into(),
        trust_bundles: TrustBundleSet {
            local: TrustBundle {
                trust_domain,
                x509_authorities: vec![b"placeholder-ca".to_vec()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: Default::default(),
        },
    }
}

#[tokio::test]
async fn wait_for_first_svid_returns_immediately_after_install() {
    use ferrum_edge::identity::workload_api::fetch_loop::{SvidFetchHandle, install_test_bundle};
    use std::time::Duration;

    let handle = SvidFetchHandle::new();
    install_test_bundle(&handle, dummy_bundle());

    // Already installed → must return without blocking.
    tokio::time::timeout(Duration::from_secs(2), handle.wait_for_first_svid())
        .await
        .expect("wait_for_first_svid should return immediately when already installed");
}

#[tokio::test]
async fn wait_for_first_svid_wakes_on_subsequent_install() {
    use ferrum_edge::identity::workload_api::fetch_loop::{SvidFetchHandle, install_test_bundle};
    use std::time::Duration;

    let handle = SvidFetchHandle::new();
    let h2 = handle.clone();

    // Spawn the waiter first. It must register as a waiter via the
    // `Notified::enable()` pattern so the install below cannot race past it.
    let waiter = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(3), h2.wait_for_first_svid())
            .await
            .expect("wait_for_first_svid timed out — lost-notify race")
    });

    // Yield once so the waiter has a real chance to be polled, then install.
    tokio::task::yield_now().await;
    install_test_bundle(&handle, dummy_bundle());

    waiter.await.expect("waiter task panicked");
}

#[tokio::test]
async fn wait_for_first_svid_no_deadlock_under_concurrent_install_storm() {
    // Stress the race window by hammering install() against many parallel
    // waiters. Each waiter must complete within the timeout. With the
    // pre-fix code (load-then-await) at least one of these would block
    // forever; with the fix all waiters wake.
    use ferrum_edge::identity::workload_api::fetch_loop::{SvidFetchHandle, install_test_bundle};
    use std::time::Duration;

    let handle = SvidFetchHandle::new();
    let mut waiters = Vec::new();
    for _ in 0..32 {
        let h = handle.clone();
        waiters.push(tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(3), h.wait_for_first_svid())
                .await
                .expect("wait_for_first_svid race regressed")
        }));
    }
    tokio::task::yield_now().await;
    install_test_bundle(&handle, dummy_bundle());
    for w in waiters {
        w.await.expect("waiter task panicked");
    }
}

#[tokio::test]
async fn revision_tx_attached_after_clone_is_seen_by_installer_clone() {
    use ferrum_edge::identity::workload_api::fetch_loop::{SvidFetchHandle, install_test_bundle};
    use tokio::sync::watch;

    let handle = SvidFetchHandle::new();
    let installer_handle = handle.clone();
    let (revision_tx, mut revision_rx) = watch::channel(0u64);

    let _configured_handle = handle.with_revision_tx(revision_tx);

    install_test_bundle(&installer_handle, dummy_bundle());
    assert_eq!(
        *revision_rx.borrow(),
        0,
        "first SVID install should not publish a rotation revision"
    );

    install_test_bundle(&installer_handle, dummy_bundle());
    revision_rx
        .changed()
        .await
        .expect("revision sender should remain configured on cloned handle state");
    assert_eq!(*revision_rx.borrow_and_update(), 1);
}

// ── Long-lived stream + rotation signal tests ──────────────────────────────

#[tokio::test]
async fn fetch_x509svid_stream_stays_open_and_pushes_on_rotation() {
    use ferrum_edge::identity::workload_api::server::WorkloadApiService;
    use std::sync::Arc;
    use tokio::sync::watch;

    let trust_domain = TrustDomain::new("td.test").unwrap();
    let ca: Arc<dyn ferrum_edge::identity::ca::CertificateAuthority> = Arc::new(StubCa {
        trust_domain: trust_domain.clone(),
        counter: std::sync::atomic::AtomicU64::new(0),
    });
    let id = SpiffeId::from_parts(&trust_domain, "ns/test/sa/foo").unwrap();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let attestor: Arc<dyn ferrum_edge::identity::attestation::Attestor> =
        Arc::new(CountingAttestor {
            id,
            calls: Arc::clone(&calls),
        });

    let (tx, _) = watch::channel(0u64);
    let rotation = Arc::new(tx);
    let svc = WorkloadApiService::with_rotation_signal(
        vec![attestor],
        ca,
        trust_domain,
        600,
        Arc::clone(&rotation),
    );

    use ferrum_edge::identity::workload_api::proto::X509svidRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use tokio_stream::StreamExt;

    let resp = svc
        .fetch_x509svid(workload_request(X509svidRequest {}))
        .await
        .unwrap();
    let mut stream = resp.into_inner();

    // First message arrives immediately.
    let first = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for first message")
        .expect("stream ended unexpectedly")
        .expect("first message was an error");
    assert!(!first.svids.is_empty());
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Bump the rotation epoch — stream should re-attest and push a second message.
    rotation.send_modify(|v| *v += 1);

    let second = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for rotation push")
        .expect("stream ended unexpectedly")
        .expect("rotation push was an error");
    assert!(!second.svids.is_empty());
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "rotation must re-run the attestor chain before minting"
    );
}

#[tokio::test]
async fn fetch_x509svid_rotation_denies_after_entitlement_revocation() {
    use ferrum_edge::identity::attestation::AttestError;
    use ferrum_edge::identity::workload_api::proto::X509svidRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use ferrum_edge::identity::workload_api::server::WorkloadApiService;
    use tokio::sync::watch;
    use tokio_stream::StreamExt;
    use tonic::Code;

    let trust_domain = TrustDomain::new("td.test").unwrap();
    let ca: Arc<dyn ferrum_edge::identity::ca::CertificateAuthority> = Arc::new(StubCa {
        trust_domain: trust_domain.clone(),
        counter: std::sync::atomic::AtomicU64::new(0),
    });
    let id = SpiffeId::from_parts(&trust_domain, "ns/a/sa/b").unwrap();
    let scripted = Arc::new(ScriptedAttestor::new(vec![
        Ok(id),
        Err(AttestError::Failed("psat revoked".to_string())),
    ]));
    let calls = Arc::clone(&scripted.calls);
    let attestor: Arc<dyn ferrum_edge::identity::attestation::Attestor> = scripted;

    let (tx, _) = watch::channel(0u64);
    let rotation = Arc::new(tx);
    let svc = WorkloadApiService::with_rotation_signal(
        vec![attestor],
        ca,
        trust_domain,
        600,
        Arc::clone(&rotation),
    );

    let resp = svc
        .fetch_x509svid(workload_request(X509svidRequest {}))
        .await
        .unwrap();
    let mut stream = resp.into_inner();

    let first = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for first message")
        .expect("stream ended unexpectedly")
        .expect("first message was an error");
    assert_eq!(first.svids.len(), 1);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

    rotation.send_modify(|v| *v += 1);

    let denied = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for entitlement denial")
        .expect("stream ended without PermissionDenied status");
    let err = denied.expect_err("revoked entitlement must not mint a rotated SVID");
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);

    // Stream must terminate after the authorization status — no endless retry.
    let closed = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for stream close");
    assert!(closed.is_none(), "stream must close after PermissionDenied");
}

#[tokio::test]
async fn fetch_x509svid_rotation_reattests_retained_peer_identity() {
    use ferrum_edge::identity::workload_api::proto::X509svidRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use ferrum_edge::identity::workload_api::server::WorkloadApiService;
    use tokio::sync::watch;
    use tokio_stream::StreamExt;

    // Rotation must revalidate using the retained authenticated peer/transport
    // identity from stream open — not a cached SPIFFE ID alone.
    let trust_domain = TrustDomain::new("td.test").unwrap();
    let ca: Arc<dyn ferrum_edge::identity::ca::CertificateAuthority> = Arc::new(StubCa {
        trust_domain: trust_domain.clone(),
        counter: std::sync::atomic::AtomicU64::new(0),
    });
    let id = SpiffeId::from_parts(&trust_domain, "ns/peer/sa/check").unwrap();
    let expected_bearer = "retained-peer-psat".to_string();
    let seen_bearers = Arc::new(std::sync::Mutex::new(Vec::new()));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let attestor: Arc<dyn ferrum_edge::identity::attestation::Attestor> =
        Arc::new(PeerRecordingAttestor {
            id,
            expected_bearer: expected_bearer.clone(),
            seen_bearers: Arc::clone(&seen_bearers),
            calls: Arc::clone(&calls),
        });

    let (tx, _) = watch::channel(0u64);
    let rotation = Arc::new(tx);
    let svc = WorkloadApiService::with_rotation_signal(
        vec![attestor],
        ca,
        trust_domain,
        600,
        Arc::clone(&rotation),
    );

    let resp = svc
        .fetch_x509svid(workload_request_with_bearer(
            X509svidRequest {},
            &expected_bearer,
        ))
        .await
        .unwrap();
    let mut stream = resp.into_inner();

    let first = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for first message")
        .expect("stream ended unexpectedly")
        .expect("first message was an error");
    assert_eq!(first.svids.len(), 1);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

    rotation.send_modify(|v| *v += 1);

    let second = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for peer-revalidated rotation push")
        .expect("stream ended unexpectedly")
        .expect("rotation push was an error");
    assert_eq!(second.svids.len(), 1);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);

    let seen = seen_bearers
        .lock()
        .expect("peer recording mutex poisoned")
        .clone();
    assert_eq!(
        seen,
        vec![Some(expected_bearer.clone()), Some(expected_bearer.clone())],
        "each rotation epoch must re-attest the retained peer bearer identity"
    );
}

#[tokio::test]
async fn fetch_x509svid_rotation_reflects_identity_change() {
    use ferrum_edge::identity::workload_api::proto::X509svidRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use ferrum_edge::identity::workload_api::server::WorkloadApiService;
    use tokio::sync::watch;
    use tokio_stream::StreamExt;

    let trust_domain = TrustDomain::new("td.test").unwrap();
    let ca: Arc<dyn ferrum_edge::identity::ca::CertificateAuthority> = Arc::new(StubCa {
        trust_domain: trust_domain.clone(),
        counter: std::sync::atomic::AtomicU64::new(0),
    });
    let id_a = SpiffeId::from_parts(&trust_domain, "ns/a/sa/b").unwrap();
    let id_b = SpiffeId::from_parts(&trust_domain, "ns/c/sa/d").unwrap();
    let expected_a = id_a.to_string();
    let expected_b = id_b.to_string();
    let attestor: Arc<dyn ferrum_edge::identity::attestation::Attestor> =
        Arc::new(ScriptedAttestor::new(vec![Ok(id_a), Ok(id_b)]));

    let (tx, _) = watch::channel(0u64);
    let rotation = Arc::new(tx);
    let svc = WorkloadApiService::with_rotation_signal(
        vec![attestor],
        ca,
        trust_domain,
        600,
        Arc::clone(&rotation),
    );

    let resp = svc
        .fetch_x509svid(workload_request(X509svidRequest {}))
        .await
        .unwrap();
    let mut stream = resp.into_inner();

    let first = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for first message")
        .expect("stream ended unexpectedly")
        .expect("first message was an error");
    assert_eq!(first.svids[0].spiffe_id, expected_a);

    rotation.send_modify(|v| *v += 1);

    let second = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for identity-changed rotation push")
        .expect("stream ended unexpectedly")
        .expect("rotation push was an error");
    assert_eq!(
        second.svids[0].spiffe_id, expected_b,
        "rotated response must reflect the re-attested identity"
    );
}

#[tokio::test]
async fn fetch_x509_bundles_skips_attestor_entitlement_checks() {
    use ferrum_edge::identity::workload_api::proto::X509BundlesRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use ferrum_edge::identity::workload_api::server::WorkloadApiService;
    use tokio::sync::watch;
    use tokio_stream::StreamExt;

    // Bundle-only contract: public CA trust material is served without
    // running the attestor chain. A denying attestor must not block bundles,
    // and rotation must not invoke attestation either.
    let trust_domain = TrustDomain::new("td.test").unwrap();
    let ca: Arc<dyn ferrum_edge::identity::ca::CertificateAuthority> = Arc::new(StubCa {
        trust_domain: trust_domain.clone(),
        counter: std::sync::atomic::AtomicU64::new(0),
    });
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counting: Arc<dyn ferrum_edge::identity::attestation::Attestor> =
        Arc::new(CountingAttestor {
            id: SpiffeId::from_parts(&trust_domain, "ns/unused/sa/unused").unwrap(),
            calls: Arc::clone(&calls),
        });
    let denying: Arc<dyn ferrum_edge::identity::attestation::Attestor> =
        Arc::new(AlwaysDenyAttestor);

    let (tx, _) = watch::channel(0u64);
    let rotation = Arc::new(tx);
    let svc = WorkloadApiService::with_rotation_signal(
        vec![denying, counting],
        ca,
        trust_domain.clone(),
        600,
        Arc::clone(&rotation),
    );

    let resp = svc
        .fetch_x509_bundles(workload_request(X509BundlesRequest {}))
        .await
        .expect("bundle-only streams must not require attestor entitlement");
    let mut stream = resp.into_inner();

    let first = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for first bundle message")
        .expect("stream ended unexpectedly")
        .expect("first bundle message was an error");
    assert!(
        first.bundles.contains_key(trust_domain.as_str()),
        "local trust domain bundle must be present"
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);

    rotation.send_modify(|v| *v += 1);

    let second = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for bundle rotation push")
        .expect("stream ended unexpectedly")
        .expect("bundle rotation push was an error");
    assert!(second.bundles.contains_key(trust_domain.as_str()));
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "FetchX509Bundles must not run attestors on open or rotation"
    );
}

#[tokio::test]
async fn fetch_x509svid_rejects_missing_workload_metadata_before_attestation() {
    use ferrum_edge::identity::workload_api::proto::X509svidRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use tonic::Code;

    let trust_domain = TrustDomain::new("td.test").unwrap();
    let ca = Arc::new(StubCa {
        trust_domain: trust_domain.clone(),
        counter: std::sync::atomic::AtomicU64::new(0),
    });
    let id = SpiffeId::from_parts(&trust_domain, "ns/test/sa/foo").unwrap();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let attestor: Arc<dyn ferrum_edge::identity::attestation::Attestor> =
        Arc::new(CountingAttestor {
            id,
            calls: Arc::clone(&calls),
        });

    let svc = WorkloadApiService::new(vec![attestor], ca, trust_domain, 600);
    let err = match svc.fetch_x509svid(Request::new(X509svidRequest {})).await {
        Ok(_) => panic!("missing workload metadata must be rejected"),
        Err(err) => err,
    };

    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn fetch_x509svid_rotation_task_exits_when_client_drops_stream() {
    use ferrum_edge::identity::workload_api::proto::X509svidRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use tokio::sync::watch;
    use tokio_stream::StreamExt;

    let trust_domain = TrustDomain::new("td.test").unwrap();
    let ca: Arc<dyn ferrum_edge::identity::ca::CertificateAuthority> = Arc::new(StubCa {
        trust_domain: trust_domain.clone(),
        counter: std::sync::atomic::AtomicU64::new(0),
    });
    let id = SpiffeId::from_parts(&trust_domain, "ns/test/sa/foo").unwrap();
    let attestor: Arc<dyn ferrum_edge::identity::attestation::Attestor> =
        Arc::new(StubAttestor { id });

    let (tx, _) = watch::channel(0u64);
    let rotation = Arc::new(tx);
    let svc = WorkloadApiService::with_rotation_signal(
        vec![attestor],
        ca,
        trust_domain,
        600,
        Arc::clone(&rotation),
    );

    let resp = svc
        .fetch_x509svid(workload_request(X509svidRequest {}))
        .await
        .unwrap();
    let mut stream = resp.into_inner();
    let _first = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for first message")
        .expect("stream ended unexpectedly")
        .expect("first message was an error");
    assert_eq!(rotation.receiver_count(), 1);

    drop(stream);

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while rotation.receiver_count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("rotation stream task did not exit after client dropped stream");
}
