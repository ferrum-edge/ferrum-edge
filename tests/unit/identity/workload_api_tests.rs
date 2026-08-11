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
        .with_federated_trust_domains(vec![partner_domain.clone()])
        .expect("one federated trust domain is within the configured cap");

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

#[cfg(unix)]
#[tokio::test]
async fn spire_fetch_loop_publishes_unhealthy_ca_and_spire_source_on_connect_failure() {
    use ferrum_edge::identity::workload_api::{
        FetchLoopConfig, FetchLoopMetricsSource, spawn_fetch_loop,
    };
    use ferrum_edge::plugins::prometheus_metrics::MetricsRegistry;
    use std::time::Duration;

    let temp = tempfile::tempdir().expect("create isolated missing-socket directory");
    let config = FetchLoopConfig {
        socket_path: temp
            .path()
            .join("missing-agent.sock")
            .to_string_lossy()
            .into_owned(),
        reconnect_backoff: Duration::from_secs(30),
        max_reconnect_backoff: Duration::from_secs(30),
        metrics_source: FetchLoopMetricsSource::SpireAgent,
        ..Default::default()
    };
    let (_handle, join) = spawn_fetch_loop(config);

    let observed = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let output = MetricsRegistry::new().render_uncached();
            let ca_unhealthy = output.lines().any(|line| {
                line.contains("ferrum_mesh_ca_health{")
                    && line.contains("ca_type=\"spire_agent\"")
                    && line.ends_with("} 0")
            });
            let spire_failure = output.lines().any(|line| {
                line.contains("ferrum_mesh_cert_rotation_failures_total{")
                    && line.contains("spiffe_id=\"unknown\"")
                    && line.contains("source=\"spire_agent\"")
            });
            if ca_unhealthy && spire_failure {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    join.abort();

    observed.expect("SPIRE fetch-loop outage telemetry was not published");
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

/// A CA backend with no JWT authority at all (the `StubCa` here, and in
/// production `FERRUM_MESH_CA_BACKEND=spire`, whose agent streams carry only
/// X.509 authorities) must fail closed with `UNIMPLEMENTED` on every JWT RPC.
///
/// `FetchJWTBundles` in particular must not return `Ok(stream)`: SPIFFE
/// Workload API §6.2.2 requires at least the local trust-domain JWT bundle, so
/// an empty `bundles` map reads as "zero trusted JWT authorities" rather than
/// "unsupported". Backends that *do* own a JWT authority are covered in
/// `jwt_svid_tests.rs`.
#[tokio::test]
async fn jwt_svid_rpcs_return_unimplemented_when_backend_has_no_jwt_authority() {
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use ferrum_edge::identity::workload_api::proto::{
        JwtBundlesRequest, JwtsvidRequest, ValidateJwtsvidRequest,
    };
    use tonic::Code;

    let trust_domain = TrustDomain::new("td.test").unwrap();
    let ca: Arc<dyn ferrum_edge::identity::ca::CertificateAuthority> = Arc::new(StubCa {
        trust_domain: trust_domain.clone(),
        counter: std::sync::atomic::AtomicU64::new(0),
    });
    let id = SpiffeId::from_parts(&trust_domain, "ns/test/sa/foo").unwrap();
    let attestor: Arc<dyn ferrum_edge::identity::attestation::Attestor> =
        Arc::new(StubAttestor { id });
    let svc = WorkloadApiService::new(vec![attestor], ca, trust_domain, 600);

    let mint_err = match svc
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["aud".to_string()],
            spiffe_id: String::new(),
        }))
        .await
    {
        Ok(_) => panic!("FetchJWTSVID must not mint without a JWT signing authority"),
        Err(err) => err,
    };
    assert_eq!(mint_err.code(), Code::Unimplemented);
    assert!(
        mint_err.message().contains("cannot mint JWT-SVIDs"),
        "mint error should name the missing signing authority (got: {})",
        mint_err.message()
    );

    // Critical: FetchJWTBundles must fail closed at the RPC boundary — never
    // return Ok(stream) of empty maps that look like "zero JWT authorities".
    let bundles_err = match svc
        .fetch_jwt_bundles(workload_request(JwtBundlesRequest {}))
        .await
    {
        Ok(_) => panic!("FetchJWTBundles must return UNIMPLEMENTED, not an empty bundle stream"),
        Err(err) => err,
    };
    assert_eq!(bundles_err.code(), Code::Unimplemented);
    assert!(
        bundles_err.message().contains("no JWT authority"),
        "bundles error should name the missing authority (got: {})",
        bundles_err.message()
    );

    let validate_err = match svc
        .validate_jwtsvid(workload_request(ValidateJwtsvidRequest {
            audience: "aud".to_string(),
            svid: "eyJhbGciOiJIUzI1NiJ9.e30.signature".to_string(),
        }))
        .await
    {
        Ok(_) => panic!("ValidateJWTSVID must not succeed without a JWT authority"),
        Err(err) => err,
    };
    assert_eq!(validate_err.code(), Code::Unimplemented);
    assert!(
        validate_err.message().contains("no JWT authority"),
        "validate error should name the missing authority (got: {})",
        validate_err.message()
    );
}

#[tokio::test]
async fn jwt_svid_rpcs_reject_missing_workload_metadata_before_unimplemented() {
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use ferrum_edge::identity::workload_api::proto::{
        JwtBundlesRequest, JwtsvidRequest, ValidateJwtsvidRequest,
    };
    use tonic::Code;

    let trust_domain = TrustDomain::new("td.test").unwrap();
    let ca: Arc<dyn ferrum_edge::identity::ca::CertificateAuthority> = Arc::new(StubCa {
        trust_domain: trust_domain.clone(),
        counter: std::sync::atomic::AtomicU64::new(0),
    });
    let id = SpiffeId::from_parts(&trust_domain, "ns/test/sa/foo").unwrap();
    let attestor: Arc<dyn ferrum_edge::identity::attestation::Attestor> =
        Arc::new(StubAttestor { id });
    let svc = WorkloadApiService::new(vec![attestor], ca, trust_domain, 600);

    for (name, result) in [
        (
            "FetchJWTSVID",
            svc.fetch_jwtsvid(Request::new(JwtsvidRequest {
                audience: vec!["aud".to_string()],
                spiffe_id: String::new(),
            }))
            .await
            .map(|_| ()),
        ),
        (
            "FetchJWTBundles",
            svc.fetch_jwt_bundles(Request::new(JwtBundlesRequest {}))
                .await
                .map(|_| ()),
        ),
        (
            "ValidateJWTSVID",
            svc.validate_jwtsvid(Request::new(ValidateJwtsvidRequest {
                audience: "aud".to_string(),
                svid: "token".to_string(),
            }))
            .await
            .map(|_| ()),
        ),
    ] {
        let err = match result {
            Ok(()) => panic!("{name}: missing workload metadata must be rejected"),
            Err(err) => err,
        };
        assert_eq!(
            err.code(),
            Code::InvalidArgument,
            "{name}: metadata failure must precede UNIMPLEMENTED"
        );
    }
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

// ── Capacity-one / latest-wins rotation bounds ───────────────────────────

#[tokio::test]
async fn latest_wins_channel_drops_superseded_values_and_stays_capacity_one() {
    use ferrum_edge::identity::workload_api::latest_wins;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Probe {
        id: u64,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for Probe {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    let drops = Arc::new(AtomicUsize::new(0));
    let (tx, mut rx) = latest_wins::channel::<Probe>();

    assert!(tx.publish(Probe {
        id: 0,
        drops: Arc::clone(&drops),
    }));
    assert_eq!(rx.pending_len(), 1);

    for id in 1..=64 {
        assert!(tx.publish(Probe {
            id,
            drops: Arc::clone(&drops),
        }));
        assert_eq!(
            rx.pending_len(),
            1,
            "latest-wins must retain at most one unread value"
        );
    }

    // 64 superseded probes dropped by replace; id 64 still pending.
    assert_eq!(drops.load(Ordering::SeqCst), 64);
    let newest = rx.recv().await.expect("newest probe");
    assert_eq!(newest.id, 64);
    assert_eq!(rx.pending_len(), 0);
    drop(newest);
    assert_eq!(drops.load(Ordering::SeqCst), 65);
}

#[tokio::test]
async fn latest_wins_receiver_drop_clears_pending_and_wakes_closed() {
    use ferrum_edge::identity::workload_api::latest_wins;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Secret(Arc<AtomicUsize>);
    impl Drop for Secret {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let drops = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = latest_wins::channel::<Secret>();
    assert!(tx.publish(Secret(Arc::clone(&drops))));
    assert_eq!(rx.pending_len(), 1);

    let closed = tokio::spawn(async move {
        tx.closed().await;
    });
    drop(rx);

    tokio::time::timeout(std::time::Duration::from_secs(2), closed)
        .await
        .expect("closed() must resolve after receiver drop")
        .expect("closed waiter panicked");
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "pending secret-bearing value must drop on stream cancel"
    );
}

#[tokio::test]
async fn latest_wins_publish_after_cancel_is_rejected_and_drops_payload() {
    use ferrum_edge::identity::workload_api::latest_wins;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Secret(Arc<AtomicUsize>);
    impl Drop for Secret {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let drops = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = latest_wins::channel::<Secret>();
    drop(rx);

    assert!(
        !tx.publish(Secret(Arc::clone(&drops))),
        "publish after cancel must report the receiver is gone"
    );
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "a rejected publish must drop its private-key-bearing payload immediately, \
         not park it in an orphaned slot"
    );
}

#[tokio::test]
async fn latest_wins_publish_racing_receiver_drop_never_retains_payload() {
    // Regression: the cancel flag must be published under the slot lock. If it
    // is stored only after the lock is released, a publish that acquires the
    // lock in between sees `receiver_gone == false`, lands its value in the
    // just-cleared slot, and that payload stays alive until the producer next
    // notices the closure — for the client relay, until the agent sends
    // another frame. Whichever side wins the lock, no value may be retained
    // while the sender is still alive.
    use ferrum_edge::identity::workload_api::latest_wins;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Secret(Arc<AtomicUsize>);
    impl Drop for Secret {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    for round in 0..256 {
        let drops = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = latest_wins::channel::<Secret>();
        let dropper = std::thread::spawn(move || drop(rx));
        let _accepted = tx.publish(Secret(Arc::clone(&drops)));
        dropper.join().expect("receiver dropper thread panicked");

        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "round {round}: payload retained in an orphaned slot after stream cancel"
        );
        drop(tx);
    }
}

#[tokio::test]
async fn fetch_x509svid_slow_consumer_coalesces_rotations_to_newest_state() {
    use ferrum_edge::identity::workload_api::proto::X509svidRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use ferrum_edge::identity::workload_api::server::WorkloadApiService;
    use tokio::sync::watch;
    use tokio_stream::StreamExt;

    let trust_domain = TrustDomain::new("td.test").unwrap();
    let ca = Arc::new(StubCa {
        trust_domain: trust_domain.clone(),
        counter: std::sync::atomic::AtomicU64::new(0),
    });
    let id = SpiffeId::from_parts(&trust_domain, "ns/test/sa/foo").unwrap();
    let attestor: Arc<dyn Attestor> = Arc::new(StubAttestor { id });

    let (tx, _) = watch::channel(0u64);
    let rotation = Arc::new(tx);
    let svc = WorkloadApiService::with_rotation_signal(
        vec![attestor],
        ca.clone(),
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
    assert_eq!(first.svids[0].x509_svid, b"stub-cert-0");
    assert_eq!(
        ca.counter.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "open must mint exactly once"
    );

    // Stop polling and fire many rotations. The producer must not retain a
    // FIFO of private-key-bearing responses — only the newest state survives.
    const ROTATIONS: u64 = 48;
    for _ in 0..ROTATIONS {
        rotation.send_modify(|v| *v += 1);
        tokio::task::yield_now().await;
    }

    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let seen = ca.counter.load(std::sync::atomic::Ordering::SeqCst);
            tokio::task::yield_now().await;
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            if ca.counter.load(std::sync::atomic::Ordering::SeqCst) == seen && seen > 1 {
                break;
            }
        }
    })
    .await
    .expect("rotation producer did not settle after burst");

    let minted = ca.counter.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        minted > 1,
        "slow-consumer burst must still advance issuance (got {minted})"
    );
    let expected_cert = format!("stub-cert-{}", minted - 1).into_bytes();

    let latest = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for coalesced newest state")
        .expect("stream ended unexpectedly")
        .expect("coalesced push was an error");
    assert_eq!(
        latest.svids[0].x509_svid, expected_cert,
        "resume must deliver the newest minted SVID, not an intermediate"
    );

    // No backlog of superseded rotations: without a further epoch, next() waits.
    let no_backlog =
        tokio::time::timeout(std::time::Duration::from_millis(75), stream.next()).await;
    assert!(
        no_backlog.is_err(),
        "capacity-one delivery must not flush a FIFO of superseded SVIDs"
    );
}

#[tokio::test]
async fn fetch_x509_bundles_slow_consumer_coalesces_to_newest_state() {
    use ferrum_edge::identity::workload_api::proto::X509BundlesRequest;
    use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_server::SpiffeWorkloadApi;
    use ferrum_edge::identity::workload_api::server::WorkloadApiService;
    use tokio::sync::watch;
    use tokio_stream::StreamExt;

    let trust_domain = TrustDomain::new("td.test").unwrap();
    let ca: Arc<dyn CertificateAuthority> = Arc::new(StubCa {
        trust_domain: trust_domain.clone(),
        counter: std::sync::atomic::AtomicU64::new(0),
    });
    let id = SpiffeId::from_parts(&trust_domain, "ns/test/sa/foo").unwrap();
    let attestor: Arc<dyn Attestor> = Arc::new(StubAttestor { id });

    let (tx, _) = watch::channel(0u64);
    let rotation = Arc::new(tx);
    let svc = WorkloadApiService::with_rotation_signal(
        vec![attestor],
        ca,
        trust_domain.clone(),
        600,
        Arc::clone(&rotation),
    );

    let resp = svc
        .fetch_x509_bundles(workload_request(X509BundlesRequest {}))
        .await
        .unwrap();
    let mut stream = resp.into_inner();
    let _first = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for first bundle")
        .expect("stream ended unexpectedly")
        .expect("first bundle was an error");

    for _ in 0..32 {
        rotation.send_modify(|v| *v += 1);
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let latest = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for coalesced bundle")
        .expect("stream ended unexpectedly")
        .expect("coalesced bundle was an error");
    assert!(latest.bundles.contains_key(trust_domain.as_str()));

    let no_backlog =
        tokio::time::timeout(std::time::Duration::from_millis(75), stream.next()).await;
    assert!(
        no_backlog.is_err(),
        "bundle stream must not retain a FIFO across slow-consumer rotations"
    );
}

#[tokio::test]
async fn client_relay_slow_consumer_coalesces_to_newest_bundle() {
    use ferrum_edge::identity::workload_api::client::WorkloadApiClient;
    use ferrum_edge::identity::workload_api::proto::{X509svid, X509svidResponse};
    use tokio_stream::StreamExt;

    fn test_x509_svid(spiffe_id: &str) -> X509svid {
        use ferrum_edge::identity::spiffe::spiffe_id_to_san;
        use rcgen::{CertificateParams, DistinguishedName, IsCa, KeyPair};
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.is_ca = IsCa::ExplicitNoCa;
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
        let id = SpiffeId::new(spiffe_id).expect("valid SPIFFE ID");
        params
            .subject_alt_names
            .push(spiffe_id_to_san(&id).expect("spiffe SAN"));
        let cert = params.self_signed(&key).expect("self-signed leaf");
        X509svid {
            spiffe_id: spiffe_id.to_string(),
            x509_svid: cert.der().as_ref().to_vec(),
            x509_svid_key: key.serialize_der(),
            bundle: cert.der().as_ref().to_vec(),
            hint: String::new(),
        }
    }

    let spiffe = "spiffe://td.test/ns/default/sa/edge";
    let (inbound_tx, inbound_rx) =
        tokio::sync::mpsc::channel::<Result<X509svidResponse, tonic::Status>>(4);
    let inbound = tokio_stream::wrappers::ReceiverStream::new(inbound_rx);
    let (mut stream, ready) = WorkloadApiClient::relay_x509_svid_stream(inbound, None);

    let first_svid = test_x509_svid(spiffe);
    let first_key = first_svid.x509_svid_key.clone();
    inbound_tx
        .send(Ok(X509svidResponse {
            svids: vec![first_svid],
            crl: Vec::new(),
            federated_bundles: Default::default(),
        }))
        .await
        .expect("send first");

    tokio::time::timeout(std::time::Duration::from_secs(2), ready)
        .await
        .expect("oneshot first-ready timed out")
        .expect("oneshot first-ready dropped");

    let first = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for first relayed bundle")
        .expect("relay ended")
        .expect("first relay error");
    assert_eq!(first.private_key_pkcs8_der.as_slice(), first_key.as_slice());

    // Stop polling the client relay and push many rotations through the inbound
    // stream. The capacity-one slot must retain only the newest decoded bundle.
    const ROTATIONS: u64 = 40;
    let mut last_key = Vec::new();
    for _ in 1..=ROTATIONS {
        let svid = test_x509_svid(spiffe);
        last_key = svid.x509_svid_key.clone();
        inbound_tx
            .send(Ok(X509svidResponse {
                svids: vec![svid],
                crl: Vec::new(),
                federated_bundles: Default::default(),
            }))
            .await
            .expect("send rotation");
    }

    // Wait until the inbound queue is drained so the relay has published the
    // newest frame (and dropped superseded private-key payloads) before we resume.
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while inbound_tx.capacity() < 4 {
            tokio::task::yield_now().await;
        }
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("client relay did not drain inbound rotations");

    let latest = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for coalesced client bundle")
        .expect("relay ended")
        .expect("coalesced relay error");
    assert_eq!(
        latest.private_key_pkcs8_der.as_slice(),
        last_key.as_slice(),
        "client relay resume must deliver the newest private-key-bearing bundle"
    );

    let no_backlog =
        tokio::time::timeout(std::time::Duration::from_millis(75), stream.next()).await;
    assert!(
        no_backlog.is_err(),
        "client relay must not retain a FIFO of superseded SVID bundles"
    );
}

#[tokio::test]
async fn client_relay_drop_cancels_silent_upstream_stream_promptly() {
    use ferrum_edge::identity::workload_api::client::WorkloadApiClient;
    use ferrum_edge::identity::workload_api::proto::X509svidResponse;

    let (inbound_tx, inbound_rx) =
        tokio::sync::mpsc::channel::<Result<X509svidResponse, tonic::Status>>(1);
    let inbound = tokio_stream::wrappers::ReceiverStream::new(inbound_rx);
    let (stream, _ready) = WorkloadApiClient::relay_x509_svid_stream(inbound, None);

    // No agent frame is ever sent. Dropping the downstream stream must wake
    // the relay through LatestWinsSender::closed(), drop the inbound receiver,
    // and therefore close the producer side without waiting for a rotation.
    drop(stream);
    tokio::time::timeout(std::time::Duration::from_secs(2), inbound_tx.closed())
        .await
        .expect("relay retained a silent upstream stream after consumer cancellation");
}

#[tokio::test]
async fn client_relay_decode_error_is_terminal_and_not_masked_by_a_later_good_frame() {
    // Regression: with an unbounded FIFO relay, a decode failure was always
    // delivered. Under capacity-one latest-wins, a decode failure that stayed
    // non-terminal could be overwritten by the next good frame before a slow
    // consumer polled — so a pinned-SPIFFE-ID violation reached neither the
    // consumer's `warn!` nor `mesh_cert_rotation_failures_total`. The decode
    // error must be terminal, exactly like a transport error.
    use ferrum_edge::identity::workload_api::client::WorkloadApiClient;
    use ferrum_edge::identity::workload_api::proto::{X509svid, X509svidResponse};
    use tokio_stream::StreamExt;

    fn svid_frame(spiffe_id: &str) -> X509svidResponse {
        use ferrum_edge::identity::spiffe::spiffe_id_to_san;
        use rcgen::{CertificateParams, DistinguishedName, IsCa, KeyPair};
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.is_ca = IsCa::ExplicitNoCa;
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);
        let id = SpiffeId::new(spiffe_id).expect("valid SPIFFE ID");
        params
            .subject_alt_names
            .push(spiffe_id_to_san(&id).expect("spiffe SAN"));
        let cert = params.self_signed(&key).expect("self-signed leaf");
        X509svidResponse {
            svids: vec![X509svid {
                spiffe_id: spiffe_id.to_string(),
                x509_svid: cert.der().as_ref().to_vec(),
                x509_svid_key: key.serialize_der(),
                bundle: cert.der().as_ref().to_vec(),
                hint: String::new(),
            }],
            crl: Vec::new(),
            federated_bundles: Default::default(),
        }
    }

    let pinned = SpiffeId::new("spiffe://td.test/ns/default/sa/edge").expect("pinned id");

    // Buffer BOTH frames before the relay task can observe either one, so the
    // ordering under test is deterministic: a wrong-identity frame immediately
    // followed by a correct one.
    let (inbound_tx, inbound_rx) =
        tokio::sync::mpsc::channel::<Result<X509svidResponse, tonic::Status>>(4);
    inbound_tx
        .send(Ok(svid_frame("spiffe://td.test/ns/default/sa/attacker")))
        .await
        .expect("buffer wrong-identity frame");
    inbound_tx
        .send(Ok(svid_frame("spiffe://td.test/ns/default/sa/edge")))
        .await
        .expect("buffer good frame");
    drop(inbound_tx);

    let inbound = tokio_stream::wrappers::ReceiverStream::new(inbound_rx);
    let (mut stream, _ready) =
        WorkloadApiClient::relay_x509_svid_stream(inbound, Some(pinned.clone()));

    let first = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for the relayed decode error")
        .expect("relay ended without surfacing the decode error");
    // `SvidBundle` deliberately has no `Debug` (it holds private-key material),
    // so unwrap the error arm by hand rather than via `expect_err`.
    let err = match first {
        Err(e) => e,
        Ok(_) => panic!("pinned-SPIFFE-ID violation must not be masked by a later good frame"),
    };
    assert!(
        err.to_string().contains(pinned.as_str()),
        "decode error must name the configured SPIFFE ID (got: {err})"
    );

    let after = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for relay termination");
    assert!(
        after.is_none(),
        "a decode error must terminate the relay like a transport error does"
    );
}

#[tokio::test]
async fn workload_api_sources_avoid_unbounded_rotation_queues() {
    // Guard against regressing to unbounded mpsc for secret-bearing rotation
    // streams; capacity-one latest-wins + oneshot first-ready are load-bearing.
    let server = include_str!("../../../src/identity/workload_api/server.rs");
    let client = include_str!("../../../src/identity/workload_api/client.rs");
    assert!(
        server.contains("latest_wins::channel"),
        "server rotation streams must use capacity-one latest-wins delivery"
    );
    assert!(
        !server.contains("unbounded_channel"),
        "server must not reintroduce unbounded rotation queues"
    );
    assert!(
        client.contains("latest_wins::channel"),
        "client relay must use capacity-one latest-wins delivery"
    );
    assert!(
        client.contains("oneshot::channel"),
        "client first-ready signal must be a oneshot"
    );
    assert!(
        !client.contains("unbounded_channel"),
        "client must not reintroduce unbounded relay queues"
    );
}

// ── Workload API socket boundary (issue #3617) ───────────────────────────
//
// The socket is a credential-adjacent surface: whoever can replace it can
// impersonate the endpoint workloads dial for their identity. Two layers are
// covered here — the pure directory-trust predicate (exhaustively, including
// ownership shapes a non-root test process cannot create on disk) and the
// filesystem walk over every component of a real path.

#[cfg(unix)]
mod socket_boundary {
    use ferrum_edge::identity::workload_api::{
        DirectoryTrustVerdict, WorkloadApiSocketConfig, classify_directory_component,
    };
    use std::path::{Path, PathBuf};

    const EUID: u32 = 1000;
    const OTHER_UID: u32 = 4242;
    const ROOT: u32 = 0;

    #[test]
    fn the_directory_trust_predicate_refuses_every_untrusted_shape() {
        use DirectoryTrustVerdict::*;

        // (label, is_symlink, is_dir, uid, mode, expected)
        let cases: &[(&str, bool, bool, u32, u32, DirectoryTrustVerdict)] = &[
            ("own dir 0755", false, true, EUID, 0o755, Trusted),
            ("own dir 0700", false, true, EUID, 0o700, Trusted),
            ("root dir 0755", false, true, ROOT, 0o755, Trusted),
            // Sticky rescues shared-writable: a non-owner can create entries but
            // cannot unlink or rename ours (`/tmp`, `/run` semantics).
            ("root sticky 1777", false, true, ROOT, 0o1777, Trusted),
            ("own sticky 1775", false, true, EUID, 0o1775, Trusted),
            // A symlink is refused, never followed — the LINK's owner, not the
            // directory's, decides where the socket lands.
            ("symlink", true, true, EUID, 0o755, Symlink),
            ("symlink owned by root", true, true, ROOT, 0o755, Symlink),
            ("regular file", false, false, EUID, 0o644, NotADirectory),
            // A directory's OWNER may modify its entries whatever the mode says,
            // so ownership is checked independently of permissions. This is the
            // directory-owner exception the sticky bit does not constrain.
            (
                "other-owned 0755",
                false,
                true,
                OTHER_UID,
                0o755,
                UntrustedOwner,
            ),
            (
                "other-owned 0700",
                false,
                true,
                OTHER_UID,
                0o700,
                UntrustedOwner,
            ),
            (
                "other-owned sticky",
                false,
                true,
                OTHER_UID,
                0o1777,
                UntrustedOwner,
            ),
            // Group-writable is an untrusted actor exactly as world-writable is.
            (
                "group-writable 0775",
                false,
                true,
                EUID,
                0o775,
                UntrustedlyWritable,
            ),
            (
                "group-writable 0770",
                false,
                true,
                ROOT,
                0o770,
                UntrustedlyWritable,
            ),
            (
                "world-writable 0777",
                false,
                true,
                ROOT,
                0o777,
                UntrustedlyWritable,
            ),
            (
                "world-writable 0707",
                false,
                true,
                EUID,
                0o707,
                UntrustedlyWritable,
            ),
        ];

        for (label, is_symlink, is_dir, uid, mode, expected) in cases {
            assert_eq!(
                classify_directory_component(*is_symlink, *is_dir, *uid, *mode, EUID),
                *expected,
                "{label}"
            );
        }
    }

    #[test]
    fn ownership_is_checked_before_permissions_so_a_private_hostile_dir_is_refused() {
        // A 0700 directory owned by another user is the case a mode-only check
        // waves through: nothing is writable by "us", yet its owner can replace
        // any entry at will.
        assert_eq!(
            classify_directory_component(false, true, OTHER_UID, 0o700, EUID),
            DirectoryTrustVerdict::UntrustedOwner
        );
    }

    /// A private per-test directory whose ancestors are all trusted, so a test
    /// can introduce exactly one untrusted component.
    ///
    /// Shared with the publication tests below, which need the same "a real path
    /// Ferrum would accept" starting point.
    pub(crate) struct Sandbox {
        pub(crate) root: PathBuf,
    }

    impl Sandbox {
        pub(crate) fn new(label: &str) -> Option<Self> {
            // Canonicalized: on macOS `std::env::temp_dir()` sits under `/var`,
            // which is itself a symlink — the very thing the walk refuses. The
            // canonical form is what an operator would configure.
            let base = std::fs::canonicalize(std::env::temp_dir()).ok()?;
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_nanos();
            let root = base.join(format!("fe-wl-sb-{label}-{}", unique % 1_000_000_000));
            std::fs::create_dir_all(&root).ok()?;
            let sandbox = Self { root };
            // If the ambient temp path is itself untrusted (an unusual CI image),
            // every case below would pass for the wrong reason. Skip instead.
            sandbox
                .socket_in(&sandbox.root)
                .validate()
                .ok()
                .map(|()| sandbox)
        }

        fn socket_in(&self, parent: &Path) -> WorkloadApiSocketConfig {
            WorkloadApiSocketConfig::from_parts(parent.join("api.sock"), "0660")
                .expect("mode parses")
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .expect("test can chmod a directory it owns");
    }

    #[test]
    fn a_group_writable_parent_directory_is_refused() {
        let Some(sandbox) = Sandbox::new("grp") else {
            return;
        };
        let parent = sandbox.root.join("parent");
        std::fs::create_dir(&parent).expect("create parent");
        set_mode(&parent, 0o775);

        let error = sandbox
            .socket_in(&parent)
            .validate()
            .expect_err("a group-writable parent must be refused");
        assert!(
            error.to_string().contains("group- or world-writable"),
            "unexpected reason: {error}"
        );

        // ...and the sticky bit makes the same mode acceptable, because a
        // non-owner can then no longer unlink our socket.
        set_mode(&parent, 0o1775);
        sandbox
            .socket_in(&parent)
            .validate()
            .expect("sticky group-writable is the /tmp posture and is accepted");
    }

    #[test]
    fn a_group_writable_ancestor_is_refused_even_with_a_pristine_parent() {
        // The finding this closes: checking only the immediate parent proves
        // nothing, because whoever controls an ancestor can rename the whole
        // subtree aside and substitute their own.
        let Some(sandbox) = Sandbox::new("anc") else {
            return;
        };
        let ancestor = sandbox.root.join("ancestor");
        let parent = ancestor.join("parent");
        std::fs::create_dir_all(&parent).expect("create ancestor/parent");
        set_mode(&parent, 0o700);
        set_mode(&ancestor, 0o777);

        let error = sandbox
            .socket_in(&parent)
            .validate()
            .expect_err("a world-writable ancestor must be refused");
        assert!(
            error.to_string().contains(&ancestor.display().to_string()),
            "the diagnostic must name the offending ancestor, not the parent: {error}"
        );

        set_mode(&ancestor, 0o755);
        sandbox
            .socket_in(&parent)
            .validate()
            .expect("a trusted ancestor chain is accepted");
    }

    #[test]
    fn a_symlinked_ancestor_is_refused_rather_than_followed() {
        let Some(sandbox) = Sandbox::new("sym") else {
            return;
        };
        let real = sandbox.root.join("real");
        std::fs::create_dir(&real).expect("create real dir");
        let link = sandbox.root.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("test can create a symlink");

        // The symlink as the socket's own parent...
        let error = sandbox
            .socket_in(&link)
            .validate()
            .expect_err("a symlinked parent must be refused");
        assert!(error.to_string().contains("symlink"), "reason: {error}");

        // ...and as an ANCESTOR of it. Following either would mean the path the
        // operator reviewed and the path Ferrum binds are different objects.
        let under_real = real.join("nested");
        std::fs::create_dir(&under_real).expect("create nested dir");
        let error = sandbox
            .socket_in(&link.join("nested"))
            .validate()
            .expect_err("a symlinked ancestor must be refused");
        assert!(error.to_string().contains("symlink"), "reason: {error}");

        // The same directory reached through its real path is fine, which is
        // what makes the refusal about the link rather than the target.
        sandbox
            .socket_in(&under_real)
            .validate()
            .expect("the real path to the same directory is accepted");
    }

    #[test]
    fn a_non_directory_component_is_refused() {
        let Some(sandbox) = Sandbox::new("file") else {
            return;
        };
        let file = sandbox.root.join("not-a-dir");
        std::fs::write(&file, b"operator data").expect("write file");
        let error = sandbox
            .socket_in(&file)
            .validate()
            .expect_err("a regular file cannot be the socket's parent");
        assert!(
            error.to_string().contains("is not a directory"),
            "reason: {error}"
        );
        assert_eq!(
            std::fs::read(&file).expect("the file survives"),
            b"operator data",
            "validation must never mutate the artifact it refuses"
        );
    }
}

// ── Socket mode, lexical path, liveness, and cleanup identity ─────────────
//
// The pure halves of the socket contract, exercised over shapes a test process
// cannot always force onto a real filesystem.

#[cfg(unix)]
mod socket_policy {
    use ferrum_edge::identity::workload_api::{
        MAX_STAGING_SUFFIX_BYTES, SocketLiveness, WorkloadApiSocketConfig, classify_connect_result,
        matches_bound_socket_identity,
    };
    use std::io;

    const EUID: u32 = 1000;
    const OTHER_UID: u32 = 4242;

    #[test]
    fn a_mode_that_permits_no_connection_is_refused_at_parse() {
        // `connect(2)` on a Unix socket requires WRITE permission on the socket
        // file. A mode with neither an owner nor a group write bit therefore
        // binds happily and then rejects every workload with EACCES, which
        // contradicts the startup contract: a successful start must mean
        // workloads can actually connect.
        for mode in ["0000", "0400", "0440", "0444", "0500", "0550", "0555"] {
            let error = WorkloadApiSocketConfig::from_parts("/run/ferrum/api.sock", mode)
                .expect_err("a mode with no owner/group write bit must be refused");
            assert!(
                error.to_string().contains("write"),
                "mode {mode} should be refused for lacking a write bit, got: {error}"
            );
        }
    }

    #[test]
    fn world_writable_modes_stay_refused() {
        for mode in ["0666", "0662", "0602", "0002", "0777"] {
            let error = WorkloadApiSocketConfig::from_parts("/run/ferrum/api.sock", mode)
                .expect_err("a world-writable mode must be refused");
            assert!(
                error.to_string().contains("world-writable"),
                "mode {mode} should be refused as world-writable, got: {error}"
            );
        }
    }

    #[test]
    fn modes_that_grant_owner_or_group_write_are_accepted() {
        // Owner-write alone, group-write alone, and the default all satisfy the
        // "a workload can reach it" rule; the group case is the documented
        // production shape.
        for mode in ["0600", "0660", "0060", "0760", "0700"] {
            let config = WorkloadApiSocketConfig::from_parts("/run/ferrum/api.sock", mode)
                .unwrap_or_else(|error| panic!("mode {mode} should parse, got: {error}"));
            assert_ne!(
                config.socket_mode & 0o220,
                0,
                "mode {mode} must retain a write bit"
            );
        }
    }

    #[test]
    fn an_embedded_dot_segment_is_refused_rather_than_normalized_away() {
        // `Path::components()` drops an embedded `.` on Unix, so a lexical
        // rejection written over it would have accepted this path while the
        // documentation promised otherwise. The check reads raw segments.
        for path in [
            "/run/ferrum/./api.sock",
            "/run/./ferrum/api.sock",
            "/run/ferrum/../ferrum/api.sock",
            "/run/ferrum/..",
            "/./api.sock",
        ] {
            let error = WorkloadApiSocketConfig::from_parts(path, "0660")
                .expect("mode parses")
                .validate()
                .expect_err("a '.' or '..' segment must be refused");
            assert!(
                error.to_string().contains("'.' or '..'"),
                "path {path} should be refused for its dot segment, got: {error}"
            );
        }
    }

    #[test]
    fn a_parent_with_no_room_for_the_staging_directory_is_refused() {
        // The socket is bound inside a private staging directory beneath the
        // parent and only then published from there, so it is the STAGING path
        // that has to fit `sockaddr_un.sun_path`. A parent that leaves no
        // headroom is a configuration error, not a bare EINVAL from `bind`.
        let parent = format!("/{}", "d".repeat(90));
        let error = WorkloadApiSocketConfig::from_parts(format!("{parent}/s"), "0660")
            .expect("mode parses")
            .validate()
            .expect_err("an over-long parent must be refused");
        let text = error.to_string();
        assert!(
            text.contains("staging") || text.contains("Unix-socket limit"),
            "unexpected reason: {error}"
        );

        // The default deployment path is comfortably inside the budget, so the
        // reserved headroom costs a real operator nothing.
        let default_parent = "/run/ferrum/workload-api";
        assert!(
            default_parent.len() + MAX_STAGING_SUFFIX_BYTES <= 100,
            "the documented default parent must still fit with staging headroom"
        );
        WorkloadApiSocketConfig::from_parts(format!("{default_parent}/socket"), "0660")
            .expect("the default path and mode parse");
    }

    #[test]
    fn only_a_definitive_not_listening_result_admits_an_unlink() {
        // A successful connection means a LIVE endpoint: refusing to unlink it
        // is what stops a second same-uid process taking over the path
        // workloads dial for their identity. Everything the kernel could not
        // answer definitively is undetermined, and undetermined fails closed.
        assert_eq!(classify_connect_result(&Ok(())), SocketLiveness::Live);
        assert_eq!(
            classify_connect_result(&Err(io::Error::from(io::ErrorKind::ConnectionRefused))),
            SocketLiveness::NotListening
        );
        assert_eq!(
            classify_connect_result(&Err(io::Error::from(io::ErrorKind::NotFound))),
            SocketLiveness::NotListening
        );
        for ambiguous in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::TimedOut,
            io::ErrorKind::Interrupted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::Other,
        ] {
            assert_eq!(
                classify_connect_result(&Err(io::Error::from(ambiguous))),
                SocketLiveness::Undetermined,
                "{ambiguous:?} must not be read as 'nobody is listening'"
            );
        }
    }

    #[test]
    fn cleanup_identity_is_type_and_owner_as_well_as_device_and_inode() {
        let bound = (7u64, 42u64);

        assert!(
            matches_bound_socket_identity(true, EUID, bound, EUID, bound),
            "our own socket at the recorded inode is the thing we may unlink"
        );
        // Inode reuse: the number is recycled and a REGULAR FILE lands on it.
        // A device+inode-only predicate would have deleted somebody's data.
        assert!(
            !matches_bound_socket_identity(false, EUID, bound, EUID, bound),
            "a non-socket on the recycled inode must not satisfy the identity"
        );
        // Type replacement by another user, same inode.
        assert!(
            !matches_bound_socket_identity(true, OTHER_UID, bound, EUID, bound),
            "another user's socket must not satisfy the identity"
        );
        // A different inode is a different object even when it is our socket.
        assert!(
            !matches_bound_socket_identity(true, EUID, (7, 43), EUID, bound),
            "a successor socket at the same path must be left alone"
        );
        assert!(
            !matches_bound_socket_identity(true, EUID, (8, 42), EUID, bound),
            "the device is part of the identity too"
        );
    }

    #[test]
    fn the_liveness_probe_carries_a_bound_and_a_timeout_is_not_an_answer() {
        use ferrum_edge::identity::workload_api::listener::SOCKET_LIVENESS_PROBE_TIMEOUT;

        // A local Unix connect either completes or fails at once; the deadline
        // exists for the peer that does neither — one that is listening but has
        // stopped draining its accept queue. Without a bound, that peer holds
        // startup open indefinitely, which is neither of the two refusals the
        // contract documents.
        assert!(
            SOCKET_LIVENESS_PROBE_TIMEOUT > std::time::Duration::ZERO
                && SOCKET_LIVENESS_PROBE_TIMEOUT <= std::time::Duration::from_secs(10),
            "the probe must be bounded, and briefly: a slow local connect is already evidence"
        );
        // Expiry is folded back through the ordinary classification rather than
        // short-circuiting it, so it lands on the same fail-closed verdict as
        // every other answer the kernel did not give.
        assert_eq!(
            classify_connect_result(&Err(io::Error::from(io::ErrorKind::TimedOut))),
            SocketLiveness::Undetermined
        );
    }
}

// ── Publication and the liveness probe against real sockets ───────────────
//
// The two startup steps that decide whether Ferrum may own the path workloads
// dial for their identity. Both are exercised on a real filesystem here: the
// pure predicates above say what the policy is, these say what the code does
// with it.

#[cfg(unix)]
mod socket_publication {
    use super::socket_boundary::Sandbox;
    use ferrum_edge::identity::workload_api::listener::{
        SocketLiveness, bind_and_publish_socket, probe_socket_liveness,
    };
    use std::os::unix::fs::MetadataExt;

    fn entries(directory: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(directory)
            .expect("the parent directory is readable")
            .map(|entry| {
                entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    #[tokio::test]
    async fn publication_never_replaces_an_artifact_that_is_already_at_the_destination() {
        // The race the publication step exists to lose safely. The liveness
        // probe runs before the socket is even bound, so a peer can bind the
        // path in between; `rename(2)` would have silently unlinked that live
        // listener and taken over the endpoint workloads dial for their
        // identity. The destination is created up front here, which is the same
        // state that window produces and needs no timing to reach.
        let Some(sandbox) = Sandbox::new("pub") else {
            return;
        };
        let path = sandbox.root.join("api.sock");
        let competitor = std::os::unix::net::UnixListener::bind(&path)
            .expect("a competing process can bind the path first");
        let before = std::fs::symlink_metadata(&path).expect("the competitor's socket exists");

        let error = bind_and_publish_socket(&path, 0o660)
            .expect_err("publication must refuse a destination that is already occupied");
        assert!(
            error.to_string().contains("another process"),
            "unexpected refusal reason: {error}"
        );

        let after = std::fs::symlink_metadata(&path).expect("the competitor's socket survives");
        assert_eq!(
            (before.dev(), before.ino()),
            (after.dev(), after.ino()),
            "a refused publication must never replace the artifact it lost to"
        );
        std::os::unix::net::UnixStream::connect(&path)
            .expect("the competing listener is still serving on its own socket");
        assert_eq!(
            entries(&sandbox.root),
            vec!["api.sock".to_string()],
            "a refused publication must leave nothing of ours behind, staging included"
        );

        drop(competitor);
    }

    #[tokio::test]
    async fn a_published_socket_is_the_staged_inode_and_reachable_through_its_new_name() {
        // The other half: refusing to clobber must not have cost publication its
        // meaning. The listener is bound in staging and never rebound, so this
        // pins that the published NAME reaches that same listener — a Unix
        // socket is resolved to its inode, which is what makes linking a valid
        // publication rather than a copy.
        let Some(sandbox) = Sandbox::new("ok") else {
            return;
        };
        let path = sandbox.root.join("api.sock");
        let (listener, identity) =
            bind_and_publish_socket(&path, 0o660).expect("an empty destination is published");

        let metadata = std::fs::symlink_metadata(&path).expect("the published socket exists");
        assert_eq!(
            (metadata.dev(), metadata.ino()),
            identity,
            "the published name is the inode that was bound and permissioned in staging"
        );
        assert_eq!(
            metadata.mode() & 0o777,
            0o660,
            "the configured mode survives"
        );
        assert_eq!(
            metadata.nlink(),
            1,
            "only the published name survives; the staging alias is unlinked"
        );
        assert_eq!(
            entries(&sandbox.root),
            vec!["api.sock".to_string()],
            "publication leaves no staging directory behind"
        );

        let client = tokio::net::UnixStream::connect(&path)
            .await
            .expect("the published name reaches the listener bound in staging");
        listener
            .accept()
            .await
            .expect("the listener accepts a connection made through the published name");
        drop(client);
        drop(listener);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn the_probe_reads_live_leftover_and_missing_sockets_correctly() {
        let Some(sandbox) = Sandbox::new("probe") else {
            return;
        };

        let path = sandbox.root.join("live.sock");
        let live = tokio::net::UnixListener::bind(&path).expect("bind a live listener");
        assert_eq!(
            probe_socket_liveness(&path).await,
            SocketLiveness::Live,
            "a listener that is serving must be seen as live and never unlinked"
        );

        // Closing the listener leaves the name on disk with nothing bound to it:
        // exactly what a crashed predecessor leaves behind, and the only shape
        // that admits an unlink.
        drop(live);
        assert!(path.exists(), "the leftover socket file remains on disk");
        assert_eq!(
            probe_socket_liveness(&path).await,
            SocketLiveness::NotListening
        );

        assert_eq!(
            probe_socket_liveness(&sandbox.root.join("missing.sock")).await,
            SocketLiveness::NotListening
        );
    }

    #[tokio::test]
    async fn a_live_socket_we_cannot_reach_is_undetermined_rather_than_stale() {
        use std::os::unix::fs::PermissionsExt;

        // "Ambiguous fails closed", against a real socket rather than a
        // synthesized error kind. A live listener whose file denies us write
        // permission answers `connect(2)` with `EACCES`, and that is not
        // evidence that nobody is there — reading it as stale would unlink a
        // serving endpoint. Root bypasses the permission check, so there is
        // nothing to observe as that user.
        //
        // SAFETY: `geteuid` is a pure read of this process's credentials.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let Some(sandbox) = Sandbox::new("eacces") else {
            return;
        };
        let path = sandbox.root.join("closed.sock");
        let live = tokio::net::UnixListener::bind(&path).expect("bind a live listener");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))
            .expect("test can chmod a socket it owns");

        assert_eq!(
            probe_socket_liveness(&path).await,
            SocketLiveness::Undetermined,
            "an unreachable socket is an answer we did not get, not an absent listener"
        );

        drop(live);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_listener_publishes_and_probes_without_the_primitives_that_caused_this() {
        // Two structural regressions this module cannot observe behaviourally,
        // both of which reintroduce a silent failure rather than a visible one:
        // an overwrite-capable `rename` as the publication step, and a blocking
        // `connect(2)` issued from the async startup path.
        let listener = include_str!("../../../src/identity/workload_api/listener.rs");
        assert!(
            !listener.contains("fs::rename"),
            "publication must not go back to an overwrite-capable rename"
        );
        assert!(
            listener.contains("fs::hard_link"),
            "publication must use a primitive that fails when the destination exists"
        );
        assert!(
            !listener.contains("std::os::unix::net::UnixStream::connect"),
            "the liveness probe must not block the startup runtime on a peer that never answers"
        );
        assert!(
            listener.contains("tokio::net::UnixStream::connect")
                && listener.contains("tokio::time::timeout("),
            "the liveness probe must stay asynchronous and bounded"
        );
    }
}
