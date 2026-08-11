//! Live coverage for Ferrum's in-process SPIFFE Workload API server over a real
//! Unix domain socket (issue #3617).
//!
//! These tests exercise the *runtime* half that unit tests cannot: an actual
//! bind, an actual gRPC dial, and the socket lifecycle. Concretely they pin
//!
//! - **server startup** — the socket exists, carries the configured mode, and
//!   answers RPCs;
//! - **mint / bundle / validate over the wire** — `FetchJWTSVID` mints for the
//!   attested identity, `FetchJWTBundles` streams a JWKS for the local trust
//!   domain, and `ValidateJWTSVID` accepts that token round-trip;
//! - **rotation publication** — driving the authority's rotation and bumping the
//!   rotation signal republishes a *changed* JWKS on an already-open stream;
//! - **cancellation** — dropping a bundle stream lets the server-side rotation
//!   task exit instead of parking forever;
//! - **restart continuity** — a token minted by one server instance still
//!   validates against a *new* instance built from the same configured signing
//!   material;
//! - **shutdown cleanup** — the socket artifact Ferrum created is unlinked, and
//!   a foreign artifact at the same path is refused rather than clobbered;
//! - **no take-over of a live endpoint** — a second start against a socket that
//!   is still serving is refused (ownership was never evidence of staleness),
//!   while a genuinely stale socket with no listener is still cleared;
//! - **publication without global state** — the process umask is untouched and
//!   no staging artifact survives;
//! - **termination signalling** — the seam mesh mode uses to notice that its
//!   identity endpoint has gone away.
//!
//! Everything runs on the ordinary hosted CI runner: a Unix socket in a
//! per-test temp directory, no root, no network.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use ferrum_edge::identity::attestation::{AttestError, Attestor, PeerInfo, WorkloadIdentity};
use ferrum_edge::identity::ca::{CertificateAuthority, bootstrap, internal};
use ferrum_edge::identity::jwt_svid::{JwtSvidSigner, MAX_JWT_SVID_TTL_SECS};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::identity::workload_api::WorkloadApiService;
use ferrum_edge::identity::workload_api::proto::spiffe_workload_api_client::SpiffeWorkloadApiClient;
use ferrum_edge::identity::workload_api::proto::{
    JwtBundlesRequest, JwtsvidRequest, ValidateJwtsvidRequest,
};
use ferrum_edge::identity::workload_api::{WorkloadApiSocketConfig, serve_workload_api};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tokio_stream::StreamExt;
use tonic::Request;
use tonic::metadata::AsciiMetadataValue;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

const TRUST_DOMAIN: &str = "workload-api.test";
const SOCKET_MODE: u32 = 0o660;

fn trust_domain() -> TrustDomain {
    TrustDomain::new(TRUST_DOMAIN.to_string()).expect("test trust domain is valid")
}

fn workload_id() -> SpiffeId {
    SpiffeId::from_parts(&trust_domain(), "ns/test/sa/app").expect("test SPIFFE ID is valid")
}

/// Attestor standing in for a peer-credential rule: it authorizes exactly one
/// identity, which is the property the mint path depends on (the subject is
/// never caller-selected).
struct FixedAttestor;

#[async_trait]
impl Attestor for FixedAttestor {
    fn kind(&self) -> &'static str {
        "test-fixed"
    }

    async fn attest(&self, _peer: &PeerInfo) -> Result<WorkloadIdentity, AttestError> {
        Ok(WorkloadIdentity {
            spiffe_id: workload_id(),
            selectors: Default::default(),
            attestor_kind: "test-fixed".to_string(),
        })
    }
}

/// A fresh ES256 (P-256) PKCS#8 PEM — the shape
/// `FERRUM_MESH_JWT_SIGNING_KEY_PEM` accepts.
fn signing_key_pem() -> String {
    rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("P-256 key generated")
        .serialize_pem()
}

/// Which JWT signing posture a server instance runs.
///
/// The two are not interchangeable, and the difference is the point of several
/// tests below: **configured** material is the production posture and rotates
/// externally (Ferrum refuses to generate a process-local replacement for it),
/// while **ephemeral** is the dev/test posture that has no continuity to lose
/// and therefore keeps in-process rotation.
#[derive(Clone)]
enum JwtKeySource {
    Configured(String),
    Ephemeral,
}

/// Build an `internal` CA with a *configured* (stable) JWT signing key.
///
/// The X.509 root is bootstrapped per call — it plays no part in the JWT
/// assertions, which is itself the point: JWT signing material is separate from
/// the certificate root, so a fresh root does not disturb JWT continuity.
fn internal_ca_with_jwt_key(jwt_key_pem: &str) -> Arc<internal::InternalCa> {
    internal_ca_with_jwt_source(&JwtKeySource::Configured(jwt_key_pem.to_string()))
}

fn internal_ca_with_jwt_source(source: &JwtKeySource) -> Arc<internal::InternalCa> {
    // `bootstrap_dev_root` is double-gated on these two reads. This process is a
    // test binary, never a serving gateway.
    //
    // SAFETY: set before any Workload API server is constructed in this test
    // binary, and only ever to these values, so no concurrently running test
    // observes a different value for them.
    unsafe {
        std::env::set_var("FERRUM_MESH_PRODUCTION_MODE", "false");
        std::env::set_var("FERRUM_MESH_CA_BOOTSTRAP_DEV", "true");
    }
    let root = bootstrap::bootstrap_dev_root(bootstrap::BootstrapConfig::new(trust_domain()))
        .expect("dev root bootstraps");
    let (jwt_signing_key_pem, allow_ephemeral_jwt_key) = match source {
        JwtKeySource::Configured(pem) => (Some(zeroize::Zeroizing::new(pem.clone())), false),
        JwtKeySource::Ephemeral => (None, true),
    };
    Arc::new(
        internal::InternalCa::new(internal::InternalCaConfig {
            root_cert_pem: root.root_cert_pem,
            root_key_pem: root.root_key_pem,
            trust_domain: root.trust_domain,
            bundle_refresh_hint_secs: None,
            default_svid_ttl_secs: 600,
            max_svid_ttl_secs: 3600,
            jwt_signing_key_pem,
            jwt_retired_key_pems: Vec::new(),
            // Rotation is driven explicitly in these tests; the scheduled cadence
            // is covered by unit tests.
            jwt_key_lifetime_secs: 0,
            allow_ephemeral_jwt_key,
        })
        .expect("internal CA builds"),
    )
}

/// A unique socket path under the system temp dir.
///
/// Deliberately short: `sockaddr_un.sun_path` is ~104 bytes, and a long
/// per-test path is the classic reason a UDS test fails with a bare `EINVAL`.
fn socket_path(label: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after the epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("fe-wl-{label}-{}.sock", unique % 1_000_000_000))
}

/// Dial a Unix socket with the same connector shape the production client uses.
async fn connect(path: &Path) -> SpiffeWorkloadApiClient<Channel> {
    let path = path.to_path_buf();
    let channel = Endpoint::try_from("http://[::1]:0")
        .expect("dummy endpoint parses")
        .connect_with_connector(service_fn(move |_: tonic::transport::Uri| {
            let path = path.clone();
            async move {
                let stream = UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await
        .expect("Workload API socket accepts a connection");
    SpiffeWorkloadApiClient::new(channel)
}

/// Every Workload API RPC must carry the mandatory metadata header.
fn workload_request<T>(payload: T) -> Request<T> {
    let mut req = Request::new(payload);
    req.metadata_mut().insert(
        "workload.spiffe.io",
        AsciiMetadataValue::from_static("true"),
    );
    req
}

struct Harness {
    listener: ferrum_edge::identity::workload_api::WorkloadApiListener,
    path: PathBuf,
    /// Held as the CONCRETE internal CA so a test can drive its JWT authority
    /// directly — that is the runtime authority the server reads bundles from, so
    /// rotating it here is the same event the mesh rotation loop produces.
    ca: Arc<internal::InternalCa>,
    rotation_signal: Arc<tokio::sync::watch::Sender<u64>>,
}

impl Harness {
    async fn start(label: &str, jwt_key_pem: &str) -> Self {
        Self::start_with(label, JwtKeySource::Configured(jwt_key_pem.to_string())).await
    }

    async fn start_with(label: &str, source: JwtKeySource) -> Self {
        let path = socket_path(label);
        let ca = internal_ca_with_jwt_source(&source);
        let rotation_signal = Arc::new(tokio::sync::watch::channel(0u64).0);
        let service = WorkloadApiService::with_rotation_signal(
            vec![Arc::new(FixedAttestor) as Arc<dyn Attestor>],
            Arc::clone(&ca) as Arc<dyn CertificateAuthority>,
            trust_domain(),
            600,
            Arc::clone(&rotation_signal),
        )
        .with_jwt_svid_ttl_secs(300);
        let socket = WorkloadApiSocketConfig::from_parts(path.clone(), "0660")
            .expect("socket config is well formed");
        let listener = serve_workload_api(service, socket)
            .await
            .expect("Workload API listener binds");
        Self {
            listener,
            path,
            ca,
            rotation_signal,
        }
    }

    async fn shutdown(self) -> PathBuf {
        let path = self.path.clone();
        tokio::time::timeout(std::time::Duration::from_secs(5), self.listener.shutdown())
            .await
            .expect("Workload API shutdown must not wait on a long-lived response stream");
        path
    }
}

#[tokio::test]
async fn workload_api_server_starts_and_serves_mint_bundle_validate() {
    let harness = Harness::start("mbv", &signing_key_pem()).await;

    // Startup: the socket exists as a socket with the configured mode.
    let metadata = std::fs::symlink_metadata(&harness.path).expect("socket exists after bind");
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        assert!(metadata.file_type().is_socket(), "bound path is a socket");
        assert_eq!(
            metadata.mode() & 0o777,
            SOCKET_MODE,
            "the socket must carry the configured mode, not the process umask"
        );
    }

    let mut client = connect(&harness.path).await;

    // Mint: the subject is the attested identity.
    let minted = client
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["spiffe://audience.test/api".to_string()],
            spiffe_id: String::new(),
        }))
        .await
        .expect("FetchJWTSVID succeeds")
        .into_inner();
    assert_eq!(minted.svids.len(), 1);
    assert_eq!(minted.svids[0].spiffe_id, workload_id().as_str());
    let token = minted.svids[0].svid.clone();
    assert!(!token.is_empty(), "a JWT-SVID was returned");

    // Bundles: a JWKS for the local trust domain, never an empty map.
    let mut bundles = client
        .fetch_jwt_bundles(workload_request(JwtBundlesRequest {}))
        .await
        .expect("FetchJWTBundles succeeds")
        .into_inner();
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), bundles.next())
        .await
        .expect("bundle stream produced a frame")
        .expect("bundle stream did not end")
        .expect("bundle frame is not an error");
    let jwks = first
        .bundles
        .get(TRUST_DOMAIN)
        .expect("the local trust domain is always present");
    assert!(
        !jwks.is_empty(),
        "an empty JWKS is not a conformant 'no authorities' signal"
    );

    // Validate: the same token round-trips.
    let validated = client
        .validate_jwtsvid(workload_request(ValidateJwtsvidRequest {
            audience: "spiffe://audience.test/api".to_string(),
            svid: token.clone(),
        }))
        .await
        .expect("ValidateJWTSVID succeeds")
        .into_inner();
    assert_eq!(validated.spiffe_id, workload_id().as_str());

    // A different audience must not validate — the audience binding is real.
    let wrong_audience = client
        .validate_jwtsvid(workload_request(ValidateJwtsvidRequest {
            audience: "spiffe://other.test/api".to_string(),
            svid: token,
        }))
        .await
        .expect_err("a token for another audience must be refused");
    assert_eq!(wrong_audience.code(), tonic::Code::InvalidArgument);

    harness.shutdown().await;
}

#[tokio::test]
async fn a_requested_spiffe_id_the_workload_is_not_entitled_to_is_denied() {
    let harness = Harness::start("deny", &signing_key_pem()).await;
    let mut client = connect(&harness.path).await;

    let denied = client
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["spiffe://audience.test/api".to_string()],
            spiffe_id: format!("spiffe://{TRUST_DOMAIN}/ns/other/sa/victim"),
        }))
        .await
        .expect_err("an unentitled subject must be refused");
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);

    harness.shutdown().await;
}

#[tokio::test]
async fn a_jwt_key_rotation_republishes_the_bundle_on_an_open_stream() {
    // The EPHEMERAL posture, deliberately: it is the only one with in-process
    // key rotation. Configured material rotates by rolling new configuration —
    // covered by `a_configured_authority_refuses_in_process_rotation` below and
    // by the restart-continuity test.
    let harness = Harness::start_with("rot", JwtKeySource::Ephemeral).await;
    let mut client = connect(&harness.path).await;

    let mut bundles = client
        .fetch_jwt_bundles(workload_request(JwtBundlesRequest {}))
        .await
        .expect("FetchJWTBundles succeeds")
        .into_inner();
    let initial = tokio::time::timeout(std::time::Duration::from_secs(5), bundles.next())
        .await
        .expect("initial bundle arrives")
        .expect("stream did not end")
        .expect("initial bundle is not an error")
        .bundles
        .get(TRUST_DOMAIN)
        .cloned()
        .expect("local trust domain present");

    // Drive the runtime authority path: rotate the JWT signing key on the CA the
    // server actually reads bundles from, then publish the rotation revision
    // exactly as the mesh rotation loop does. `rotate_if_due` is a deliberate
    // no-op here (the cadence is disabled in this harness), so the rotation is
    // driven outright — the same call the scheduled path makes once due.
    let authority = harness
        .ca
        .jwt_authority()
        .expect("configured signing material yields a JWT authority");
    let generation_before = authority.generation();
    authority.rotate().await.expect("rotation succeeds");
    assert!(
        authority.generation() > generation_before,
        "the authority generation must advance on rotation"
    );
    assert!(
        harness
            .ca
            .jwt_signer()
            .expect("the internal CA owns a JWT signing authority")
            .authorities()
            .len()
            >= 2,
        "the retired key stays published through its verification overlap"
    );

    harness
        .rotation_signal
        .send_modify(|revision| *revision = revision.saturating_add(1));

    let republished = tokio::time::timeout(std::time::Duration::from_secs(5), bundles.next())
        .await
        .expect("a rotation republishes on the open stream")
        .expect("stream did not end")
        .expect("republished bundle is not an error")
        .bundles
        .get(TRUST_DOMAIN)
        .cloned()
        .expect("local trust domain present");
    assert_ne!(
        initial, republished,
        "a JWT key rotation must change the published JWKS"
    );

    harness.shutdown().await;
}

#[tokio::test]
async fn dropping_a_bundle_stream_cancels_the_server_side_producer() {
    let harness = Harness::start("cancel", &signing_key_pem()).await;
    let mut client = connect(&harness.path).await;

    let mut bundles = client
        .fetch_jwt_bundles(workload_request(JwtBundlesRequest {}))
        .await
        .expect("FetchJWTBundles succeeds")
        .into_inner();
    tokio::time::timeout(std::time::Duration::from_secs(5), bundles.next())
        .await
        .expect("initial bundle arrives")
        .expect("stream did not end")
        .expect("initial bundle is not an error");

    // Cancel. The server-side rotation task must observe the closed sink rather
    // than parking on the rotation signal forever.
    drop(bundles);
    // Publish a rotation the cancelled stream must not consume; the server must
    // stay healthy and continue serving new callers.
    harness
        .rotation_signal
        .send_modify(|revision| *revision = revision.saturating_add(1));

    let mut fresh = connect(&harness.path).await;
    let mut fresh_bundles = fresh
        .fetch_jwt_bundles(workload_request(JwtBundlesRequest {}))
        .await
        .expect("the server still serves after a cancelled stream")
        .into_inner();
    tokio::time::timeout(std::time::Duration::from_secs(5), fresh_bundles.next())
        .await
        .expect("a new stream still receives its initial bundle")
        .expect("stream did not end")
        .expect("bundle is not an error");

    harness.shutdown().await;
}

#[tokio::test]
async fn a_token_minted_before_a_server_restart_validates_after_it() {
    // The whole point of configured signing material: the SECOND server is a
    // different process-lifetime authority with the same material, and it must
    // accept the first one's token.
    let jwt_key = signing_key_pem();

    let first = Harness::start("restart-a", &jwt_key).await;
    let mut client = connect(&first.path).await;
    let minted = client
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["spiffe://audience.test/api".to_string()],
            spiffe_id: String::new(),
        }))
        .await
        .expect("FetchJWTSVID succeeds")
        .into_inner();
    let token = minted.svids[0].svid.clone();
    drop(client);
    let old_path = first.shutdown().await;
    assert!(
        !old_path.exists(),
        "shutdown must unlink the socket it created"
    );

    let second = Harness::start("restart-b", &jwt_key).await;
    let mut client = connect(&second.path).await;
    let validated = client
        .validate_jwtsvid(workload_request(ValidateJwtsvidRequest {
            audience: "spiffe://audience.test/api".to_string(),
            svid: token,
        }))
        .await
        .expect("a pre-restart token validates against the restarted server")
        .into_inner();
    assert_eq!(validated.spiffe_id, workload_id().as_str());

    // The advertised JWT-SVID ceiling is what makes that guarantee bounded rather
    // than open-ended; assert the constant the docs quote.
    assert_eq!(MAX_JWT_SVID_TTL_SECS, 3600);

    second.shutdown().await;
}

#[tokio::test]
async fn shutdown_removes_only_the_socket_ferrum_created() {
    let harness = Harness::start("cleanup", &signing_key_pem()).await;
    let path = harness.path.clone();
    assert!(path.exists(), "the socket exists while serving");
    harness.shutdown().await;
    assert!(
        !path.exists(),
        "the socket artifact must be unlinked on shutdown"
    );

    // A NON-socket artifact at the same path is refused, not clobbered: the
    // cleanup path only ever removes an owned socket.
    std::fs::write(&path, b"operator data").expect("write a decoy regular file");
    let ca = internal_ca_with_jwt_key(&signing_key_pem());
    let service = WorkloadApiService::new(
        vec![Arc::new(FixedAttestor) as Arc<dyn Attestor>],
        ca as Arc<dyn CertificateAuthority>,
        trust_domain(),
        600,
    );
    let socket = WorkloadApiSocketConfig::from_parts(path.clone(), "0660")
        .expect("socket config is well formed");
    let refused = serve_workload_api(service, socket)
        .await
        .expect_err("a regular file at the socket path must be refused");
    assert!(
        refused.to_string().contains("not a socket"),
        "unexpected refusal reason: {refused}"
    );
    assert_eq!(
        std::fs::read(&path).expect("the decoy file survives"),
        b"operator data",
        "a foreign artifact must never be deleted"
    );
    std::fs::remove_file(&path).expect("test cleanup");
}

#[tokio::test]
async fn a_configured_authority_refuses_in_process_rotation() {
    // The P1 continuity contract, over the live surface: a server running on
    // operator-configured signing material must not replace that material with
    // a process-local key. Doing so would publish a different JWKS on every
    // replica and lose the signer of every still-live token on restart.
    let harness = Harness::start("noroti", &signing_key_pem()).await;
    let authority = harness
        .ca
        .jwt_authority()
        .expect("configured signing material yields a JWT authority");
    assert!(
        !authority.allows_in_process_rotation(),
        "configured material must be externally rotated"
    );

    let key_id_before = authority.active_key_id();
    let generation_before = authority.generation();
    let refused = authority
        .rotate()
        .await
        .expect_err("in-process rotation of configured material must be refused");
    assert!(
        matches!(
            refused,
            ferrum_edge::identity::jwt_svid::JwtSvidError::RotationRefused(_)
        ),
        "expected RotationRefused, got {refused:?}"
    );
    assert_eq!(authority.generation(), generation_before);
    assert_eq!(authority.active_key_id(), key_id_before);

    // The scheduled path is a permanent no-op too, so a rotation task cannot
    // reach the refusal on every tick.
    assert_eq!(
        authority.rotate_if_due().await.expect("no-op succeeds"),
        None
    );

    // And the surface still mints and validates against the unchanged key.
    let mut client = connect(&harness.path).await;
    let minted = client
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["spiffe://audience.test/api".to_string()],
            spiffe_id: String::new(),
        }))
        .await
        .expect("FetchJWTSVID still succeeds")
        .into_inner();
    client
        .validate_jwtsvid(workload_request(ValidateJwtsvidRequest {
            audience: "spiffe://audience.test/api".to_string(),
            svid: minted.svids[0].svid.clone(),
        }))
        .await
        .expect("the token validates against the unchanged authority");

    harness.shutdown().await;
}

#[tokio::test]
async fn two_replicas_on_one_configuration_validate_each_others_tokens() {
    // The HA half of the continuity contract: two independently started servers
    // handed the SAME signing material are one trust-domain authority. A token
    // minted by either must validate on the other, with no shared state.
    let jwt_key = signing_key_pem();
    let replica_a = Harness::start("repl-a", &jwt_key).await;
    let replica_b = Harness::start("repl-b", &jwt_key).await;

    let mut client_a = connect(&replica_a.path).await;
    let minted = client_a
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["spiffe://audience.test/api".to_string()],
            spiffe_id: String::new(),
        }))
        .await
        .expect("FetchJWTSVID succeeds on replica A")
        .into_inner();

    let mut client_b = connect(&replica_b.path).await;
    let validated = client_b
        .validate_jwtsvid(workload_request(ValidateJwtsvidRequest {
            audience: "spiffe://audience.test/api".to_string(),
            svid: minted.svids[0].svid.clone(),
        }))
        .await
        .expect("replica B validates replica A's token")
        .into_inner();
    assert_eq!(validated.spiffe_id, workload_id().as_str());

    // Their published bundles are byte-identical, which is what makes any
    // relying party unable to tell the two replicas apart.
    let jwks_of = |harness: &Harness| {
        ferrum_edge::identity::jwt_svid::jwks_document(
            &harness
                .ca
                .jwt_signer()
                .expect("configured material yields a signer")
                .authorities(),
        )
        .expect("JWKS builds")
    };
    assert_eq!(
        jwks_of(&replica_a),
        jwks_of(&replica_b),
        "two replicas of one configuration must publish a byte-identical JWKS"
    );

    replica_a.shutdown().await;
    replica_b.shutdown().await;
}

#[tokio::test]
async fn the_bound_socket_carries_the_configured_mode_and_is_owned_by_this_process() {
    // The bound identity Ferrum verifies before serving: a socket, owned by this
    // process, at exactly the configured mode.
    //
    // Ferrum never touches the process umask — it binds inside a private 0700
    // staging directory, sets and verifies the mode there, and publishes the inode
    // into place — so a permissive ambient umask must neither widen the endpoint
    // nor be observable in the published artifact. The umask is set to 0o000
    // here to prove exactly that: it is the state that WOULD have leaked through
    // if publication depended on it.
    let previous = unsafe { libc::umask(0o000) };
    let harness = Harness::start("mode", &signing_key_pem()).await;
    let umask_after_bind = unsafe { libc::umask(previous) };
    assert_eq!(
        umask_after_bind, 0o000,
        "publishing the socket must not mutate the process umask; it is global state that other \
         already-running runtime tasks create files under"
    );

    let metadata = std::fs::symlink_metadata(&harness.path).expect("socket exists after bind");
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        assert!(metadata.file_type().is_socket());
        assert_eq!(
            metadata.mode() & 0o777,
            SOCKET_MODE,
            "a permissive ambient umask must not widen the credential endpoint"
        );
        assert_eq!(
            metadata.uid(),
            unsafe { libc::geteuid() },
            "the bound socket must be owned by this process"
        );
    }

    harness.shutdown().await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn listener_retains_the_lifecycle_lock_until_socket_cleanup_finishes() {
    use std::ffi::OsString;
    use std::os::fd::AsRawFd;

    let harness = Harness::start("lifecycle-lock", &signing_key_pem()).await;
    let mut lock_name = OsString::from(".");
    lock_name.push(harness.path.file_name().expect("socket has a filename"));
    lock_name.push(".startup.lock");
    let lock_path = harness
        .path
        .parent()
        .expect("socket has a parent")
        .join(lock_name);
    let contender = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .expect("open lifecycle lock sidecar");

    let locked = unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(locked, -1, "a serving listener must retain the lock");
    assert_eq!(
        std::io::Error::last_os_error().kind(),
        std::io::ErrorKind::WouldBlock,
        "the retained listener lock, not an unrelated I/O failure, must block the contender"
    );

    let path = harness.shutdown().await;
    assert!(
        !path.exists(),
        "socket cleanup completes before lock release"
    );
    let acquired_after_cleanup =
        unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(
        acquired_after_cleanup, 0,
        "a replacement may acquire the lifecycle boundary only after cleanup"
    );
    let _ = unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_UN) };
}

#[tokio::test]
async fn shutdown_does_not_unlink_an_artifact_that_replaced_our_socket() {
    // The replacement race: if something takes over the path while Ferrum is
    // serving, the inode-checked cleanup must leave the replacement alone rather
    // than deleting an artifact Ferrum never created.
    let harness = Harness::start("replace", &signing_key_pem()).await;
    let path = harness.path.clone();
    assert!(path.exists(), "the socket exists while serving");

    // Replace the inode at the path (the shape a hostile or a restarted peer
    // would produce), then shut down.
    std::fs::remove_file(&path).expect("test removes the bound socket");
    std::fs::write(&path, b"someone else's artifact").expect("test writes a replacement");
    harness.shutdown().await;

    assert_eq!(
        std::fs::read(&path).expect("the replacement survives shutdown"),
        b"someone else's artifact",
        "cleanup must unlink only the exact inode Ferrum bound"
    );
    std::fs::remove_file(&path).expect("test cleanup");
}

#[tokio::test]
async fn a_socket_path_under_an_untrusted_ancestor_is_refused_before_bind() {
    // Validation covers every directory component, so a pristine parent under a
    // world-writable ancestor is still refused — and nothing is created.
    let base = std::fs::canonicalize(std::env::temp_dir()).expect("temp dir canonicalizes");
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after the epoch")
        .as_nanos();
    let ancestor = base.join(format!("fe-wl-anc-{}", unique % 1_000_000_000));
    let parent = ancestor.join("p");
    std::fs::create_dir_all(&parent).expect("create ancestor/parent");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
            .expect("chmod parent");
        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o777))
            .expect("chmod ancestor");
    }
    let socket = parent.join("api.sock");

    let ca = internal_ca_with_jwt_key(&signing_key_pem());
    let service = WorkloadApiService::new(
        vec![Arc::new(FixedAttestor) as Arc<dyn Attestor>],
        ca as Arc<dyn CertificateAuthority>,
        trust_domain(),
        600,
    );
    let config = WorkloadApiSocketConfig::from_parts(socket.clone(), "0660").expect("mode parses");
    let refused = serve_workload_api(service, config)
        .await
        .expect_err("a world-writable ancestor must be refused before bind");
    assert!(
        refused.to_string().contains("group- or world-writable"),
        "unexpected refusal reason: {refused}"
    );
    assert!(
        !socket.exists(),
        "a refused configuration must not have created a socket"
    );

    let _ = std::fs::remove_dir_all(&ancestor);
}

#[tokio::test]
async fn a_second_start_refuses_a_live_same_uid_socket_and_leaves_it_serving() {
    // The take-over race. Ownership was never evidence of staleness: two Ferrum
    // processes run as the same uid, so an owner-only check let the second one
    // unlink the first one's LIVE Workload API socket and become the endpoint
    // workloads dial for their identity. Liveness is now proven with a real
    // connect(2), and a live socket fails startup.
    use std::os::unix::fs::MetadataExt;

    let first = Harness::start("live", &signing_key_pem()).await;
    let path = first.path.clone();
    let inode_before = std::fs::symlink_metadata(&path)
        .expect("the first server's socket exists")
        .ino();

    let ca = internal_ca_with_jwt_key(&signing_key_pem());
    let service = WorkloadApiService::new(
        vec![Arc::new(FixedAttestor) as Arc<dyn Attestor>],
        ca as Arc<dyn CertificateAuthority>,
        trust_domain(),
        600,
    );
    let socket = WorkloadApiSocketConfig::from_parts(path.clone(), "0660").expect("mode parses");
    let refused = serve_workload_api(service, socket)
        .await
        .expect_err("a LIVE same-uid socket must not be taken over");
    assert!(
        refused.to_string().contains("LIVE"),
        "unexpected refusal reason: {refused}"
    );

    // The first server owns the same inode at the same path and still answers.
    assert_eq!(
        std::fs::symlink_metadata(&path)
            .expect("the live socket survives the refused start")
            .ino(),
        inode_before,
        "the refused start must not have unlinked or replaced the live socket"
    );
    let mut client = connect(&path).await;
    let minted = client
        .fetch_jwtsvid(workload_request(JwtsvidRequest {
            audience: vec!["spiffe://audience.test/api".to_string()],
            spiffe_id: String::new(),
        }))
        .await
        .expect("the original server is still serving on its socket")
        .into_inner();
    assert_eq!(minted.svids[0].spiffe_id, workload_id().as_str());

    drop(client);
    first.shutdown().await;
}

#[tokio::test]
async fn a_stale_socket_with_no_listener_is_still_cleared() {
    // The other half of the same contract: a crashed predecessor leaves a socket
    // inode behind with nothing bound to it, `bind` would fail EADDRINUSE, and
    // that case must still start. Dropping a std listener leaves the file on
    // disk without a listener, which is exactly the crashed-run shape.
    let path = socket_path("stale");
    let leftover =
        std::os::unix::net::UnixListener::bind(&path).expect("test can bind a leftover socket");
    drop(leftover);
    assert!(path.exists(), "the leftover socket file remains on disk");

    let ca = internal_ca_with_jwt_key(&signing_key_pem());
    let service = WorkloadApiService::new(
        vec![Arc::new(FixedAttestor) as Arc<dyn Attestor>],
        ca as Arc<dyn CertificateAuthority>,
        trust_domain(),
        600,
    );
    let socket = WorkloadApiSocketConfig::from_parts(path.clone(), "0660").expect("mode parses");
    let listener = serve_workload_api(service, socket)
        .await
        .expect("a genuinely stale socket is cleared and rebound");

    let mut client = connect(&path).await;
    client
        .fetch_jwt_bundles(workload_request(JwtBundlesRequest {}))
        .await
        .expect("the newly bound server serves");
    drop(client);
    listener.shutdown().await;
    assert!(!path.exists(), "shutdown unlinks the socket it created");
}

#[tokio::test]
async fn concurrent_stale_cleanup_publishes_one_listener_without_unlinking_the_winner() {
    // Both startups can positively probe the same leftover inode before either
    // removes it. An inode recheck alone is insufficient: one can then publish
    // between the other's recheck and pathname unlink. The per-socket startup
    // lock must serialize cleanup through publication, leaving exactly one
    // serving winner and making the loser observe that winner as LIVE.
    let path = socket_path("stale-race");
    let leftover =
        std::os::unix::net::UnixListener::bind(&path).expect("test can bind a leftover socket");
    drop(leftover);

    let make_service = || {
        let ca = internal_ca_with_jwt_key(&signing_key_pem());
        WorkloadApiService::new(
            vec![Arc::new(FixedAttestor) as Arc<dyn Attestor>],
            ca as Arc<dyn CertificateAuthority>,
            trust_domain(),
            600,
        )
    };
    let first_config =
        WorkloadApiSocketConfig::from_parts(path.clone(), "0660").expect("mode parses");
    let second_config =
        WorkloadApiSocketConfig::from_parts(path.clone(), "0660").expect("mode parses");

    let (first, second) = tokio::join!(
        serve_workload_api(make_service(), first_config),
        serve_workload_api(make_service(), second_config),
    );
    let (winner, loser) = match (first, second) {
        (Ok(winner), Err(loser)) | (Err(loser), Ok(winner)) => (winner, loser),
        (Ok(first), Ok(second)) => {
            first.shutdown().await;
            second.shutdown().await;
            panic!("both concurrent startups published the same socket path");
        }
        (Err(first), Err(second)) => {
            panic!("both concurrent startups failed: first={first}; second={second}");
        }
    };
    assert!(
        loser.to_string().contains("LIVE"),
        "the serialized loser must probe the winner as live, got: {loser}"
    );

    let mut client = connect(&path).await;
    client
        .fetch_jwt_bundles(workload_request(JwtBundlesRequest {}))
        .await
        .expect("the winning listener remains reachable after the loser refuses");
    drop(client);
    winner.shutdown().await;
}

#[tokio::test]
async fn publication_leaves_no_staging_artifact_behind() {
    // The socket is bound inside a private 0700 staging directory and published
    // from there with a no-clobber primitive, so the parent directory must hold
    // exactly the published socket and its persistent startup-lock sidecar
    // afterwards — no `.fw-*` directory, no staged alias, no half-published
    // inode. The lock is intentionally retained so blocked flock waiters and a
    // newcomer can never coordinate through different inodes at one pathname.
    let base = std::fs::canonicalize(std::env::temp_dir()).expect("temp dir canonicalizes");
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after the epoch")
        .as_nanos();
    let parent = base.join(format!("fe-wl-stg-{}", unique % 1_000_000_000));
    std::fs::create_dir(&parent).expect("create the socket's parent directory");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
            .expect("chmod parent");
    }
    let path = parent.join("api.sock");

    let ca = internal_ca_with_jwt_key(&signing_key_pem());
    let service = WorkloadApiService::new(
        vec![Arc::new(FixedAttestor) as Arc<dyn Attestor>],
        ca as Arc<dyn CertificateAuthority>,
        trust_domain(),
        600,
    );
    let socket = WorkloadApiSocketConfig::from_parts(path.clone(), "0660").expect("mode parses");
    let listener = serve_workload_api(service, socket)
        .await
        .expect("the listener binds and publishes");

    let entries: Vec<String> = std::fs::read_dir(&parent)
        .expect("the parent directory is readable")
        .map(|entry| {
            entry
                .expect("directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(entries.len(), 2, "only the socket and startup lock remain");
    assert!(entries.iter().any(|entry| entry == "api.sock"));
    assert!(
        entries
            .iter()
            .any(|entry| entry == ".api.sock.startup.lock")
    );

    listener.shutdown().await;
    let _ = std::fs::remove_dir_all(&parent);
}

#[tokio::test]
async fn the_termination_signal_fires_when_the_serve_task_ends() {
    // The seam mesh mode observes: the serve task is spawned, so without a
    // published termination the runtime would keep serving traffic after the
    // identity endpoint had silently disappeared. The signal is set by a drop
    // guard inside the task, which is what makes it survive a panic unwind as
    // well as a clean return.
    let harness = Harness::start("term", &signing_key_pem()).await;
    let mut terminated = harness.listener.termination_signal();
    assert!(
        !*terminated.borrow(),
        "a serving listener must not report termination"
    );

    harness.listener.shutdown().await;

    // A requested shutdown publishes the same signal; distinguishing it from a
    // fault is the observer's job (mesh checks its shared shutdown flag first).
    tokio::time::timeout(std::time::Duration::from_secs(5), terminated.changed())
        .await
        .expect("the termination signal is published promptly")
        .expect("the sender outlives the serve task until it fires");
    assert!(*terminated.borrow(), "the serve task reported termination");
    assert!(
        !harness.path.exists(),
        "the socket artifact is cleaned up by the same guard"
    );
}
