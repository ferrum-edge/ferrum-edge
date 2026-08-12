//! Live data-path coverage for Gateway API `BackendTLSPolicy` (issue #3276).
//!
//! The integration suite proves what the *translator* emits. This suite proves
//! the emitted configuration actually changes traffic: a real gateway process
//! serves a K8s-translated config against a real TLS backend, and every
//! assertion is made on the wire.
//!
//! Covered:
//!
//! * `caCertificateRefs` → verified backend TLS with the policy's SNI/trust.
//! * an untrusted backend CA fails closed (502), never silently plaintext.
//! * a hostname/SAN-mismatched backend fails closed (502).
//! * `subjectAltNames` is enforced: a cert that chains and matches the SNI but
//!   carries no allow-listed SAN is still refused.
//! * `wellKnownCACertificates: System` does NOT inherit
//!   `FERRUM_TLS_CA_BUNDLE_PATH` — a backend signed by the cluster-global
//!   private CA is refused, which is the whole point of the `system://` source.
//! * live withdrawal: deleting the policy and SIGHUP-reloading returns the
//!   backend to plaintext, so the TLS-only backend stops answering.
//! * the backend-visible `Host`: the HTTP/1.1 SNI dial moves
//!   `validation.hostname` into the request URL's authority, so the backend must
//!   still be shown the REAL selected target's authority.
//!
//! Not covered, deliberately: the defensive `Host` fallback for a request that
//! arrives with no authority at all. Every route here is hostname-bound
//! (`hostnames: [app.example.com]`), so a request carrying no `Host` cannot
//! match a route and never reaches backend dispatch — there is no reachable
//! frontend shape for it in this fixture. The fallback stays as
//! defence-in-depth for frontends that can synthesize one.
//!
//! Run with:
//!   cargo build --bin ferrum-edge && cargo test --test functional_tests -- functional_gateway_backend_tls_policy --ignored --nocapture

use crate::common::{TestGateway, captured_output_reports_listener_addr_in_use};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

const BACKEND_SNI: &str = "backend.example.com";
const ROUTE_HOST: &str = "app.example.com";
/// Kubernetes namespace every fixture object lives in. It is also the
/// translation namespace, so every emitted resource is stamped with it — which
/// makes it the namespace the gateway subprocess must be told to load
/// (`FERRUM_NAMESPACE`), since file mode filters the document by namespace.
const K8S_NAMESPACE: &str = "default";
// Cluster DNS name the translator emits for the `reviews` Service in
// `default`. This is the authority the BACKEND must see, and it is distinct
// from `BACKEND_SNI` — which is the whole point of the Host assertion.

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

struct GeneratedCa {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

struct GeneratedCert {
    cert_pem: String,
    key_pem: String,
}

fn generate_ca(cn: &str) -> GeneratedCa {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("gen CA key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);
    let cert = params.self_signed(&key_pair).expect("self-sign CA");
    GeneratedCa {
        cert_pem: cert.pem(),
        issuer: Issuer::new(params, key_pair),
    }
}

fn generate_signed_cert(ca: &GeneratedCa, cn: &str, sans: &[&str]) -> GeneratedCert {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("gen leaf key");
    let san_strings: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
    let mut params = CertificateParams::new(san_strings).expect("leaf params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let cert = params.signed_by(&key_pair, &ca.issuer).expect("sign leaf");
    GeneratedCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    }
}

// ---------------------------------------------------------------------------
// TLS backend
// ---------------------------------------------------------------------------

/// TLS-only echo backend. It speaks no plaintext at all, which is what makes
/// the withdrawal assertion meaningful: once the policy is gone the gateway
/// dials plaintext and the backend cannot answer.
///
/// It also records the `Host` header of every request it serves and echoes it
/// back in the response body. That is the only place the backend-visible
/// authority can be observed on the wire, and it proves the H1 SNI dial (whose
/// URL authority is `validation.hostname`) does not replace the effective
/// HTTPRoute request authority with the TLS-only server name.
async fn start_https_echo_on(
    listener: TcpListener,
    cert_pem: &str,
    key_pem: &str,
) -> (tokio::task::JoinHandle<()>, Arc<Mutex<Vec<String>>>) {
    let cert = cert_pem.to_string();
    let key = key_pem.to_string();
    let observed_hosts: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&observed_hosts);
    let handle = tokio::spawn(async move {
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert.as_bytes())
            .filter_map(|r| r.ok())
            .collect();
        let pk = rustls_pemfile::private_key(&mut key.as_bytes())
            .expect("key parse")
            .expect("key present");
        let provider = rustls::crypto::ring::default_provider();
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(certs, pk)
            .expect("server cert");
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let recorder = Arc::clone(&recorder);
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = vec![0u8; 4096];
                let read = stream.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..read]).to_string();
                let host = request_host_header(&head).unwrap_or_default();
                // Keep the non-Send std::sync::MutexGuard in a lexical scope so
                // the spawned future cannot carry it across the response I/O
                // awaits below. An explicit drop() is not sufficient for every
                // compiler/control-flow analysis used by hosted CI.
                {
                    let mut seen = recorder.lock().expect("host recorder lock");
                    seen.push(host.clone());
                }
                let body = format!(r#"{{"status":"ok","tls":true,"host":"{host}"}}"#);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (handle, observed_hosts)
}

/// Extract the `Host` header value from a raw HTTP/1.1 request head.
fn request_host_header(head: &str) -> Option<String> {
    for line in head.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("host") {
            return Some(value.trim().to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Kubernetes fixture → translated gateway config
// ---------------------------------------------------------------------------

fn k8s_object(api_version: &str, kind: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: K8S_NAMESPACE.to_string(),
            generation: Some(1),
            labels: Default::default(),
            creation_timestamp: None,
            deletion_timestamp: None,
            annotations: Default::default(),
        },
        spec,
        status: Value::Object(Default::default()),
    }
}

/// `validation` block variants under test.
enum PolicyValidation {
    /// ConfigMap-backed CA, optionally with a `subjectAltNames` allow-list.
    ConfigMapCa {
        sans: Vec<String>,
    },
    System,
}

/// Build the Kubernetes snapshot. `backend_port` is the *real* bound port of
/// the TLS echo backend, declared as the Service port so the translated
/// upstream target dials it directly.
fn k8s_objects(
    backend_port: u16,
    ca_pem: &str,
    policy: Option<PolicyValidation>,
) -> Vec<K8sObject> {
    let mut gateway_class = k8s_object(
        "gateway.networking.k8s.io/v1",
        "GatewayClass",
        "ferrum",
        json!({ "controllerName": "ferrum.io/gateway-controller" }),
    );
    gateway_class.metadata.namespace.clear();

    let mut objects = vec![
        gateway_class,
        k8s_object(
            "gateway.networking.k8s.io/v1",
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "http",
                    "port": 80,
                    "protocol": "HTTP",
                    "allowedRoutes": { "namespaces": { "from": "Same" } }
                }]
            }),
        ),
        k8s_object(
            "v1",
            "Service",
            "reviews",
            json!({
                "ports": [{ "name": "https", "port": backend_port, "targetPort": backend_port }]
            }),
        ),
        k8s_object(
            "v1",
            "ConfigMap",
            "reviews-ca",
            json!({ "data": { "ca.crt": ca_pem } }),
        ),
        k8s_object(
            "gateway.networking.k8s.io/v1",
            "HTTPRoute",
            "reviews-route",
            json!({
                "parentRefs": [{ "name": "edge" }],
                "hostnames": [ROUTE_HOST],
                "rules": [{
                    "matches": [{ "path": { "type": "PathPrefix", "value": "/api" } }],
                    "backendRefs": [{ "name": "reviews", "port": backend_port }]
                }]
            }),
        ),
    ];

    if let Some(validation) = policy {
        let validation = match validation {
            PolicyValidation::ConfigMapCa { sans } => {
                let mut block = json!({
                    "hostname": BACKEND_SNI,
                    "caCertificateRefs": [{
                        "group": "",
                        "kind": "ConfigMap",
                        "name": "reviews-ca"
                    }]
                });
                if !sans.is_empty() {
                    block["subjectAltNames"] = Value::Array(
                        sans.into_iter()
                            .map(|san| json!({ "type": "Hostname", "hostname": san }))
                            .collect(),
                    );
                }
                block
            }
            PolicyValidation::System => json!({
                "hostname": BACKEND_SNI,
                "wellKnownCACertificates": "System"
            }),
        };
        objects.push(k8s_object(
            "gateway.networking.k8s.io/v1",
            "BackendTLSPolicy",
            "reviews-tls",
            json!({
                "targetRefs": [{ "group": "", "kind": "Service", "name": "reviews" }],
                "validation": validation
            }),
        ));
    }

    objects
}

/// Translate the snapshot and render the file-mode document.
///
/// The only post-processing is `dns_override`: the translated upstream targets
/// name the Service's cluster DNS record, which does not exist off-cluster.
/// Every security-relevant field (`backend_scheme`, `backend_tls_sni`,
/// `backend_tls_server_ca_cert_path`, `backend_tls_san_allow_list`,
/// `backend_tls_verify_server_cert`) is used exactly as the translator emitted
/// it — that is what makes this a test of the translated policy and not of a
/// hand-written config.
///
/// The dispatch is deliberately NOT forced onto HTTP/1.1. The echo backend
/// offers only `http/1.1` in ALPN, so the direct-H2 pool cannot negotiate h2
/// and the request falls through to the reqwest HTTP/1.1 SNI dial — which is
/// exactly the path under test. Pinning `pool_enable_http2: false` would skip
/// that fallback (it is admitted at config load, but it takes the route
/// straight to reqwest rather than through the capability downgrade this
/// suite exercises).
fn translated_config_yaml(objects: &[K8sObject]) -> String {
    let options = K8sTranslationOptions::new(
        K8S_NAMESPACE.to_string(),
        TrustDomain::new("cluster.local").expect("trust domain"),
    );
    let mut translated = translate_k8s_objects(objects, options).expect("translate");
    for proxy in &mut translated.config.proxies {
        proxy.dns_override = Some("127.0.0.1".to_string());
    }

    let document = json!({
        "version": "1",
        "proxies": translated.config.proxies,
        "consumers": translated.config.consumers,
        "plugin_configs": translated.config.plugin_configs,
        "upstreams": translated.config.upstreams,
    });
    serde_yaml::to_string(&document).expect("serialize translated config")
}

// ---------------------------------------------------------------------------
// Gateway harness
// ---------------------------------------------------------------------------

/// Ephemeral-port reservations held until the moment the child binds them.
///
/// Root cause of the flake this replaces: the previous `alloc_port()` did
/// `TcpListener::bind("127.0.0.1:0").await.expect(..).local_addr()..port()`, so
/// the listener was a temporary dropped at the end of that expression. Every
/// port was released before anything owned it, which produced two distinct
/// `Address already in use` child deaths:
///
/// 1. **Self-collision, which no retry could fix.** The kernel may immediately
///    re-offer a just-released ephemeral port, and the four ports were allocated
///    by four independent calls with no exclusion between them. So
///    `FERRUM_PROXY_HTTP_PORT` and `FERRUM_PROXY_HTTPS_PORT` (or either admin
///    port) could be handed the *same* number. That collision is internal to the
///    attempt, so retrying only re-rolled the same dice.
/// 2. **Cross-test theft.** A concurrently running functional test's own fixture
///    could bind the released port during the gap before this child started.
///
/// Holding each reservation until just before `spawn()` fixes both: the four
/// ports are distinct *by construction* (the kernel cannot offer a port that is
/// still bound), and the unavoidable release-to-bind window — unavoidable
/// because a subprocess binds by port number, so the reservation must be
/// released first — shrinks to the spawn call itself, with every environment
/// variable already staged.
///
/// The residual window is covered, not slept on:
/// * the attempt loop below retries with **fresh** ports and a fresh reservation
///   set, per `.claude/rules/testing.md` ("every retry needs fresh ports"), and
/// * `TestGateway`'s spawn barrier binds readiness to **that child**: it requires
///   the authenticated `/health` detail tier with `ready: true` (which flips only
///   after every listener bind, so a competitor that stole the port cannot
///   satisfy it) and polls `Child::try_wait`, so a child that died on a lost race
///   is detected immediately instead of being waited out.
struct PortReservations {
    /// Kept alive purely so the kernel cannot re-offer these ports. Released as
    /// a set by [`Self::release`].
    listeners: Vec<TcpListener>,
    ports: Vec<u16>,
}

impl PortReservations {
    async fn take(count: usize) -> Self {
        let mut listeners = Vec::with_capacity(count);
        let mut ports = Vec::with_capacity(count);
        for _ in 0..count {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind ephemeral port reservation");
            ports.push(listener.local_addr().expect("addr").port());
            listeners.push(listener);
        }
        Self { listeners, ports }
    }

    fn port(&self, index: usize) -> u16 {
        self.ports[index]
    }

    /// Release every reservation, immediately before the child binds them.
    fn release(self) {
        drop(self.listeners);
    }
}

/// Spawn a file-mode gateway on the rendered config.
///
/// A retry is admitted for exactly one failure: this child reported a listener
/// bind that lost the ephemeral-port race documented on [`PortReservations`].
/// `TestGatewayBuilder::spawn`'s blanket retry loop would also re-roll a
/// rejected config, a JWT/auth failure, a parse error, or any other
/// deterministic child fault and then report it three attempts later as
/// "gateway failed to start", masking exactly the failures this suite exists to
/// detect. `spawn_classified` makes one attempt and classifies structurally
/// (see `captured_output_reports_listener_addr_in_use`); every other failure
/// stops immediately with the child's captured diagnostics. Each retry takes a
/// fresh reservation set, per `.claude/rules/testing.md`.
fn exact_listener_config(config_yaml: &str, proxy_http: u16) -> String {
    let mut config: serde_yaml::Value =
        serde_yaml::from_str(config_yaml).expect("translated config YAML");
    for proxy in config["proxies"]
        .as_sequence_mut()
        .expect("translated config proxies")
    {
        if proxy["listen_port"].as_u64() == Some(80) {
            proxy["listen_port"] =
                serde_yaml::to_value(proxy_http).expect("serialize exact listener port");
        }
    }
    serde_yaml::to_string(&config).expect("serialize exact-listener translated config")
}

async fn start_gateway(config_yaml: &str, extra_env: Vec<(String, String)>) -> (TestGateway, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    const PROXY_HTTP: usize = 0;
    const PROXY_HTTPS: usize = 1;
    const ADMIN_HTTP: usize = 2;
    const ADMIN_HTTPS: usize = 3;
    let mut last_error = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        let ports = PortReservations::take(4).await;
        let proxy_http = ports.port(PROXY_HTTP);
        let exact_listener_config = exact_listener_config(config_yaml, proxy_http);
        let mut builder = TestGateway::builder()
            // This suite exercises backend TLS, not Service-port remapping.
            // Bind its Gateway listener to the process-global test frontend so
            // parallel fixtures that also declare :80 cannot turn a real
            // EADDRINUSE refusal into an unrelated 404.
            .mode_file(exact_listener_config)
            // The translator stamps every resource with the Kubernetes
            // namespace (`default`), and file mode filters the loaded document
            // down to `FERRUM_NAMESPACE` — whose default is `ferrum`. Without
            // this the child starts cleanly on an empty config and answers
            // every probe with 404 instead of exercising backend TLS.
            .namespace(K8S_NAMESPACE)
            // The outer loop owns retries so each attempt gets a fresh
            // reservation set; an inner retry would reuse these ports.
            .max_attempts(1)
            .capture_output()
            .env("FERRUM_PROXY_HTTP_PORT", proxy_http.to_string())
            .env(
                "FERRUM_PROXY_HTTPS_PORT",
                ports.port(PROXY_HTTPS).to_string(),
            )
            .env("FERRUM_ADMIN_HTTP_PORT", ports.port(ADMIN_HTTP).to_string())
            .env(
                "FERRUM_ADMIN_HTTPS_PORT",
                ports.port(ADMIN_HTTPS).to_string(),
            )
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .env("FERRUM_TLS_NO_VERIFY", "false");
        for (key, value) in &extra_env {
            builder = builder.env(key.clone(), value.clone());
        }
        // Everything the child needs is staged; hand the ports over now.
        ports.release();
        match builder.spawn_classified().await {
            Ok(gateway) => return (gateway, proxy_http),
            Err(failure) if failure.listener_addr_in_use => {
                last_error = failure.detail;
                eprintln!(
                    "gateway spawn attempt {attempt} lost an ephemeral-port race; \
                     retrying with fresh ports: {last_error}"
                );
            }
            Err(failure) => {
                panic!(
                    "gateway spawn failed for a reason no retry can fix (attempt {attempt}): {}",
                    failure.detail
                );
            }
        }
    }
    panic!("gateway failed to start after {MAX_ATTEMPTS} port races: {last_error}");
}

async fn get_status(proxy_http: u16, path: &str) -> u16 {
    get_response(proxy_http, path).await.0
}

/// Status plus body, so a test can assert what the BACKEND saw.
async fn get_response(proxy_http: u16, path: &str) -> (u16, String) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");
    let response = client
        .get(format!("http://127.0.0.1:{proxy_http}{path}"))
        .header("Host", ROUTE_HOST)
        .send()
        .await
        .expect("gateway must answer, not hang");
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    (status, body)
}

/// Poll through the bounded SIGHUP reload window instead of assuming a loaded
/// hosted runner will apply the new snapshot within a fixed sleep.
///
/// The child is polled between probes: a gateway that died during the reload
/// answers every subsequent probe with a connection error, which is
/// indistinguishable from "not converged yet" and would otherwise be waited out
/// for the full deadline and then reported as a convergence failure. Observing
/// the exit turns that into an immediate, correctly-attributed failure with the
/// child's captured output.
async fn wait_for_status(
    gateway: &mut TestGateway,
    proxy_http: u16,
    path: &str,
    expected: u16,
) -> u16 {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("client");
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let last = match client
            .get(format!("http://127.0.0.1:{proxy_http}{path}"))
            .header("Host", ROUTE_HOST)
            .send()
            .await
        {
            Ok(response) if response.status().as_u16() == expected => return expected,
            Ok(response) => format!("HTTP {}", response.status()),
            Err(error) => error.to_string(),
        };
        assert!(
            gateway.is_running(),
            "gateway exited during the reload instead of converging to HTTP \
             {expected}; last observation: {last}\n--- captured gateway output ---\n{}",
            gateway.diagnostic_captured_output()
        );
        assert!(
            Instant::now() < deadline,
            "gateway did not converge to HTTP {expected} before the reload deadline; last observation: {last}"
        );
        sleep(Duration::from_millis(100)).await;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Trusted CA + matching SNI + matching SAN allow-list → verified backend TLS.
#[ignore]
#[tokio::test]
async fn backend_tls_policy_performs_verified_backend_tls() {
    let ca = generate_ca("Reviews-CA");
    let backend = generate_signed_cert(&ca, "reviews", &[BACKEND_SNI]);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let backend_port = listener.local_addr().expect("addr").port();
    let (echo, observed_hosts) =
        start_https_echo_on(listener, &backend.cert_pem, &backend.key_pem).await;

    let objects = k8s_objects(
        backend_port,
        &ca.cert_pem,
        Some(PolicyValidation::ConfigMapCa {
            sans: vec![BACKEND_SNI.to_string()],
        }),
    );
    let (mut gateway, proxy_http) =
        start_gateway(&translated_config_yaml(&objects), Vec::new()).await;

    let (status, body) = get_response(proxy_http, "/api/test").await;
    assert_eq!(
        status, 200,
        "a trusted, SNI- and SAN-matching backend must be reachable over TLS"
    );

    // The H1 SNI dial puts `validation.hostname` in the request URL's authority
    // (reqwest derives the rustls server name from the URL and exposes no
    // per-request hook). Gateway API preserves the HTTPRoute request Host unless
    // a route filter rewrites it; BackendTLSPolicy changes only TLS SNI and
    // certificate validation. Assert that boundary on the wire: the backend
    // must see the effective request authority, never `validation.hostname`.
    let observed = observed_hosts
        .lock()
        .expect("host recorder lock")
        .last()
        .cloned()
        .expect("the backend must have served the request");
    let expected_authority = ROUTE_HOST.to_string();
    assert_eq!(
        observed, expected_authority,
        "BackendTLSPolicy must not replace the effective request Host with validation.hostname"
    );
    assert!(
        !observed.contains(BACKEND_SNI),
        "validation.hostname must never reach the backend as Host: {observed}"
    );
    // ...and the response body the client received carries the same value, so a
    // future change that drops the explicit Host cannot pass by recording only.
    let expected_echo = format!(r#""host":"{expected_authority}""#);
    assert!(
        body.contains(&expected_echo),
        "backend-echoed Host must retain the effective request authority, got body {body}"
    );

    gateway.shutdown();
    echo.abort();
}

/// The backend chains to a CA the policy does not name → fail closed.
#[ignore]
#[tokio::test]
async fn backend_tls_policy_untrusted_backend_ca_fails_closed() {
    let trusted_ca = generate_ca("Trusted-CA");
    let rogue_ca = generate_ca("Rogue-CA");
    let backend = generate_signed_cert(&rogue_ca, "reviews", &[BACKEND_SNI]);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let backend_port = listener.local_addr().expect("addr").port();
    let (echo, _observed_hosts) =
        start_https_echo_on(listener, &backend.cert_pem, &backend.key_pem).await;

    let objects = k8s_objects(
        backend_port,
        &trusted_ca.cert_pem,
        Some(PolicyValidation::ConfigMapCa { sans: Vec::new() }),
    );
    let (mut gateway, proxy_http) =
        start_gateway(&translated_config_yaml(&objects), Vec::new()).await;

    assert_eq!(
        get_status(proxy_http, "/api/test").await,
        502,
        "an untrusted backend chain must fail closed, never fall back to plaintext"
    );

    gateway.shutdown();
    echo.abort();
}

/// The backend chains correctly but its SANs do not cover the policy hostname.
#[ignore]
#[tokio::test]
async fn backend_tls_policy_hostname_mismatch_fails_closed() {
    let ca = generate_ca("Reviews-CA");
    let backend = generate_signed_cert(&ca, "reviews", &["some-other-host.example.com"]);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let backend_port = listener.local_addr().expect("addr").port();
    let (echo, _observed_hosts) =
        start_https_echo_on(listener, &backend.cert_pem, &backend.key_pem).await;

    let objects = k8s_objects(
        backend_port,
        &ca.cert_pem,
        Some(PolicyValidation::ConfigMapCa { sans: Vec::new() }),
    );
    let (mut gateway, proxy_http) =
        start_gateway(&translated_config_yaml(&objects), Vec::new()).await;

    assert_eq!(
        get_status(proxy_http, "/api/test").await,
        502,
        "validation.hostname must be enforced as the verified certificate name"
    );

    gateway.shutdown();
    echo.abort();
}

/// The chain and the SNI both verify, but no SAN matches the allow-list.
#[ignore]
#[tokio::test]
async fn backend_tls_policy_subject_alt_name_allow_list_is_enforced() {
    let ca = generate_ca("Reviews-CA");
    // The cert covers the policy hostname, so chain + name verification pass;
    // only the explicit `subjectAltNames` allow-list can reject it.
    let backend = generate_signed_cert(&ca, "reviews", &[BACKEND_SNI]);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let backend_port = listener.local_addr().expect("addr").port();
    let (echo, _observed_hosts) =
        start_https_echo_on(listener, &backend.cert_pem, &backend.key_pem).await;

    let objects = k8s_objects(
        backend_port,
        &ca.cert_pem,
        Some(PolicyValidation::ConfigMapCa {
            sans: vec!["not-presented.example.com".to_string()],
        }),
    );
    let (mut gateway, proxy_http) =
        start_gateway(&translated_config_yaml(&objects), Vec::new()).await;

    assert_eq!(
        get_status(proxy_http, "/api/test").await,
        502,
        "subjectAltNames must be enforced independently of chain and name verification"
    );

    gateway.shutdown();
    echo.abort();
}

/// `wellKnownCACertificates: System` must pin the built-in roots.
///
/// This is the security boundary the `system://` source exists for. The
/// cluster-global `FERRUM_TLS_CA_BUNDLE_PATH` names the private CA that signed
/// the backend, so before `system://` the request succeeded — the private CA had
/// silently replaced the public trust anchors the policy asked for. It must now
/// fail closed.
#[ignore]
#[tokio::test]
async fn backend_tls_policy_system_roots_ignore_global_ca_bundle() {
    let cluster_ca = generate_ca("Cluster-Private-CA");
    let backend = generate_signed_cert(&cluster_ca, "reviews", &[BACKEND_SNI]);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let backend_port = listener.local_addr().expect("addr").port();
    let (echo, _observed_hosts) =
        start_https_echo_on(listener, &backend.cert_pem, &backend.key_pem).await;

    let temp = TempDir::new().expect("tempdir");
    let global_ca_path = temp.path().join("cluster-ca.pem");
    std::fs::write(&global_ca_path, &cluster_ca.cert_pem).expect("write global CA");

    let objects = k8s_objects(
        backend_port,
        &cluster_ca.cert_pem,
        Some(PolicyValidation::System),
    );
    let (mut gateway, proxy_http) = start_gateway(
        &translated_config_yaml(&objects),
        vec![(
            "FERRUM_TLS_CA_BUNDLE_PATH".to_string(),
            global_ca_path.to_string_lossy().to_string(),
        )],
    )
    .await;

    assert_eq!(
        get_status(proxy_http, "/api/test").await,
        502,
        "System trust must not inherit the cluster-global private CA bundle"
    );

    gateway.shutdown();
    echo.abort();

    // Positive control on the same backend and the same global bundle: naming
    // the CA through `caCertificateRefs` is trusted, so the 502 above is about
    // trust-anchor selection and not about the fixture being unreachable.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let backend_port = listener.local_addr().expect("addr").port();
    let (echo, _observed_hosts) =
        start_https_echo_on(listener, &backend.cert_pem, &backend.key_pem).await;
    let objects = k8s_objects(
        backend_port,
        &cluster_ca.cert_pem,
        Some(PolicyValidation::ConfigMapCa { sans: Vec::new() }),
    );
    let (mut gateway, proxy_http) = start_gateway(
        &translated_config_yaml(&objects),
        vec![(
            "FERRUM_TLS_CA_BUNDLE_PATH".to_string(),
            global_ca_path.to_string_lossy().to_string(),
        )],
    )
    .await;
    assert_eq!(get_status(proxy_http, "/api/test").await, 200);
    gateway.shutdown();
    echo.abort();
}

/// Deleting the policy and reloading withdraws backend TLS on the live config.
#[cfg(unix)]
#[ignore]
#[tokio::test]
async fn backend_tls_policy_withdrawal_reaches_the_live_data_path() {
    let ca = generate_ca("Reviews-CA");
    let backend = generate_signed_cert(&ca, "reviews", &[BACKEND_SNI]);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let backend_port = listener.local_addr().expect("addr").port();
    let (echo, _observed_hosts) =
        start_https_echo_on(listener, &backend.cert_pem, &backend.key_pem).await;

    let with_policy = k8s_objects(
        backend_port,
        &ca.cert_pem,
        Some(PolicyValidation::ConfigMapCa { sans: Vec::new() }),
    );
    let (mut gateway, proxy_http) =
        start_gateway(&translated_config_yaml(&with_policy), Vec::new()).await;
    assert_eq!(
        get_status(proxy_http, "/api/test").await,
        200,
        "baseline: the policy-backed TLS route works"
    );

    // Withdraw the policy from the Kubernetes snapshot, re-translate, and
    // SIGHUP the running gateway.
    let without_policy = k8s_objects(backend_port, &ca.cert_pem, None);
    let config_path = gateway
        .config_path
        .as_ref()
        .expect("file-mode harness must populate config_path");
    std::fs::write(
        config_path,
        exact_listener_config(&translated_config_yaml(&without_policy), proxy_http),
    )
    .expect("rewrite translated config");
    let pid = gateway.pid().expect("gateway still running");
    let signal = std::process::Command::new("kill")
        .args(["-HUP", &pid.to_string()])
        .output()
        .expect("invoke SIGHUP command");
    assert!(
        signal.status.success(),
        "SIGHUP command failed: {}",
        String::from_utf8_lossy(&signal.stderr)
    );

    // The backend speaks TLS only, so a withdrawn policy — which returns the
    // route to a plaintext direct backend — must stop succeeding.
    assert_eq!(
        wait_for_status(&mut gateway, proxy_http, "/api/test", 502).await,
        502,
        "withdrawing the policy must reach the live data path, not just the config"
    );

    gateway.shutdown();
    echo.abort();
}

/// Deterministic, gateway-free assertion of the retry classification
/// [`start_gateway`] depends on: only this child's own listener-bind
/// address-in-use failure may be retried. Everything else — a rejected config,
/// an auth failure, a parse error — must stop the suite immediately, which is
/// what the `panic!` arm in `start_gateway` does.
///
/// Not `#[ignore]`d: it spawns nothing, and the functional shards run with
/// `--run-ignored=all`, so it executes alongside the live tests.
#[test]
fn start_gateway_retries_only_a_listener_address_race() {
    let port_race = r#"{"level":"ERROR","fields":{"message":"Gateway listener task 'proxy_https' failed: Address already in use (os error 98)"}}"#;
    assert!(
        captured_output_reports_listener_addr_in_use(port_race),
        "a listener bind that lost the port race is the one retryable failure"
    );

    for deterministic in [
        r#"{"level":"ERROR","fields":{"message":"Configuration validation failed: 1 invalid upstream reference(s) found"}}"#,
        r#"{"level":"ERROR","fields":{"message":"Gateway listener task 'proxy_https' failed: Permission denied (os error 13)"}}"#,
        r#"{"level":"ERROR","fields":{"message":"Failed to load TLS material"},"detail":"Address already in use"}"#,
        "gateway did not prove ownership of admin port 1234 within 30s",
    ] {
        assert!(
            !captured_output_reports_listener_addr_in_use(deterministic),
            "must not be retried: {deterministic}"
        );
    }
}
