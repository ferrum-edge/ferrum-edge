//! Request-path coverage for Gateway API rules that share one listener's
//! route slot but dial their backends over different transports (#6290).
//!
//! One route-table slot keeps one backend scheme, so the translator refuses
//! the later of two same-slot rules whose BackendTLSPolicy coverage differs.
//! The translation tests in `gateway_api_backend_tls_policy_tests` pin what is
//! emitted; these tests drive real requests through `modes::file::serve` (the
//! binary's own entry point, with the Gateway listener bound by
//! `GatewayListenerManager`) and prove what the data plane does with it:
//!
//! - the surviving method reaches its own backend over its own transport —
//!   plaintext to an HTTP-only backend, TLS to a TLS-only backend, so a wrong
//!   transport cannot answer 200;
//! - the refused method reaches NEITHER backend and gets the gateway's
//!   unmatched-route 404;
//! - controls: the same two rules on separate paths, or on separate listeners,
//!   are both served.
//!
//! The only post-processing of the translated config is `dns_override` (the
//! Service DNS names do not exist off-cluster) and moving each Gateway
//! listener port onto a test-owned port. Every transport-relevant field is used
//! exactly as the translator emitted it.

use crate::scaffolding::port_registry::TestSocket;

use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use ferrum_edge::config::EnvConfig;
use ferrum_edge::config::env_config::OperatingMode;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::FERRUM_GATEWAY_CONTROLLER_NAME;
use ferrum_edge::modes::file::{ServeHandles, ServeOptions, serve};

const K8S_NAMESPACE: &str = "default";
const ROUTE_HOST: &str = "app.example.com";
const BACKEND_SNI: &str = "backend.example.com";
const PLAIN_BODY: &str = "plain-backend";
const SECURE_BODY: &str = "secure-backend";
/// Declared Gateway listener ports, rewritten onto test-owned ports.
const LISTENER_A_PORT: u16 = 80;
const LISTENER_B_PORT: u16 = 8080;
/// Translator warning for a same-slot transport refusal.
const TRANSPORT_REFUSAL_WARNING: &str = "dials its backend over a different transport";
const GATEWAY_STARTUP_ATTEMPTS: u32 = 3;

static INIT_CRYPTO: Once = Once::new();

fn ensure_crypto_provider() {
    INIT_CRYPTO.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

struct TestCa {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

fn test_ca() -> TestCa {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("CA key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "mixed-transport-ca");
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    let cert = params.self_signed(&key_pair).expect("self-sign CA");
    TestCa {
        cert_pem: cert.pem(),
        issuer: Issuer::new(params, key_pair),
    }
}

/// Leaf for the BackendTLSPolicy hostname, signed by `ca`.
fn backend_leaf(ca: &TestCa) -> (String, String) {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut params = CertificateParams::new(vec![BACKEND_SNI.to_string()]).expect("leaf params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, BACKEND_SNI);
    let cert = params.signed_by(&key_pair, &ca.issuer).expect("sign leaf");
    (cert.pem(), key_pair.serialize_pem())
}

// ---------------------------------------------------------------------------
// Backends
// ---------------------------------------------------------------------------

/// Methods of the requests one backend actually served.
#[derive(Clone, Default)]
struct ServedMethods(Arc<Mutex<Vec<String>>>);

impl ServedMethods {
    fn record(&self, method: &str) {
        self.0
            .lock()
            .expect("served-methods lock")
            .push(method.to_string());
    }

    fn snapshot(&self) -> Vec<String> {
        self.0.lock().expect("served-methods lock").clone()
    }

    fn served(&self, method: &str) -> bool {
        self.snapshot().iter().any(|served| served == method)
    }
}

/// Plaintext-only HTTP/1.1 backend. A TLS dial cannot complete against it.
async fn start_plain_backend() -> (u16, ServedMethods, tokio::task::JoinHandle<()>) {
    use hyper::server::conn::http1;
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind plaintext backend");
    let port = listener.local_addr().expect("backend addr").port();
    let served = ServedMethods::default();
    let recorder = served.clone();
    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let recorder = recorder.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<Incoming>| {
                    recorder.record(req.method().as_str());
                    async move {
                        Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(200)
                                .header("content-type", "text/plain")
                                .body(Full::new(Bytes::from_static(PLAIN_BODY.as_bytes())))
                                .expect("plaintext backend response"),
                        )
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    (port, served, handle)
}

/// TLS-only HTTP/1.1 backend. It speaks no plaintext, so a plaintext dial
/// cannot be answered.
async fn start_tls_backend(
    cert_pem: &str,
    key_pem: &str,
) -> (u16, ServedMethods, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind TLS backend");
    let port = listener.local_addr().expect("backend addr").port();
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .expect("backend cert parse");
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).expect("backend key parse");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("backend server cert");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let served = ServedMethods::default();
    let recorder = served.clone();
    let handle = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let recorder = recorder.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = vec![0u8; 4096];
                let read = stream.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..read]).to_string();
                let Some(method) = head.split_whitespace().next() else {
                    return;
                };
                recorder.record(method);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{SECURE_BODY}",
                    SECURE_BODY.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (port, served, handle)
}

struct Backends {
    plain_port: u16,
    plain: ServedMethods,
    secure_port: u16,
    secure: ServedMethods,
    ca_pem: String,
    _handles: Vec<tokio::task::JoinHandle<()>>,
}

async fn start_backends() -> Backends {
    let ca = test_ca();
    let (cert_pem, key_pem) = backend_leaf(&ca);
    let (plain_port, plain, plain_handle) = start_plain_backend().await;
    let (secure_port, secure, secure_handle) = start_tls_backend(&cert_pem, &key_pem).await;
    Backends {
        plain_port,
        plain,
        secure_port,
        secure,
        ca_pem: ca.cert_pem,
        _handles: vec![plain_handle, secure_handle],
    }
}

// ---------------------------------------------------------------------------
// Kubernetes fixture
// ---------------------------------------------------------------------------

fn k8s_object(api_version: &str, kind: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: format!("uid-{name}"),
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

/// One HTTPRoute rule matching `method` on `path` and forwarding to `service`.
fn method_rule(method: &str, path: &str, service: &str, port: u16) -> Value {
    json!({
        "matches": [{
            "path": { "type": "PathPrefix", "value": path },
            "method": method
        }],
        "backendRefs": [{ "name": service, "port": port }]
    })
}

fn http_route(name: &str, parent_ref: Value, rules: Vec<Value>) -> K8sObject {
    k8s_object(
        "gateway.networking.k8s.io/v1",
        "HTTPRoute",
        name,
        json!({
            "parentRefs": [parent_ref],
            "hostnames": [ROUTE_HOST],
            "rules": rules
        }),
    )
}

/// GatewayClass, Gateway, the plaintext and TLS Services, and a
/// BackendTLSPolicy covering only the TLS Service. `two_listeners` adds a
/// second plaintext listener `alt` beside `http`.
fn base_objects(backends: &Backends, two_listeners: bool) -> Vec<K8sObject> {
    let mut gateway_class = k8s_object(
        "gateway.networking.k8s.io/v1",
        "GatewayClass",
        "ferrum",
        json!({ "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME }),
    );
    gateway_class.metadata.namespace.clear();

    let mut listeners = vec![json!({
        "name": "http",
        "port": LISTENER_A_PORT,
        "protocol": "HTTP",
        "allowedRoutes": { "namespaces": { "from": "Same" } }
    })];
    if two_listeners {
        listeners.push(json!({
            "name": "alt",
            "port": LISTENER_B_PORT,
            "protocol": "HTTP",
            "allowedRoutes": { "namespaces": { "from": "Same" } }
        }));
    }

    vec![
        gateway_class,
        k8s_object(
            "gateway.networking.k8s.io/v1",
            "Gateway",
            "edge",
            json!({ "gatewayClassName": "ferrum", "listeners": listeners }),
        ),
        k8s_object(
            "v1",
            "Service",
            "plain",
            json!({
                "selector": { "app": "plain" },
                "ports": [{
                    "name": "http",
                    "port": backends.plain_port,
                    "targetPort": backends.plain_port
                }]
            }),
        ),
        k8s_object(
            "v1",
            "Service",
            "secure",
            json!({
                "selector": { "app": "secure" },
                "ports": [{
                    "name": "https",
                    "port": backends.secure_port,
                    "targetPort": backends.secure_port
                }]
            }),
        ),
        k8s_object(
            "v1",
            "ConfigMap",
            "secure-ca",
            json!({ "data": { "ca.crt": backends.ca_pem } }),
        ),
        k8s_object(
            "gateway.networking.k8s.io/v1",
            "BackendTLSPolicy",
            "secure-tls",
            json!({
                "targetRefs": [{ "group": "", "kind": "Service", "name": "secure" }],
                "validation": {
                    "hostname": BACKEND_SNI,
                    "caCertificateRefs": [{
                        "group": "",
                        "kind": "ConfigMap",
                        "name": "secure-ca"
                    }]
                }
            }),
        ),
    ]
}

fn plain_get_rule(backends: &Backends, path: &str) -> Value {
    method_rule("GET", path, "plain", backends.plain_port)
}

fn secure_post_rule(backends: &Backends, path: &str) -> Value {
    method_rule("POST", path, "secure", backends.secure_port)
}

/// Translate the snapshot, asserting whether a transport refusal is reported.
fn translate(objects: &[K8sObject], expect_transport_refusal: bool) -> GatewayConfig {
    let options = K8sTranslationOptions::new(
        K8S_NAMESPACE.to_string(),
        TrustDomain::new("cluster.local").expect("trust domain"),
    );
    let mut translated = translate_k8s_objects(objects, options).expect("translate");
    let refused = translated
        .warnings
        .iter()
        .any(|warning| warning.contains(TRANSPORT_REFUSAL_WARNING));
    assert_eq!(
        refused, expect_transport_refusal,
        "transport refusal reported: {:?}",
        translated.warnings
    );
    for proxy in &mut translated.config.proxies {
        proxy.dns_override = Some("127.0.0.1".to_string());
    }
    translated.config
}

// ---------------------------------------------------------------------------
// Gateway harness
// ---------------------------------------------------------------------------

fn test_env_config() -> EnvConfig {
    EnvConfig {
        mode: OperatingMode::File,
        log_level: "error".into(),
        namespace: K8S_NAMESPACE.to_string(),
        proxy_http_port: 0,
        proxy_https_port: 0,
        admin_http_port: 0,
        admin_https_port: 0,
        admin_jwt_secret: Some("ferrum-edge-mixed-transport-test-secret-0000".to_string()),
        shutdown_drain_seconds: 0,
        max_connections: 0,
        pool_warmup_enabled: false,
        ..EnvConfig::default()
    }
}

struct RunningGateway {
    handles: ServeHandles,
    shutdown_tx: ferrum_edge::overload::ShutdownSender,
    /// Bound port of each declared Gateway listener port, in declared order.
    listener_ports: Vec<u16>,
}

impl RunningGateway {
    fn port_for(&self, declared: &[u16], declared_port: u16) -> u16 {
        let index = declared
            .iter()
            .position(|port| *port == declared_port)
            .expect("declared listener port");
        self.listener_ports[index]
    }

    async fn shutdown(self) {
        self.shutdown_tx.shutdown();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.handles.join()).await;
    }
}

/// Serve `config` with each declared Gateway listener port moved onto a fresh
/// test-owned port that `GatewayListenerManager` binds itself. A whole startup
/// is retried, with fresh ports, only when a listener port was lost to another
/// process between reservation and bind.
async fn start_gateway(config: &GatewayConfig, declared: &[u16]) -> RunningGateway {
    ensure_crypto_provider();
    for attempt in 1..=GATEWAY_STARTUP_ATTEMPTS {
        let mut listener_ports = Vec::with_capacity(declared.len());
        for _ in declared {
            listener_ports.push(
                crate::scaffolding::ports::unbound_port()
                    .await
                    .expect("reserve Gateway listener port"),
            );
        }
        let mut config = config.clone();
        for proxy in &mut config.proxies {
            if let Some(declared_port) = proxy.listen_port
                && let Some(index) = declared.iter().position(|port| *port == declared_port)
            {
                proxy.listen_port = Some(listener_ports[index]);
            }
        }

        let proxy_http = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind global proxy port");
        let admin_http = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind admin port");
        let (shutdown_tx, _) =
            ferrum_edge::overload::ShutdownSender::channel(std::time::Duration::ZERO);
        let handles = serve(
            test_env_config(),
            config,
            ServeOptions {
                proxy_http: Some(proxy_http),
                proxy_https: None,
                admin_http: Some(admin_http),
                admin_https: None,
                admin_jwt_manager: None,
                skip_initial_capability_refresh: true,
                background_drain_timeout: Some(Duration::from_millis(200)),
            },
            shutdown_tx.clone(),
        )
        .await
        .expect("file::serve must accept the translated config");

        let mut active = handles.gateway_listeners.active_ports().await;
        active.sort_unstable();
        let mut expected = listener_ports.clone();
        expected.sort_unstable();
        if active == expected {
            return RunningGateway {
                handles,
                shutdown_tx,
                listener_ports,
            };
        }

        let failures = handles.gateway_listeners.bind_failures();
        eprintln!(
            "mixed-transport gateway startup attempt {attempt}/{GATEWAY_STARTUP_ATTEMPTS} did not \
             bind every listener: want {expected:?}, active {active:?}, refusals {failures:?}"
        );
        shutdown_tx.shutdown();
        let _ = tokio::time::timeout(Duration::from_secs(5), handles.join()).await;
    }
    panic!("the Gateway listeners never all bound in {GATEWAY_STARTUP_ATTEMPTS} attempts")
}

/// One HTTP/1.1 request through the gateway: `(status, body)`.
async fn send(port: u16, method: &str, path: &str) -> (u16, String) {
    let exchange = async {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {ROUTE_HOST}\r\nContent-Length: 0\r\n\
             Connection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        Ok::<_, std::io::Error>(buf)
    };
    let buf = tokio::time::timeout(Duration::from_secs(15), exchange)
        .await
        .unwrap_or_else(|_| panic!("{method} {path} on port {port} timed out"))
        .unwrap_or_else(|error| panic!("{method} {path} on port {port} failed: {error}"));
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    (status, body)
}

async fn assert_served_by(port: u16, method: &str, path: &str, backend_body: &str) {
    let (status, body) = send(port, method, path).await;
    assert_eq!(
        status, 200,
        "{method} {path} must reach its backend over its own transport: {body}"
    );
    assert!(
        body.contains(backend_body),
        "{method} {path} must be answered by the {backend_body} backend: {body}"
    );
}

fn assert_only_served(backend: &ServedMethods, served: &str, never: &str) {
    assert!(
        backend.served(served) && !backend.served(never),
        "backend must have served {served} and never {never}: {:?}",
        backend.snapshot()
    );
}

fn assert_never_served(backend: &ServedMethods, method: &str) {
    assert!(
        !backend.served(method),
        "backend must never have served {method}: {:?}",
        backend.snapshot()
    );
}

async fn assert_unmatched(port: u16, method: &str, path: &str) {
    let (status, body) = send(port, method, path).await;
    assert_eq!(
        status, 404,
        "{method} {path} was refused at translation, so the gateway must answer its \
         unmatched-route 404: {body}"
    );
}

// ---------------------------------------------------------------------------
// One listener, one slot: only the earlier rule serves
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn uncovered_rule_first_serves_get_over_http_and_refuses_post() {
    let backends = start_backends().await;
    let mut objects = base_objects(&backends, false);
    objects.push(http_route(
        "method-split",
        json!({ "name": "edge" }),
        vec![
            plain_get_rule(&backends, "/api"),
            secure_post_rule(&backends, "/api"),
        ],
    ));
    let config = translate(&objects, true);
    let declared = [LISTENER_A_PORT];
    let gateway = start_gateway(&config, &declared).await;
    let port = gateway.port_for(&declared, LISTENER_A_PORT);

    assert_served_by(port, "GET", "/api/items", PLAIN_BODY).await;
    assert_unmatched(port, "POST", "/api/items").await;

    // GET reached only the plaintext backend; the refused POST reached
    // neither backend.
    assert_only_served(&backends.plain, "GET", "POST");
    assert_never_served(&backends.secure, "GET");
    assert_never_served(&backends.secure, "POST");
    gateway.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn covered_rule_first_serves_post_over_tls_and_refuses_get() {
    let backends = start_backends().await;
    let mut objects = base_objects(&backends, false);
    objects.push(http_route(
        "method-split",
        json!({ "name": "edge" }),
        vec![
            secure_post_rule(&backends, "/api"),
            plain_get_rule(&backends, "/api"),
        ],
    ));
    let config = translate(&objects, true);
    let declared = [LISTENER_A_PORT];
    let gateway = start_gateway(&config, &declared).await;
    let port = gateway.port_for(&declared, LISTENER_A_PORT);

    assert_served_by(port, "POST", "/api/items", SECURE_BODY).await;
    assert_unmatched(port, "GET", "/api/items").await;

    // POST reached only the TLS backend; the refused GET reached neither
    // backend.
    assert_only_served(&backends.secure, "POST", "GET");
    assert_never_served(&backends.plain, "GET");
    assert_never_served(&backends.plain, "POST");
    gateway.shutdown().await;
}

// ---------------------------------------------------------------------------
// Controls: distinct slots serve both rules
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rules_on_separate_paths_both_serve_over_their_own_transport() {
    let backends = start_backends().await;
    let mut objects = base_objects(&backends, false);
    objects.push(http_route(
        "path-split",
        json!({ "name": "edge" }),
        vec![
            plain_get_rule(&backends, "/api"),
            secure_post_rule(&backends, "/secure"),
        ],
    ));
    let config = translate(&objects, false);
    let declared = [LISTENER_A_PORT];
    let gateway = start_gateway(&config, &declared).await;
    let port = gateway.port_for(&declared, LISTENER_A_PORT);

    assert_served_by(port, "GET", "/api/items", PLAIN_BODY).await;
    assert_served_by(port, "POST", "/secure/items", SECURE_BODY).await;
    assert_only_served(&backends.plain, "GET", "POST");
    assert_only_served(&backends.secure, "POST", "GET");
    gateway.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rules_on_separate_listeners_both_serve_over_their_own_transport() {
    let backends = start_backends().await;
    let mut objects = base_objects(&backends, true);
    objects.push(http_route(
        "plain-on-http",
        json!({ "name": "edge", "sectionName": "http" }),
        vec![plain_get_rule(&backends, "/api")],
    ));
    objects.push(http_route(
        "secure-on-alt",
        json!({ "name": "edge", "sectionName": "alt" }),
        vec![secure_post_rule(&backends, "/api")],
    ));
    let config = translate(&objects, false);
    let declared = [LISTENER_A_PORT, LISTENER_B_PORT];
    let gateway = start_gateway(&config, &declared).await;
    let http_port = gateway.port_for(&declared, LISTENER_A_PORT);
    let alt_port = gateway.port_for(&declared, LISTENER_B_PORT);

    assert_served_by(http_port, "GET", "/api/items", PLAIN_BODY).await;
    assert_served_by(alt_port, "POST", "/api/items", SECURE_BODY).await;
    // Each listener serves only its own Route's method.
    assert_unmatched(http_port, "POST", "/api/items").await;
    assert_unmatched(alt_port, "GET", "/api/items").await;
    assert_only_served(&backends.plain, "GET", "POST");
    assert_only_served(&backends.secure, "POST", "GET");
    gateway.shutdown().await;
}
