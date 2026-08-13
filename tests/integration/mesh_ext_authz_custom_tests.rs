//! Live external-authorization execution for Istio `action: CUSTOM`
//! (issue #3235).
//!
//! These exercise the real provider round trip through the shared plugin HTTP
//! client against a local stub authorizer: allow, deny, timeout, oversize
//! response, malformed transport, provider withdrawal, and namespace isolation
//! of the provider set. The translation / ordering half lives in
//! `tests/unit/config/istio_authz_custom_action_tests.rs`.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshExtAuthzProvider, MeshPolicy, MeshRule, PolicyAction, PolicyScope,
};
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use ferrum_edge::plugins::PluginHttpClient;
use ferrum_edge::plugins::mesh::ext_authz::{
    MeshExtAuthzCheckRequest, MeshExtAuthzExecutor, MeshExtAuthzOutcome, MeshExtAuthzReason,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// How the stub authorizer answers one check.
#[derive(Clone, Copy)]
enum StubBehavior {
    /// Reply `200 OK` with an empty body.
    Allow,
    /// Reply with the given status and a `www-authenticate` header.
    Deny(u16),
    /// Accept the connection and never answer, forcing the client timeout.
    Hang,
    /// Reply `200 OK` with a body far larger than the read bound.
    OversizeBody,
    /// Reply with an explicit denial whose discarded body exceeds the read
    /// bound. The denial must remain authoritative even under `failOpen`.
    OversizeDenialBody,
    /// Reply with an explicit denial and a truncated body. The denial must not
    /// be reclassified as a failed check when the discarded body cannot drain.
    TruncatedDenialBody,
    /// Close the connection without writing a response.
    Reset,
}

struct Stub {
    port: u16,
    calls: Arc<AtomicUsize>,
    last_request: Arc<std::sync::Mutex<String>>,
}

async fn start_stub(behavior: StubBehavior) -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("stub authorizer binds");
    let port = listener.local_addr().expect("stub local addr").port();
    let calls = Arc::new(AtomicUsize::new(0));
    let last_request = Arc::new(std::sync::Mutex::new(String::new()));
    let task_calls = Arc::clone(&calls);
    let task_request = Arc::clone(&last_request);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            task_calls.fetch_add(1, Ordering::SeqCst);
            let request = Arc::clone(&task_request);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 8192];
                let read = stream.read(&mut buffer).await.unwrap_or(0);
                if let Ok(mut slot) = request.lock() {
                    *slot = String::from_utf8_lossy(&buffer[..read]).to_string();
                }
                match behavior {
                    StubBehavior::Allow => {
                        let _ = stream
                            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                            .await;
                    }
                    StubBehavior::Deny(status) => {
                        let response = format!(
                            "HTTP/1.1 {status} Forbidden\r\nwww-authenticate: Bearer realm=\"mesh\"\r\ncontent-length: 7\r\n\r\ndenied!"
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                    }
                    StubBehavior::Hang => {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                    StubBehavior::OversizeBody => {
                        let body = vec![b'x'; 256 * 1024];
                        let _ = stream
                            .write_all(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n")
                            .await;
                        let _ = stream
                            .write_all(format!("{:x}\r\n", body.len()).as_bytes())
                            .await;
                        let _ = stream.write_all(&body).await;
                        let _ = stream.write_all(b"\r\n0\r\n\r\n").await;
                    }
                    StubBehavior::OversizeDenialBody => {
                        let body = vec![b'x'; 256 * 1024];
                        let header = format!(
                            "HTTP/1.1 403 Forbidden\r\ncontent-length: {}\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(header.as_bytes()).await;
                        let _ = stream.write_all(&body).await;
                    }
                    StubBehavior::TruncatedDenialBody => {
                        let _ = stream
                            .write_all(
                                b"HTTP/1.1 403 Forbidden\r\ncontent-length: 64\r\n\r\ndenied!",
                            )
                            .await;
                        let _ = stream.shutdown().await;
                    }
                    StubBehavior::Reset => {
                        let _ = stream.shutdown().await;
                    }
                }
            });
        }
    });
    Stub {
        port,
        calls,
        last_request,
    }
}

fn provider(port: u16) -> MeshExtAuthzProvider {
    MeshExtAuthzProvider {
        name: "sample-ext-authz".to_string(),
        service: "127.0.0.1".to_string(),
        port,
        tls: false,
        path_prefix: Some("/check".to_string()),
        timeout_ms: 500,
        fail_open: false,
        status_on_error: 403,
        include_request_headers_in_check: vec!["x-request-id".to_string()],
        include_additional_headers_in_check: Vec::new(),
        include_request_body_in_check: None,
        headers_to_upstream_on_allow: Vec::new(),
        headers_to_downstream_on_deny: vec!["www-authenticate".to_string()],
        headers_to_downstream_on_allow: Vec::new(),
    }
}

fn executor(providers: Vec<MeshExtAuthzProvider>) -> MeshExtAuthzExecutor {
    MeshExtAuthzExecutor::new(&providers, PluginHttpClient::default())
        .expect("executor prepares from validated providers")
}

async fn check(
    executor: &MeshExtAuthzExecutor,
    provider_name: &str,
    headers: &HashMap<String, String>,
) -> MeshExtAuthzOutcome {
    let accumulator = AtomicU64::new(0);
    executor
        .check(
            provider_name,
            MeshExtAuthzCheckRequest {
                method: "GET",
                path: "/admin/reports",
                headers,
                authority: Some("api.example.com"),
                body: None,
                body_proven_empty: true,
            },
            &accumulator,
        )
        .await
}

fn request_headers() -> HashMap<String, String> {
    HashMap::from([
        ("x-request-id".to_string(), "abc-123".to_string()),
        (
            "authorization".to_string(),
            "Bearer super-secret-token".to_string(),
        ),
    ])
}

#[tokio::test]
async fn a_two_hundred_from_the_provider_allows() {
    let stub = start_stub(StubBehavior::Allow).await;
    let executor = executor(vec![provider(stub.port)]);
    let outcome = check(&executor, "sample-ext-authz", &request_headers()).await;
    assert!(
        matches!(outcome, MeshExtAuthzOutcome::Allow { .. }),
        "unexpected outcome: {outcome:?}"
    );
    assert_eq!(stub.calls.load(Ordering::SeqCst), 1, "exactly one check");
}

#[tokio::test]
async fn only_the_declared_headers_and_no_query_reach_the_provider() {
    let stub = start_stub(StubBehavior::Allow).await;
    let executor = executor(vec![provider(stub.port)]);
    let _ = check(&executor, "sample-ext-authz", &request_headers()).await;

    let seen = stub.last_request.lock().expect("stub request").clone();
    assert!(
        seen.to_ascii_lowercase().contains("x-request-id: abc-123"),
        "a declared header must be forwarded, got: {seen}"
    );
    assert!(
        !seen.to_ascii_lowercase().contains("super-secret-token"),
        "a credential the operator did NOT name must never reach the provider"
    );
    assert!(
        seen.starts_with("GET /check/admin/reports "),
        "the check must carry the original method and the prefixed path, got: {seen}"
    );
}

#[tokio::test]
async fn a_provider_denial_forwards_its_status_and_allow_listed_header_only() {
    let stub = start_stub(StubBehavior::Deny(401)).await;
    let executor = executor(vec![provider(stub.port)]);
    let outcome = check(&executor, "sample-ext-authz", &request_headers()).await;
    match outcome {
        MeshExtAuthzOutcome::Deny {
            status,
            headers,
            reason,
        } => {
            assert_eq!(status, 401, "the provider's own status is preserved");
            assert_eq!(reason, MeshExtAuthzReason::DeniedByProvider);
            assert_eq!(
                headers,
                vec![(
                    "www-authenticate".to_string(),
                    "Bearer realm=\"mesh\"".to_string()
                )],
                "only headersToDownstreamOnDeny entries are copied out"
            );
        }
        other => panic!("expected a denial, got {other:?}"),
    }
}

#[tokio::test]
async fn a_provider_timeout_fails_closed_with_status_on_error() {
    let stub = start_stub(StubBehavior::Hang).await;
    let mut provider = provider(stub.port);
    provider.timeout_ms = 100;
    provider.status_on_error = 503;
    let executor = executor(vec![provider]);
    let outcome = check(&executor, "sample-ext-authz", &request_headers()).await;
    match outcome {
        MeshExtAuthzOutcome::Deny { status, .. } => assert_eq!(status, 503),
        other => panic!("a timeout must never allow, got {other:?}"),
    }
}

#[tokio::test]
async fn a_provider_timeout_with_fail_open_continues() {
    let stub = start_stub(StubBehavior::Hang).await;
    let mut provider = provider(stub.port);
    provider.timeout_ms = 100;
    provider.fail_open = true;
    let executor = executor(vec![provider]);
    let outcome = check(&executor, "sample-ext-authz", &request_headers()).await;
    assert!(
        matches!(outcome, MeshExtAuthzOutcome::Allow { .. }),
        "failOpen is the operator's explicit opt-in and must be honoured: {outcome:?}"
    );
}

#[tokio::test]
async fn a_transport_failure_fails_closed() {
    let stub = start_stub(StubBehavior::Reset).await;
    let executor = executor(vec![provider(stub.port)]);
    let outcome = check(&executor, "sample-ext-authz", &request_headers()).await;
    match outcome {
        MeshExtAuthzOutcome::Deny { status, reason, .. } => {
            assert_eq!(status, 403);
            assert!(
                matches!(
                    reason,
                    MeshExtAuthzReason::TransportError | MeshExtAuthzReason::Timeout
                ),
                "unexpected reason: {reason:?}"
            );
        }
        other => panic!("a transport failure must never allow, got {other:?}"),
    }
}

#[tokio::test]
async fn an_oversize_provider_response_fails_closed() {
    let stub = start_stub(StubBehavior::OversizeBody).await;
    let executor = executor(vec![provider(stub.port)]);
    let outcome = check(&executor, "sample-ext-authz", &request_headers()).await;
    match outcome {
        MeshExtAuthzOutcome::Deny { status, reason, .. } => {
            assert_eq!(status, 403);
            assert!(
                matches!(
                    reason,
                    MeshExtAuthzReason::ResponseTooLarge | MeshExtAuthzReason::ResponseReadFailed
                ),
                "a 200 with an unbounded body must not be read as an allow: {reason:?}"
            );
        }
        other => panic!("expected a fail-closed denial, got {other:?}"),
    }
}

#[tokio::test]
async fn an_oversize_explicit_denial_cannot_be_turned_into_a_fail_open_allow() {
    let stub = start_stub(StubBehavior::OversizeDenialBody).await;
    let mut source = provider(stub.port);
    source.fail_open = true;
    let executor = executor(vec![source]);
    match check(&executor, "sample-ext-authz", &request_headers()).await {
        MeshExtAuthzOutcome::Deny { status, reason, .. } => {
            assert_eq!(status, 403);
            assert_eq!(reason, MeshExtAuthzReason::DeniedByProvider);
        }
        other => panic!(
            "a discarded oversize body must not weaken an explicit provider denial: {other:?}"
        ),
    }
}

#[tokio::test]
async fn a_truncated_explicit_denial_cannot_be_turned_into_a_fail_open_allow() {
    let stub = start_stub(StubBehavior::TruncatedDenialBody).await;
    let mut source = provider(stub.port);
    source.fail_open = true;
    let executor = executor(vec![source]);
    match check(&executor, "sample-ext-authz", &request_headers()).await {
        MeshExtAuthzOutcome::Deny { status, reason, .. } => {
            assert_eq!(status, 403);
            assert_eq!(reason, MeshExtAuthzReason::DeniedByProvider);
        }
        other => panic!(
            "a discarded truncated body must not weaken an explicit provider denial: {other:?}"
        ),
    }
}

#[tokio::test]
async fn a_provider_name_this_generation_does_not_carry_denies() {
    let stub = start_stub(StubBehavior::Allow).await;
    let executor = executor(vec![provider(stub.port)]);
    let outcome = check(&executor, "retired-ext-authz", &request_headers()).await;
    match outcome {
        MeshExtAuthzOutcome::Deny { status, reason, .. } => {
            assert_eq!(status, 403);
            assert_eq!(reason, MeshExtAuthzReason::ProviderUnbound);
        }
        other => panic!("an unbound delegation must deny, got {other:?}"),
    }
    assert_eq!(
        stub.calls.load(Ordering::SeqCst),
        0,
        "an unbound provider name must not reach any endpoint"
    );
}

// ── Slice projection: withdrawal and namespace isolation ──────────────────

fn custom_policy(namespace: &str, provider_name: &str) -> MeshPolicy {
    MeshPolicy {
        name: "delegate".to_string(),
        namespace: namespace.to_string(),
        scope: PolicyScope::Namespace {
            namespace: namespace.to_string(),
        },
        rules: vec![MeshRule {
            action: PolicyAction::Custom {
                provider: provider_name.to_string(),
            },
            ..MeshRule::default()
        }],
    }
}

fn slice_for(mesh: MeshConfig, namespace: &str) -> MeshSlice {
    let config = ferrum_edge::config::types::GatewayConfig {
        mesh: Some(Box::new(mesh)),
        ..ferrum_edge::config::types::GatewayConfig::default()
    };
    MeshSlice::from_gateway_config(
        &config,
        MeshSliceRequest::from_native(
            format!("node-{namespace}"),
            namespace.to_string(),
            String::new(),
            std::collections::HashMap::new(),
        ),
    )
}

#[test]
fn a_slice_carries_only_the_providers_its_retained_policies_bind() {
    let mut unused = provider(9999);
    unused.name = "unused-ext-authz".to_string();
    let mesh = MeshConfig {
        mesh_policies: vec![custom_policy("default", "sample-ext-authz")],
        ext_authz_providers: vec![provider(9000), unused],
        ..MeshConfig::default()
    };
    let slice = slice_for(mesh, "default");
    assert_eq!(
        slice
            .ext_authz_providers
            .iter()
            .map(|provider| provider.name.as_str())
            .collect::<Vec<_>>(),
        vec!["sample-ext-authz"],
        "an unreferenced provider endpoint must not ride every workload's slice"
    );
}

#[test]
fn withdrawing_the_custom_policy_withdraws_its_provider() {
    let mesh = MeshConfig {
        ext_authz_providers: vec![provider(9000)],
        ..MeshConfig::default()
    };
    let slice = slice_for(mesh, "default");
    assert!(
        slice.ext_authz_providers.is_empty(),
        "no CUSTOM policy remains, so no provider is published and nothing keeps a client alive"
    );
}

#[test]
fn a_provider_set_change_alone_is_not_deduped_away() {
    let base = MeshConfig {
        mesh_policies: vec![custom_policy("default", "sample-ext-authz")],
        ext_authz_providers: vec![provider(9000)],
        ..MeshConfig::default()
    };
    let mut edited_provider = provider(9000);
    edited_provider.timeout_ms = 250;
    let edited = MeshConfig {
        mesh_policies: vec![custom_policy("default", "sample-ext-authz")],
        ext_authz_providers: vec![edited_provider],
        ..MeshConfig::default()
    };

    let before = slice_for(base, "default");
    let after = slice_for(edited, "default");
    assert!(
        !before.content_eq(&after),
        "editing only meshConfig.extensionProviders must still republish the slice, or the DP \
         keeps enforcing against a retired provider contract"
    );
}

// ── Outcome classification: exactly 200 allows; 5xx is an ERROR, not a deny ─

/// Reply with an arbitrary status and a fixed short body.
async fn start_status_stub(status: u16) -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("stub authorizer binds");
    let port = listener.local_addr().expect("stub local addr").port();
    let calls = Arc::new(AtomicUsize::new(0));
    let last_request = Arc::new(std::sync::Mutex::new(String::new()));
    let task_calls = Arc::clone(&calls);
    let task_request = Arc::clone(&last_request);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            task_calls.fetch_add(1, Ordering::SeqCst);
            let request = Arc::clone(&task_request);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 16384];
                let read = stream.read(&mut buffer).await.unwrap_or(0);
                if let Ok(mut slot) = request.lock() {
                    *slot = String::from_utf8_lossy(&buffer[..read]).to_string();
                }
                let response = format!(
                    "HTTP/1.1 {status} X\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Stub {
        port,
        calls,
        last_request,
    }
}

#[tokio::test]
async fn exactly_two_hundred_allows() {
    let stub = start_status_stub(200).await;
    let executor = executor(vec![provider(stub.port)]);
    assert!(
        matches!(
            check(&executor, "sample-ext-authz", &request_headers()).await,
            MeshExtAuthzOutcome::Allow { .. }
        ),
        "HTTP 200 is the protocol's only allow signal"
    );
}

#[tokio::test]
async fn a_two_hundred_and_four_is_a_denial_not_an_allow() {
    let stub = start_status_stub(204).await;
    let executor = executor(vec![provider(stub.port)]);
    match check(&executor, "sample-ext-authz", &request_headers()).await {
        MeshExtAuthzOutcome::Deny { status, reason, .. } => {
            // The denial is a gateway-AUTHORED response carrying a JSON error
            // body, so a no-content status cannot be forwarded verbatim: it
            // would frame content the client is required not to read, leaving
            // those bytes to be misparsed as the next response on an HTTP/1.1
            // keep-alive connection. The DECISION is unchanged.
            assert_eq!(
                status, 403,
                "a denial status that cannot carry the gateway-authored body becomes a plain 403"
            );
            assert_eq!(reason, MeshExtAuthzReason::DeniedByProvider);
        }
        other => panic!("a non-200 success must never be read as an allow, got {other:?}"),
    }
}

#[tokio::test]
async fn a_redirect_denial_keeps_the_providers_own_status() {
    // A redirect-to-login denial is an ordinary ext-authz pattern (it pairs
    // with `headersToDownstreamOnDeny: [location]`), so a representable status
    // must still reach the client unchanged.
    let stub = start_status_stub(302).await;
    let executor = executor(vec![provider(stub.port)]);
    match check(&executor, "sample-ext-authz", &request_headers()).await {
        MeshExtAuthzOutcome::Deny { status, reason, .. } => {
            assert_eq!(status, 302);
            assert_eq!(reason, MeshExtAuthzReason::DeniedByProvider);
        }
        other => panic!("a 302 is an explicit provider denial, got {other:?}"),
    }
}

#[tokio::test]
async fn a_four_hundred_and_three_is_an_explicit_denial_not_a_failed_check() {
    let stub = start_status_stub(403).await;
    let mut source = provider(stub.port);
    // failOpen governs FAILED checks only. An explicit denial must still deny.
    source.fail_open = true;
    let executor = executor(vec![source]);
    match check(&executor, "sample-ext-authz", &request_headers()).await {
        MeshExtAuthzOutcome::Deny { status, reason, .. } => {
            assert_eq!(status, 403);
            assert_eq!(reason, MeshExtAuthzReason::DeniedByProvider);
        }
        other => {
            panic!("failOpen must not convert an explicit 4xx denial into an allow: {other:?}")
        }
    }
}

#[tokio::test]
async fn a_five_hundred_is_a_failed_check_and_uses_status_on_error_when_fail_closed() {
    let stub = start_status_stub(500).await;
    let mut source = provider(stub.port);
    source.status_on_error = 503;
    let executor = executor(vec![source]);
    match check(&executor, "sample-ext-authz", &request_headers()).await {
        MeshExtAuthzOutcome::Deny { status, reason, .. } => {
            assert_eq!(
                status, 503,
                "a failed check resolves to statusOnError, never the provider's own 5xx"
            );
            assert_eq!(reason, MeshExtAuthzReason::ProviderError);
        }
        other => panic!("expected a fail-closed denial, got {other:?}"),
    }
}

#[tokio::test]
async fn a_five_hundred_with_fail_open_allows() {
    let stub = start_status_stub(502).await;
    let mut source = provider(stub.port);
    source.fail_open = true;
    let executor = executor(vec![source]);
    match check(&executor, "sample-ext-authz", &request_headers()).await {
        MeshExtAuthzOutcome::Allow { reason } => {
            assert_eq!(
                reason,
                MeshExtAuthzReason::ProviderError,
                "the allow is recorded as a FAILED check, not a clean allow"
            );
        }
        other => panic!("a 5xx is a failed check and must honour failOpen, got {other:?}"),
    }
}

// ── Wire contract ─────────────────────────────────────────────────────────

#[tokio::test]
async fn a_fixed_check_header_overrides_a_same_named_client_header() {
    use ferrum_edge::modes::mesh::config::MeshExtAuthzHeader;

    let stub = start_status_stub(200).await;
    let mut source = provider(stub.port);
    // The operator both forwards `x-request-id` from the client AND fixes it.
    // The fixed value is authoritative; the client's must not ride along.
    source.include_request_headers_in_check = vec!["x-request-id".to_string()];
    source.include_additional_headers_in_check = vec![MeshExtAuthzHeader {
        name: "x-request-id".to_string(),
        value: "fixed-by-operator".to_string(),
    }];
    let executor = executor(vec![source]);
    let headers = HashMap::from([("x-request-id".to_string(), "attacker-chosen".to_string())]);
    let _ = check(&executor, "sample-ext-authz", &headers).await;

    let seen = stub.last_request.lock().expect("stub request").clone();
    assert!(
        seen.contains("fixed-by-operator"),
        "the fixed operator value must be sent: {seen}"
    );
    assert!(
        !seen.contains("attacker-chosen"),
        "an attacker-controlled value must not survive beside the fixed one: {seen}"
    );
    assert_eq!(
        seen.to_ascii_lowercase().matches("x-request-id:").count(),
        1,
        "exactly one value is sent for the name: {seen}"
    );
}

#[tokio::test]
async fn the_original_request_authority_reaches_the_provider_as_host() {
    let stub = start_status_stub(200).await;
    let executor = executor(vec![provider(stub.port)]);
    let _ = check(&executor, "sample-ext-authz", &request_headers()).await;

    let seen = stub.last_request.lock().expect("stub request").clone();
    let lowercased = seen.to_ascii_lowercase();
    assert!(
        lowercased.contains("host: api.example.com"),
        "the ext-auth protocol carries the ORIGINAL Host: {seen}"
    );
    assert!(
        !lowercased.contains(&format!("host: 127.0.0.1:{}", stub.port)),
        "the provider's own URL host must not replace the original authority: {seen}"
    );
}

#[tokio::test]
async fn a_check_is_never_retried_even_when_shared_plugin_retries_are_configured() {
    use ferrum_edge::config::PoolConfig;

    // `Reset` accepts the connection and closes it without answering — the
    // shared client's transport-retry predicate would replay this GET.
    let stub = start_stub(StubBehavior::Reset).await;
    let retrying_client = PluginHttpClient::from_pool_config_with_settings(
        &PoolConfig::default(),
        1_000, // slow threshold
        3,     // max_retries
        1,     // retry delay ms
    );
    let executor = MeshExtAuthzExecutor::new(&[provider(stub.port)], retrying_client)
        .expect("executor prepares");
    let accumulator = AtomicU64::new(0);
    let headers = HashMap::new();
    let outcome = executor
        .check(
            "sample-ext-authz",
            MeshExtAuthzCheckRequest {
                method: "GET",
                path: "/admin/reports",
                headers: &headers,
                authority: Some("api.example.com"),
                body: None,
                body_proven_empty: true,
            },
            &accumulator,
        )
        .await;
    assert!(
        matches!(outcome, MeshExtAuthzOutcome::Deny { .. }),
        "a transport failure still fails closed: {outcome:?}"
    );
    assert_eq!(
        stub.calls.load(Ordering::SeqCst),
        1,
        "an authorization decision must be dispatched exactly once, whatever \
         FERRUM_PLUGIN_HTTP_MAX_RETRIES says"
    );
}

// ── Per-provider request-body cap ─────────────────────────────────────────

/// Run a check that carries a request body.
async fn check_with_body(
    executor: &MeshExtAuthzExecutor,
    provider_name: &str,
    body: &[u8],
) -> MeshExtAuthzOutcome {
    let accumulator = AtomicU64::new(0);
    let headers = HashMap::new();
    executor
        .check(
            provider_name,
            MeshExtAuthzCheckRequest {
                method: "POST",
                path: "/admin/reports",
                headers: &headers,
                authority: Some("api.example.com"),
                body: Some(body),
                body_proven_empty: false,
            },
            &accumulator,
        )
        .await
}

fn body_provider(port: u16, name: &str, max_request_bytes: usize) -> MeshExtAuthzProvider {
    use ferrum_edge::modes::mesh::config::MeshExtAuthzBodyCheck;

    let mut source = provider(port);
    source.name = name.to_string();
    source.include_request_body_in_check = Some(MeshExtAuthzBodyCheck {
        max_request_bytes,
        allow_partial_message: false,
    });
    source
}

/// The proxy's pre-`authorize` prebuffer ceiling is the MAXIMUM
/// `maxRequestBytes` across the generation's providers, so a body within that
/// shared ceiling but over the SELECTED provider's own cap reaches the check.
/// It must be refused unconditionally, with no provider I/O and no `failOpen`
/// escape — otherwise an unrelated high-cap provider silently raises the cap a
/// low-cap provider enforces.
#[tokio::test]
async fn a_high_cap_provider_cannot_raise_the_selected_providers_body_cap() {
    let stub = start_status_stub(200).await;
    // The low-cap provider is even configured failOpen: an over-cap body is
    // not a FAILED CHECK, so failOpen must not apply to it.
    let mut low = body_provider(stub.port, "low-cap", 8);
    low.fail_open = true;
    let high = body_provider(stub.port, "high-cap", 1024);
    let executor = executor(vec![low, high]);
    assert_eq!(
        executor.max_request_body_bytes(),
        Some(1024),
        "one prebuffer serves whichever provider the matched rule selects, so the shared \
         ceiling is the maximum — NOT the selected provider's own cap"
    );

    let body = [b'x'; 64];
    match check_with_body(&executor, "low-cap", &body).await {
        MeshExtAuthzOutcome::Deny { status, reason, .. } => {
            assert_eq!(
                status, 413,
                "an over-cap body is a client-facing 413, not the provider's statusOnError"
            );
            assert_eq!(reason, MeshExtAuthzReason::BodyTooLarge);
        }
        other => panic!(
            "failOpen must never admit a body over the selected provider's maxRequestBytes, \
             got {other:?}"
        ),
    }
    assert_eq!(
        stub.calls.load(Ordering::SeqCst),
        0,
        "the refusal is decided before any provider I/O"
    );

    // The SAME body is within the other provider's declared cap, so selecting
    // that provider still dispatches a real check: the refusal is per-provider,
    // not a generation-wide ceiling.
    assert!(
        matches!(
            check_with_body(&executor, "high-cap", &body).await,
            MeshExtAuthzOutcome::Allow { .. }
        ),
        "a body within the selected provider's cap must still be checked"
    );
    assert_eq!(stub.calls.load(Ordering::SeqCst), 1);
}

/// A body that is MISSING (rather than too large) stays an ordinary failed
/// check: the provider could not decide, so `failOpen` still governs it.
#[tokio::test]
async fn an_unavailable_body_remains_a_failed_check_distinct_from_an_oversize_one() {
    let stub = start_status_stub(200).await;
    let mut source = body_provider(stub.port, "sample-ext-authz", 64);
    source.fail_open = true;
    let executor = executor(vec![source]);
    let accumulator = AtomicU64::new(0);
    let headers = HashMap::new();
    let outcome = executor
        .check(
            "sample-ext-authz",
            MeshExtAuthzCheckRequest {
                method: "POST",
                path: "/admin/reports",
                headers: &headers,
                authority: Some("api.example.com"),
                body: None,
                body_proven_empty: false,
            },
            &accumulator,
        )
        .await;
    match outcome {
        MeshExtAuthzOutcome::Allow { reason } => {
            assert_eq!(
                reason,
                MeshExtAuthzReason::BodyUnavailable,
                "an unavailable body is a FAILED CHECK, which failOpen may admit"
            );
        }
        other => panic!("expected the failOpen allow, got {other:?}"),
    }
    assert_eq!(
        stub.calls.load(Ordering::SeqCst),
        0,
        "a provider that inspects bodies is not contacted without one"
    );
}

/// Fail-closed is the default for both, and the two are still distinguishable.
#[tokio::test]
async fn an_oversize_body_and_a_missing_body_fail_closed_with_distinct_reasons() {
    let stub = start_status_stub(200).await;
    let executor = executor(vec![body_provider(stub.port, "sample-ext-authz", 8)]);

    match check_with_body(&executor, "sample-ext-authz", &[b'x'; 64]).await {
        MeshExtAuthzOutcome::Deny { status, reason, .. } => {
            assert_eq!(status, 413);
            assert_eq!(reason, MeshExtAuthzReason::BodyTooLarge);
        }
        other => panic!("expected the oversize refusal, got {other:?}"),
    }

    let accumulator = AtomicU64::new(0);
    let headers = HashMap::new();
    let outcome = executor
        .check(
            "sample-ext-authz",
            MeshExtAuthzCheckRequest {
                method: "POST",
                path: "/admin/reports",
                headers: &headers,
                authority: None,
                body: None,
                body_proven_empty: false,
            },
            &accumulator,
        )
        .await;
    match outcome {
        MeshExtAuthzOutcome::Deny { status, reason, .. } => {
            assert_eq!(
                status, 403,
                "a failed check resolves to the provider's statusOnError"
            );
            assert_eq!(reason, MeshExtAuthzReason::BodyUnavailable);
        }
        other => panic!("expected the fail-closed denial, got {other:?}"),
    }
    assert_eq!(stub.calls.load(Ordering::SeqCst), 0);
}

// ── Live datapath: through MeshAuthz::authorize ───────────────────────────

mod live_datapath {
    use super::*;
    use ferrum_edge::plugins::mesh::authz::MeshAuthz;
    use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
    use serde_json::json;

    fn slice_json(port: u16, extra_provider: Option<&str>, fail_open: bool) -> serde_json::Value {
        let mut providers = vec![json!({
            "name": "sample-ext-authz",
            "service": "127.0.0.1",
            "port": port,
            "path_prefix": "/check",
            "timeout_ms": 500,
            "fail_open": fail_open,
            "status_on_error": 403,
            "include_request_headers_in_check": ["x-request-id"],
        })];
        let mut rules = vec![json!({
            "to": [{ "paths": ["/admin/*"] }],
            "action": { "custom": { "provider": "sample-ext-authz" } },
        })];
        if let Some(other) = extra_provider {
            providers.push(json!({
                "name": other,
                "service": "127.0.0.1",
                "port": port,
                "timeout_ms": 500,
                "status_on_error": 403,
            }));
            rules.push(json!({
                "to": [{ "paths": ["/admin/*"] }],
                "action": { "custom": { "provider": other } },
            }));
        }
        json!({
            "node_id": "node-a",
            "namespace": "default",
            "version": "test",
            "mesh_policies": [{
                "name": "delegate-admin",
                "namespace": "default",
                "scope": { "kind": "mesh_wide" },
                "rules": rules,
            }],
            "ext_authz_providers": providers,
        })
    }

    fn plugin(slice: serde_json::Value) -> Result<MeshAuthz, String> {
        MeshAuthz::new_with_http_client(
            &json!({ "mesh_slice": slice }),
            Some(PluginHttpClient::default()),
        )
    }

    fn ctx(path: &str) -> RequestContext {
        let mut ctx =
            RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), path.to_string());
        ctx.headers
            .insert("host".to_string(), "api.example.com".to_string());
        ctx.headers
            .insert("x-request-id".to_string(), "abc-123".to_string());
        ctx
    }

    #[tokio::test]
    async fn an_allowing_provider_lets_the_request_through_the_authorize_phase() {
        let stub = start_status_stub(200).await;
        let plugin = plugin(slice_json(stub.port, None, false)).expect("generation builds");
        let mut ctx = ctx("/admin/reports");
        assert!(matches!(
            plugin.authorize(&mut ctx).await,
            PluginResult::Continue
        ));
        assert_eq!(
            ctx.metadata
                .get("mesh_authz.ext_authz_outcome")
                .map(String::as_str),
            Some("allowed")
        );
        assert_eq!(stub.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_denying_provider_rejects_in_the_authorize_phase() {
        let stub = start_status_stub(401).await;
        let plugin = plugin(slice_json(stub.port, None, false)).expect("generation builds");
        let mut ctx = ctx("/admin/reports");
        match plugin.authorize(&mut ctx).await {
            PluginResult::Reject {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 401, "the provider's own status is preserved");
                assert!(
                    !body.contains("denied!"),
                    "the provider's response body is never echoed to the client"
                );
            }
            other => panic!("expected a rejection, got {other:?}"),
        }
        assert_eq!(
            ctx.metadata
                .get("mesh_authz.deny_policy")
                .map(String::as_str),
            Some("custom:delegate-admin")
        );
    }

    #[tokio::test]
    async fn a_request_no_custom_rule_matches_is_not_checked_at_all() {
        let stub = start_status_stub(403).await;
        let plugin = plugin(slice_json(stub.port, None, false)).expect("generation builds");
        let mut ctx = ctx("/public");
        assert!(matches!(
            plugin.authorize(&mut ctx).await,
            PluginResult::Continue
        ));
        assert_eq!(
            stub.calls.load(Ordering::SeqCst),
            0,
            "an unmatched CUSTOM policy must not dispatch a check"
        );
    }

    #[tokio::test]
    async fn a_provider_five_hundred_follows_fail_open() {
        let stub = start_status_stub(503).await;
        let plugin = plugin(slice_json(stub.port, None, true)).expect("generation builds");
        let mut ctx = ctx("/admin/reports");
        assert!(
            matches!(plugin.authorize(&mut ctx).await, PluginResult::Continue),
            "a 5xx is a failed check and failOpen is the operator's opt-in"
        );
        assert_eq!(
            ctx.metadata
                .get("mesh_authz.ext_authz_outcome")
                .map(String::as_str),
            Some("provider_error")
        );
    }

    #[tokio::test]
    async fn a_provider_five_hundred_fails_closed_by_default() {
        let stub = start_status_stub(503).await;
        let plugin = plugin(slice_json(stub.port, None, false)).expect("generation builds");
        let mut ctx = ctx("/admin/reports");
        match plugin.authorize(&mut ctx).await {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
            other => panic!("expected the statusOnError denial, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_generation_with_no_http_client_denies_a_matched_delegation() {
        // The executor-unavailable path: a matched delegation that cannot be
        // executed must never fall through to the ALLOW tier.
        let plugin = MeshAuthz::new(&json!({ "mesh_slice": slice_json(9, None, false) }))
            .expect("generation builds without an HTTP client");
        let mut ctx = ctx("/admin/reports");
        match plugin.authorize(&mut ctx).await {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
            other => panic!("an unexecutable delegation must deny, got {other:?}"),
        }
        assert_eq!(
            ctx.metadata
                .get("mesh_authz.ext_authz_outcome")
                .map(String::as_str),
            Some("provider_unbound"),
            "the refusal participates in the fixed-cardinality outcome set"
        );
    }

    #[test]
    fn a_workload_selected_by_two_distinct_providers_is_refused_at_construction() {
        // Match rather than `expect_err`: MeshAuthz intentionally omits Debug,
        // and Result::expect_err requires Debug on the success type.
        let error = match plugin(slice_json(9000, Some("other-ext-authz"), false)) {
            Ok(_) => panic!("Istio permits at most one extension provider per workload"),
            Err(error) => error,
        };
        assert!(
            error.contains("more than one"),
            "the refusal must state the contract: {error}"
        );
    }

    /// Two providers declared once, reused by both multi-scope fixtures below.
    fn two_providers_json() -> serde_json::Value {
        json!([
            {
                "name": "provider-a",
                "service": "127.0.0.1",
                "port": 9000,
                "timeout_ms": 500,
                "status_on_error": 403,
            },
            {
                "name": "provider-b",
                "service": "127.0.0.1",
                "port": 9001,
                "timeout_ms": 500,
                "status_on_error": 403,
            },
        ])
    }

    /// A NodeWaypoint slice: two pods enrolled on ONE node, each selected by its
    /// own CUSTOM policy naming its own provider.
    fn node_waypoint_slice_json() -> serde_json::Value {
        json!({
            "node_id": "node-a",
            "namespace": "default",
            "version": "test",
            "mesh_policies": [
                {
                    "name": "delegate-api",
                    "namespace": "default",
                    "scope": {
                        "kind": "workload_selector",
                        "selector": {
                            "namespace": "default",
                            "labels": { "app": "api" },
                        },
                    },
                    "rules": [{
                        "to": [{ "paths": ["/admin/*"] }],
                        "action": { "custom": { "provider": "provider-a" } },
                    }],
                },
                {
                    "name": "delegate-batch",
                    "namespace": "default",
                    "scope": {
                        "kind": "workload_selector",
                        "selector": {
                            "namespace": "default",
                            "labels": { "app": "batch" },
                        },
                    },
                    "rules": [{
                        "to": [{ "paths": ["/admin/*"] }],
                        "action": { "custom": { "provider": "provider-b" } },
                    }],
                },
            ],
            "ext_authz_providers": two_providers_json(),
        })
    }

    /// A waypoint slice fronting TWO Services, each with its own
    /// `targetRefs`-attached CUSTOM policy naming its own provider.
    fn waypoint_slice_json() -> serde_json::Value {
        json!({
            "node_id": "node-a",
            "namespace": "default",
            "version": "test",
            "waypoint_name": "shared-waypoint",
            "services": [
                { "name": "reviews", "namespace": "default" },
                { "name": "ratings", "namespace": "default" },
            ],
            "mesh_policies": [
                {
                    "name": "delegate-reviews",
                    "namespace": "default",
                    "scope": {
                        "kind": "target_refs",
                        "attachments": [{
                            "kind": "service",
                            "namespace": "default",
                            "name": "reviews",
                        }],
                    },
                    "rules": [{
                        "to": [{ "paths": ["/admin/*"] }],
                        "action": { "custom": { "provider": "provider-a" } },
                    }],
                },
                {
                    "name": "delegate-ratings",
                    "namespace": "default",
                    "scope": {
                        "kind": "target_refs",
                        "attachments": [{
                            "kind": "service",
                            "namespace": "default",
                            "name": "ratings",
                        }],
                    },
                    "rules": [{
                        "to": [{ "paths": ["/admin/*"] }],
                        "action": { "custom": { "provider": "provider-b" } },
                    }],
                },
            ],
            "ext_authz_providers": two_providers_json(),
        })
    }

    /// A NodeWaypoint serves EVERY enrolled pod on the node from one listener,
    /// so `per_pod_policy_scoping` deliberately SKIPS the workload retain and
    /// `mesh_policies` is the node's superset, not one workload's set. Two pods
    /// each naming their own provider is a legitimate Istio configuration
    /// ("at most one per workload" is satisfied), and refusing the generation
    /// would stall config for every pod on the node — not just the two. The
    /// per-request, pod-filtered evaluation is what refuses a request that can
    /// genuinely see two providers (`custom:provider-conflict`).
    #[test]
    fn a_node_waypoint_generation_may_carry_one_provider_per_enrolled_pod() {
        let config = json!({
            "mesh_slice": node_waypoint_slice_json(),
            "per_pod_policy_scoping": true,
        });
        // Match rather than `expect`: MeshAuthz intentionally omits Debug.
        match MeshAuthz::new_with_http_client(&config, Some(PluginHttpClient::default())) {
            Ok(_) => {}
            Err(error) => panic!(
                "a node waypoint's un-narrowed policy superset is not one workload naming two \
                 providers: {error}"
            ),
        }
    }

    /// The same holds for a waypoint: its retain admits `targetRefs` policies
    /// for every fronted Service, so one provider per destination Service is the
    /// disjoint-destination-scope configuration the per-request
    /// destination-scope evaluation already resolves.
    #[test]
    fn a_waypoint_generation_may_carry_one_provider_per_fronted_service() {
        let config = json!({ "mesh_slice": waypoint_slice_json() });
        match MeshAuthz::new_with_http_client(&config, Some(PluginHttpClient::default())) {
            Ok(_) => {}
            Err(error) => panic!(
                "a waypoint fronting two Services may bind one provider per destination: {error}"
            ),
        }
    }

    // ── Request-body phase seams ──────────────────────────────────────────

    fn body_slice_json(port: u16, paths: &[&str]) -> serde_json::Value {
        json!({
            "node_id": "node-a",
            "namespace": "default",
            "version": "test",
            "mesh_policies": [{
                "name": "delegate-admin",
                "namespace": "default",
                "scope": { "kind": "mesh_wide" },
                "rules": [{
                    "to": [{ "paths": paths }],
                    "action": { "custom": { "provider": "sample-ext-authz" } },
                }],
            }],
            "ext_authz_providers": [{
                "name": "sample-ext-authz",
                "service": "127.0.0.1",
                "port": port,
                "timeout_ms": 500,
                "status_on_error": 403,
                "include_request_body_in_check": { "max_request_bytes": 64 },
            }],
        })
    }

    #[test]
    fn only_a_request_a_body_inspecting_rule_can_reach_is_buffered_and_capped() {
        let plugin = plugin(body_slice_json(9000, &["/admin/*"])).expect("generation builds");
        assert!(
            plugin.requires_request_body_before_authorize(),
            "the check runs in the authorize phase, so the body must be there"
        );
        assert_eq!(
            plugin.request_body_buffer_limit(),
            Some(64),
            "the pre-authorize prebuffer ceiling is the MAXIMUM maxRequestBytes across the \
             generation's providers (one provider here), enforced as a 413; the selected \
             provider's own cap is enforced again at check time and never honours failOpen"
        );
        assert!(
            plugin.should_buffer_request_body(&ctx("/admin/reports")),
            "a request the body-inspecting rule can reach IS buffered"
        );
        assert!(
            !plugin.should_buffer_request_body(&ctx("/public/upload")),
            "an unrelated request must keep its ordinary accepted body size"
        );
    }

    #[test]
    fn a_generation_with_no_body_inspecting_provider_buffers_nothing() {
        let plugin = plugin(slice_json(9000, None, false)).expect("generation builds");
        assert!(!plugin.requires_request_body_before_authorize());
        assert_eq!(plugin.request_body_buffer_limit(), None);
        assert!(!plugin.should_buffer_request_body(&ctx("/admin/reports")));
    }

    #[test]
    fn an_unscoped_body_inspecting_rule_buffers_every_request_it_can_reach() {
        // No `to:` scope at all — the rule can reach anything, so the
        // predicate must have no false negatives.
        let plugin = plugin(json!({
            "node_id": "node-a",
            "namespace": "default",
            "version": "test",
            "mesh_policies": [{
                "name": "delegate-all",
                "namespace": "default",
                "scope": { "kind": "mesh_wide" },
                "rules": [{ "action": { "custom": { "provider": "sample-ext-authz" } } }],
            }],
            "ext_authz_providers": [{
                "name": "sample-ext-authz",
                "service": "127.0.0.1",
                "port": 9000,
                "timeout_ms": 500,
                "status_on_error": 403,
                "include_request_body_in_check": { "max_request_bytes": 64 },
            }],
        }))
        .expect("generation builds");
        assert!(plugin.should_buffer_request_body(&ctx("/anything")));
    }

    fn body_slice_with_ports(port: u16, ports: &[u16], not_ports: &[u16]) -> serde_json::Value {
        json!({
            "node_id": "node-a",
            "namespace": "default",
            "version": "test",
            "mesh_policies": [{
                "name": "delegate-admin-port",
                "namespace": "default",
                "scope": { "kind": "mesh_wide" },
                "rules": [{
                    "to": [{
                        "paths": ["/admin/*"],
                        "ports": ports,
                        "not_ports": not_ports,
                    }],
                    "action": { "custom": { "provider": "sample-ext-authz" } },
                }],
            }],
            "ext_authz_providers": [{
                "name": "sample-ext-authz",
                "service": "127.0.0.1",
                "port": port,
                "timeout_ms": 500,
                "fail_open": true,
                "status_on_error": 403,
                "include_request_body_in_check": { "max_request_bytes": 64 },
            }],
        })
    }

    /// Positive port scoping must NOT suppress pre-authorize buffering.
    ///
    /// Destination port is resolved later (orig-dst / matched proxy). A
    /// prebuffer predicate that required `request.port` would return false
    /// here, leave the body unbuffered, then match at authorize and — with
    /// `failOpen` — admit on `BodyUnavailable`.
    #[test]
    fn a_body_inspecting_custom_rule_with_positive_port_scope_still_buffers() {
        let plugin = plugin(body_slice_with_ports(9000, &[8080], &[])).expect("generation builds");
        assert!(
            plugin.should_buffer_request_body(&ctx("/admin/reports")),
            "positive ports are unavailable at the prebuffer point and must be treated as satisfiable"
        );
        assert!(
            !plugin.should_buffer_request_body(&ctx("/public/upload")),
            "method/path/host narrowing must still exclude unrelated requests"
        );
    }

    #[test]
    fn a_body_inspecting_custom_rule_with_negative_port_scope_still_buffers() {
        let plugin = plugin(body_slice_with_ports(9000, &[], &[9090])).expect("generation builds");
        assert!(
            plugin.should_buffer_request_body(&ctx("/admin/reports")),
            "notPorts is also unavailable pre-authorize and must not false-negative buffering"
        );
    }

    /// End-to-end through `authorize`: once the prebuffer gate says yes and
    /// the body is present, a port-scoped body-inspecting CUSTOM rule with
    /// `failOpen` contacts the provider instead of admitting on
    /// `BodyUnavailable`.
    #[tokio::test]
    async fn a_port_scoped_body_inspecting_rule_cannot_fail_open_on_body_unavailable() {
        let stub = start_status_stub(200).await;
        let plugin =
            plugin(body_slice_with_ports(stub.port, &[8080], &[])).expect("generation builds");
        let mut ctx = ctx("/admin/reports");
        // Authorize resolves destination port from the frontend listen port
        // when mesh direction / orig-dst evidence is absent — the same
        // evidence that is unavailable at the prebuffer point.
        ctx.frontend_listen_port = Some(8080);
        assert!(
            plugin.should_buffer_request_body(&ctx),
            "the proxy must buffer before authorize for this rule"
        );
        ctx.request_body_bytes = Some(b"payload".to_vec().into());

        assert!(
            matches!(plugin.authorize(&mut ctx).await, PluginResult::Continue),
            "with the body buffered, failOpen must not be reached via BodyUnavailable"
        );
        assert_eq!(
            ctx.metadata
                .get("mesh_authz.ext_authz_outcome")
                .map(String::as_str),
            Some("allowed")
        );
        assert_eq!(
            stub.calls.load(Ordering::SeqCst),
            1,
            "the provider must be contacted once the body is available"
        );
    }
}
