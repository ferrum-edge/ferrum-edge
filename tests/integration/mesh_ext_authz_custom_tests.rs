//! Live external-authorization execution for Istio `action: CUSTOM`
//! (issue #3235).
//!
//! These exercise the real provider round trip through the shared plugin HTTP
//! client against a local stub authorizer: allow, deny, timeout, oversize
//! response, malformed transport, provider withdrawal, and namespace isolation
//! of the provider set. The translation / ordering half lives in
//! `tests/unit/config/istio_authz_custom_action_tests.rs`.

use crate::scaffolding::port_registry::TestSocket;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use ferrum_edge::modes::mesh::config::{
    MESH_EXT_AUTHZ_PROCESS_CONCURRENT_CALLS, MeshConfig, MeshExtAuthzProvider, MeshPolicy,
    MeshRule, PolicyAction, PolicyScope,
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
    /// Reply with exactly these bytes (one complete HTTP/1.1 response).
    Raw(&'static str),
}

struct Stub {
    port: u16,
    calls: Arc<AtomicUsize>,
    last_request: Arc<std::sync::Mutex<String>>,
}

async fn start_stub(behavior: StubBehavior) -> Stub {
    let listener = TcpListener::bind_test("127.0.0.1:0")
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
                    StubBehavior::Raw(response) => {
                        let _ = stream.write_all(response.as_bytes()).await;
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
                source_principal: None,
                request_principal: None,
                body: None,
                body_proven_empty: true,
                proxy_hops: None,
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
    let listener = TcpListener::bind_test("127.0.0.1:0")
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
        MeshExtAuthzOutcome::Allow { reason, .. } => {
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
                source_principal: None,
                request_principal: None,
                body: None,
                body_proven_empty: true,
                proxy_hops: None,
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
                source_principal: None,
                request_principal: None,
                body: Some(body),
                body_proven_empty: false,
                proxy_hops: None,
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
                source_principal: None,
                request_principal: None,
                body: None,
                body_proven_empty: false,
                proxy_hops: None,
            },
            &accumulator,
        )
        .await;
    match outcome {
        MeshExtAuthzOutcome::Allow { reason, .. } => {
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
                source_principal: None,
                request_principal: None,
                body: None,
                body_proven_empty: false,
                proxy_hops: None,
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
    async fn a_connect_relay_is_refused_without_asking_the_provider() {
        // The requests inside a relayed CONNECT are opaque bytes, so a
        // delegation cannot judge them. Asking the provider about the CONNECT
        // would authorize the tunnel, not the requests written into it, so a
        // matched delegation refuses it outright.
        let stub = start_status_stub(200).await;
        let plugin = plugin(slice_json(stub.port, None, false)).expect("generation builds");
        let mut ctx = ctx("/");
        ctx.method = "CONNECT".to_string();
        ctx.mark_hbone_connect_relay();
        match plugin.authorize(&mut ctx).await {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
            other => panic!("a relayed CONNECT must be refused, got {other:?}"),
        }
        assert_eq!(
            ctx.metadata
                .get("mesh_authz.ext_authz_outcome")
                .map(String::as_str),
            Some("unexecutable")
        );
        assert_eq!(
            ctx.metadata
                .get("mesh_authz.deny_policy")
                .map(String::as_str),
            Some("custom:delegate-admin")
        );
        assert_eq!(
            stub.calls.load(Ordering::SeqCst),
            0,
            "the provider must not be asked about the tunnel"
        );
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
    fn the_body_buffer_scan_considers_the_parameter_stripped_spelling() {
        // `authorize` judges a CUSTOM rule on both spellings of a `;` path
        // (issue #5948), so the pre-authorize scan must buffer for either.
        let plugin = plugin(body_slice_json(9000, &["/admin/*"])).expect("generation builds");
        assert!(
            plugin.should_buffer_request_body(&ctx("/admin;x/reports")),
            "the stripped /admin/reports is reachable by the body-inspecting rule"
        );
        assert!(
            !plugin.should_buffer_request_body(&ctx("/public;x/upload")),
            "neither spelling of /public;x/upload is reachable"
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

// ── Process-wide check budget (advisory GHSA-4f6g-8xxw-qm99) ───────────────
//
// The in-flight ceiling is a RESOURCE bound: each permit holder occupies a
// socket, a buffered check body, and a task for a provider round trip. It was
// owned per executor, so N enabled `mesh_authz` instances each opened their own
// budget and a reload published a replacement with a full pool while the
// retiring generation's checks were still running on their own. It is one
// process-wide pool now, and these prove the aggregate contract without opening
// the whole budget's worth of live connections.

#[tokio::test]
async fn two_independent_executors_draw_from_one_process_wide_check_budget() {
    let first = executor(vec![provider(9000)]);
    let second = executor(vec![provider(9001)]);

    assert!(
        Arc::ptr_eq(first.check_budget(), second.check_budget()),
        "independently constructed executors must share ONE budget"
    );
    assert_eq!(
        first.check_budget().available_permits(),
        MESH_EXT_AUTHZ_PROCESS_CONCURRENT_CALLS,
        "the shared budget starts at the documented process-wide ceiling"
    );
}

/// A reload builds a replacement executor while the retiring one's checks are
/// still in flight. Both draw on the same pool, so the replacement cannot
/// restart with a full budget, and the retiring generation's permits stay
/// charged until its checks finish.
#[tokio::test]
async fn a_reload_generation_cannot_reopen_a_fresh_budget() {
    let stub = start_stub(StubBehavior::Allow).await;
    let retiring = executor(vec![provider(stub.port)]);

    // Stand in for the retiring generation's in-flight checks by holding its
    // whole budget. Taking the permits directly keeps the test deterministic
    // and avoids opening 128 live provider connections. The budget is
    // process-static and is released before this test returns; CI runs the
    // integration suites under nextest, one process per test.
    let held = Arc::clone(retiring.check_budget())
        .acquire_many_owned(MESH_EXT_AUTHZ_PROCESS_CONCURRENT_CALLS as u32)
        .await
        .expect("the process budget is never closed");
    assert_eq!(retiring.check_budget().available_permits(), 0);

    let replacement = executor(vec![provider(stub.port)]);
    assert_eq!(
        replacement.check_budget().available_permits(),
        0,
        "a replacement generation must NOT reopen a fresh budget"
    );

    let refused = check(&replacement, "sample-ext-authz", &request_headers()).await;
    assert_eq!(
        refused,
        MeshExtAuthzOutcome::Deny {
            status: 403,
            headers: Vec::new(),
            reason: MeshExtAuthzReason::ConcurrencyExhausted,
        },
        "at the ceiling the check is refused immediately, never queued"
    );
    assert_eq!(
        stub.calls.load(Ordering::SeqCst),
        0,
        "a refused check must not reach the provider"
    );

    // Releasing the retiring generation's permits restores capacity exactly
    // once, and the replacement serves normally again.
    drop(held);
    assert_eq!(
        replacement.check_budget().available_permits(),
        MESH_EXT_AUTHZ_PROCESS_CONCURRENT_CALLS,
        "permits are released exactly once when their holders finish"
    );

    let allowed = check(&replacement, "sample-ext-authz", &request_headers()).await;
    assert_eq!(
        allowed,
        MeshExtAuthzOutcome::Allow {
            reason: MeshExtAuthzReason::Allowed,
            upstream_headers: Vec::new(),
            downstream_headers: Vec::new(),
        },
        "capacity restored, so the check runs"
    );
    assert_eq!(stub.calls.load(Ordering::SeqCst), 1);
}

/// Every `X-Ferrum-Hops` field line in the raw check request the stub saw.
fn seen_proxy_hops(seen: &str) -> Vec<String> {
    seen.split("\r\n")
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("x-ferrum-hops"))
        .map(|(_, value)| value.trim().to_string())
        .collect()
}

/// A CUSTOM check carries the request's gateway hop count (`received + 1`) as
/// exactly one `X-Ferrum-Hops` field line, so a provider that resolves back to
/// the gateway is refused at the proxy hop limit like a looping route (issue
/// #6128). A provider cannot name `x-ferrum-*` for forwarding (refused at
/// admission), so a client copy never reaches the check; with the limit
/// disabled the check carries no hop field at all.
#[tokio::test]
async fn a_check_carries_the_proxy_hop_count() {
    for (proxy_hops, expected) in [(Some(5), vec!["5".to_string()]), (None, Vec::new())] {
        let stub = start_stub(StubBehavior::Allow).await;
        let executor = executor(vec![provider(stub.port)]);
        let mut headers = request_headers();
        headers.insert("x-ferrum-hops".to_string(), "1".to_string());
        let accumulator = AtomicU64::new(0);
        let outcome = executor
            .check(
                "sample-ext-authz",
                MeshExtAuthzCheckRequest {
                    method: "GET",
                    path: "/admin/reports",
                    headers: &headers,
                    authority: Some("api.example.com"),
                    source_principal: None,
                    request_principal: None,
                    body: None,
                    body_proven_empty: true,
                    proxy_hops,
                },
                &accumulator,
            )
            .await;
        assert!(
            matches!(outcome, MeshExtAuthzOutcome::Allow { .. }),
            "unexpected outcome: {outcome:?}"
        );

        let seen = stub.last_request.lock().expect("stub request").clone();
        assert_eq!(
            seen_proxy_hops(&seen),
            expected,
            "proxy_hops={proxy_hops:?}"
        );
    }
}

// ── Repeated provider response headers (deny forwarding) ──────────────────

/// A login-redirect denial that sets TWO cookies and advertises TWO auth
/// challenges, each as its own field line.
const MULTI_LINE_DENIAL: &str = "HTTP/1.1 302 Found\r\n\
location: https://login.example.com/start\r\n\
set-cookie: oauth_state=s1; Path=/\r\n\
set-cookie: csrf_nonce=n1; Path=/\r\n\
www-authenticate: Bearer realm=\"mesh\"\r\n\
www-authenticate: Basic realm=\"mesh\"\r\n\
content-length: 0\r\n\r\n";

#[tokio::test]
async fn a_denial_keeps_every_repeated_set_cookie_and_challenge_line() {
    let stub = start_stub(StubBehavior::Raw(MULTI_LINE_DENIAL)).await;
    let mut source = provider(stub.port);
    source.headers_to_downstream_on_deny = vec![
        "location".to_string(),
        "set-cookie".to_string(),
        "www-authenticate".to_string(),
    ];
    let executor = executor(vec![source]);
    let headers = match check(&executor, "sample-ext-authz", &request_headers()).await {
        MeshExtAuthzOutcome::Deny {
            status, headers, ..
        } => {
            assert_eq!(status, 302, "a redirect denial keeps the provider's status");
            headers.into_iter().collect::<HashMap<_, _>>()
        }
        other => panic!("expected a denial, got {other:?}"),
    };
    assert_eq!(
        headers.get("set-cookie").map(String::as_str),
        Some("oauth_state=s1; Path=/\ncsrf_nonce=n1; Path=/"),
        "BOTH cookies must survive, in the proxy's newline-joined multi-cookie form"
    );
    assert_eq!(
        headers.get("www-authenticate").map(String::as_str),
        Some("Bearer realm=\"mesh\", Basic realm=\"mesh\""),
        "every advertised challenge must survive"
    );
    assert_eq!(
        headers.get("location").map(String::as_str),
        Some("https://login.example.com/start")
    );

    // The client-visible response builder every protocol shares splits the
    // cookies back into one `Set-Cookie` field each.
    let response = ferrum_edge::proxy::headers::apply_response_headers(
        http::Response::builder().status(302),
        &headers,
    )
    .body(())
    .expect("response builds");
    let cookies: Vec<&str> = response
        .headers()
        .get_all(http::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    assert_eq!(
        cookies,
        vec!["oauth_state=s1; Path=/", "csrf_nonce=n1; Path=/"]
    );
}

// ── Gateway-asserted caller identity on the check ─────────────────────────

/// Every field line named `name` in the raw check request the stub saw.
fn seen_header_lines(seen: &str, name: &str) -> Vec<String> {
    seen.split("\r\n")
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .filter(|(field, _)| field.trim().eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim().to_string())
        .collect()
}

#[tokio::test]
async fn the_check_carries_the_gateway_asserted_caller_identity() {
    let stub = start_stub(StubBehavior::Allow).await;
    let executor = executor(vec![provider(stub.port)]);
    let principal =
        ferrum_edge::identity::SpiffeId::new("spiffe://cluster.local/ns/shop/sa/frontend")
            .expect("valid spiffe id");
    let mut headers = request_headers();
    // A client copy can never be forwarded: admission refuses `x-ferrum-*`
    // in `includeRequestHeadersInCheck`, and the stamp replaces the name.
    headers.insert(
        "x-ferrum-source-principal".to_string(),
        "spiffe://cluster.local/ns/evil/sa/forged".to_string(),
    );
    let accumulator = AtomicU64::new(0);
    let outcome = executor
        .check(
            "sample-ext-authz",
            MeshExtAuthzCheckRequest {
                method: "GET",
                path: "/admin/reports",
                headers: &headers,
                authority: Some("api.example.com"),
                source_principal: Some(&principal),
                request_principal: Some("https://issuer.example.com/alice"),
                body: None,
                body_proven_empty: true,
                proxy_hops: None,
            },
            &accumulator,
        )
        .await;
    assert!(
        matches!(outcome, MeshExtAuthzOutcome::Allow { .. }),
        "unexpected outcome: {outcome:?}"
    );
    let seen = stub.last_request.lock().expect("stub request").clone();
    assert_eq!(
        seen_header_lines(&seen, "x-ferrum-source-principal"),
        vec!["spiffe://cluster.local/ns/shop/sa/frontend".to_string()],
        "exactly one, gateway-authored source principal"
    );
    assert_eq!(
        seen_header_lines(&seen, "x-ferrum-source-namespace"),
        vec!["shop".to_string()]
    );
    assert_eq!(
        seen_header_lines(&seen, "x-ferrum-source-service-account"),
        vec!["frontend".to_string()]
    );
    assert_eq!(
        seen_header_lines(&seen, "x-ferrum-request-principal"),
        vec!["https://issuer.example.com/alice".to_string()]
    );
}

#[tokio::test]
async fn an_unknown_caller_identity_is_absent_from_the_check() {
    let stub = start_stub(StubBehavior::Allow).await;
    let executor = executor(vec![provider(stub.port)]);
    let _ = check(&executor, "sample-ext-authz", &request_headers()).await;
    let seen = stub.last_request.lock().expect("stub request").clone();
    for name in [
        "x-ferrum-source-principal",
        "x-ferrum-source-namespace",
        "x-ferrum-source-service-account",
        "x-ferrum-request-principal",
    ] {
        assert!(
            seen_header_lines(&seen, name).is_empty(),
            "{name} must be absent, never empty, when the gateway holds no identity"
        );
    }
}

// ── headersToUpstreamOnAllow / headersToDownstreamOnAllow ─────────────────

/// An allowing provider that exchanges the token, names the user, refreshes
/// the session cookie, and returns a header nobody listed.
const ALLOW_WITH_MUTATIONS: &str = "HTTP/1.1 200 OK\r\n\
x-auth-request-user: alice\r\n\
authorization: Bearer exchanged-token\r\n\
set-cookie: session=refreshed; Path=/\r\n\
x-unlisted: provider-internal\r\n\
content-length: 0\r\n\r\n";

#[tokio::test]
async fn an_allowed_check_returns_only_the_listed_provider_headers() {
    let stub = start_stub(StubBehavior::Raw(ALLOW_WITH_MUTATIONS)).await;
    let mut source = provider(stub.port);
    source.headers_to_upstream_on_allow = vec![
        "x-auth-request-user".to_string(),
        "authorization".to_string(),
    ];
    source.headers_to_downstream_on_allow = vec!["set-cookie".to_string()];
    let executor = executor(vec![source]);
    match check(&executor, "sample-ext-authz", &request_headers()).await {
        MeshExtAuthzOutcome::Allow {
            reason,
            upstream_headers,
            downstream_headers,
        } => {
            assert_eq!(reason, MeshExtAuthzReason::Allowed);
            assert_eq!(
                upstream_headers,
                vec![
                    ("x-auth-request-user".to_string(), "alice".to_string()),
                    (
                        "authorization".to_string(),
                        "Bearer exchanged-token".to_string()
                    ),
                ]
            );
            assert_eq!(
                downstream_headers,
                vec![(
                    "set-cookie".to_string(),
                    "session=refreshed; Path=/".to_string()
                )]
            );
        }
        other => panic!("expected an allow, got {other:?}"),
    }
}

mod allowed_request_mutations {
    use super::*;
    use ferrum_edge::plugins::mesh::authz::MeshAuthz;
    use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
    use serde_json::json;

    fn plugin(port: u16, fail_open: bool) -> MeshAuthz {
        let slice = json!({
            "node_id": "node-a",
            "namespace": "default",
            "version": "test",
            "mesh_policies": [{
                "name": "delegate-admin",
                "namespace": "default",
                "scope": { "kind": "mesh_wide" },
                "rules": [{
                    "to": [{ "paths": ["/admin/*"] }],
                    "action": { "custom": { "provider": "mutating-ext-authz" } },
                }],
            }],
            "ext_authz_providers": [{
                "name": "mutating-ext-authz",
                "service": "127.0.0.1",
                "port": port,
                "timeout_ms": 500,
                "fail_open": fail_open,
                "status_on_error": 403,
                "headers_to_upstream_on_allow": ["x-auth-request-user", "authorization"],
                "headers_to_downstream_on_allow": ["set-cookie"],
            }],
        });
        match MeshAuthz::new_with_http_client(
            &json!({ "mesh_slice": slice }),
            Some(PluginHttpClient::default()),
        ) {
            Ok(plugin) => plugin,
            Err(error) => panic!("generation builds: {error}"),
        }
    }

    fn ctx() -> RequestContext {
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/admin/reports".to_string(),
        );
        ctx.headers
            .insert("host".to_string(), "api.example.com".to_string());
        ctx
    }

    /// The backend-bound header map a client forging the provider-owned
    /// identity would produce, in both spellings a CGI-style backend folds.
    fn forged_upstream_headers() -> HashMap<String, String> {
        HashMap::from([
            ("x-auth-request-user".to_string(), "mallory".to_string()),
            ("X_Auth_Request_User".to_string(), "mallory".to_string()),
            (
                "authorization".to_string(),
                "Bearer client-token".to_string(),
            ),
            ("x-request-id".to_string(), "abc-123".to_string()),
        ])
    }

    #[tokio::test]
    async fn provider_headers_replace_client_copies_upstream_and_refresh_the_cookie_downstream() {
        let stub = start_stub(StubBehavior::Raw(ALLOW_WITH_MUTATIONS)).await;
        let plugin = plugin(stub.port, false);
        assert!(plugin.modifies_request_headers());
        let declared = plugin
            .modified_request_header_names()
            .expect("a bounded spelling set is declared, not `any header`");
        // `before_proxy` removes every `_` / `-` spelling of an owned name, so
        // the declaration must name every one of them: 1 for `authorization`,
        // 2^3 for `x-auth-request-user`.
        assert_eq!(declared.len(), 9, "unexpected declaration: {declared:?}");
        for spelling in [
            "authorization",
            "x-auth-request-user",
            "x_auth_request_user",
            "x-auth_request-user",
            "x_auth-request_user",
        ] {
            assert!(
                declared.iter().any(|name| name == spelling),
                "{spelling} must be declared mutable: {declared:?}"
            );
        }

        let mut ctx = ctx();
        assert!(matches!(
            plugin.authorize(&mut ctx).await,
            PluginResult::Continue
        ));

        let mut upstream = forged_upstream_headers();
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut upstream).await,
            PluginResult::Continue
        ));
        assert_eq!(
            upstream.get("x-auth-request-user").map(String::as_str),
            Some("alice"),
            "the provider's value replaces the client's"
        );
        assert!(
            !upstream.contains_key("X_Auth_Request_User"),
            "a folded-spelling client copy must not ride beside the provider's value"
        );
        assert_eq!(
            upstream.get("authorization").map(String::as_str),
            Some("Bearer exchanged-token"),
            "the exchanged token replaces the client's"
        );
        assert_eq!(
            upstream.get("x-request-id").map(String::as_str),
            Some("abc-123"),
            "headers the provider does not own are untouched"
        );
        assert!(!upstream.contains_key("x-unlisted"));

        let mut response = HashMap::from([("set-cookie".to_string(), "backend=1".to_string())]);
        assert!(matches!(
            plugin.after_proxy(&mut ctx, 200, &mut response).await,
            PluginResult::Continue
        ));
        assert_eq!(
            response.get("set-cookie").map(String::as_str),
            Some("backend=1\nsession=refreshed; Path=/"),
            "the refreshed session cookie is appended beside the backend's own cookie"
        );
    }

    #[tokio::test]
    async fn a_fail_open_allow_strips_provider_owned_names_and_installs_nothing() {
        // The provider could not decide (5xx) and `failOpen` admitted the
        // request: nothing vouched for the identity, so the client's copies of
        // the provider-owned names must not reach the backend either.
        let stub = start_status_stub(503).await;
        let plugin = plugin(stub.port, true);
        let mut ctx = ctx();
        assert!(matches!(
            plugin.authorize(&mut ctx).await,
            PluginResult::Continue
        ));
        let mut upstream = forged_upstream_headers();
        let _ = plugin.before_proxy(&mut ctx, &mut upstream).await;
        assert!(!upstream.contains_key("x-auth-request-user"));
        assert!(!upstream.contains_key("X_Auth_Request_User"));
        assert!(!upstream.contains_key("authorization"));
        assert_eq!(
            upstream.get("x-request-id").map(String::as_str),
            Some("abc-123")
        );
    }

    #[tokio::test]
    async fn a_request_no_custom_rule_matches_keeps_its_headers() {
        // No delegation ran, so there is no provider-owned contract for this
        // request: the backend sees exactly what the client sent.
        let stub = start_stub(StubBehavior::Raw(ALLOW_WITH_MUTATIONS)).await;
        let plugin = plugin(stub.port, false);
        let mut ctx = ctx();
        ctx.path = "/public".to_string();
        assert!(matches!(
            plugin.authorize(&mut ctx).await,
            PluginResult::Continue
        ));
        let mut upstream = forged_upstream_headers();
        let _ = plugin.before_proxy(&mut ctx, &mut upstream).await;
        assert_eq!(upstream, forged_upstream_headers());
        assert_eq!(stub.calls.load(Ordering::SeqCst), 0);
    }

    /// A second allowing provider: a tenant header upstream and its own cookie.
    const TENANT_ALLOW: &str = "HTTP/1.1 200 OK\r\n\
x-tenant: tenant-b\r\n\
set-cookie: b-session=1; Path=/\r\n\
content-length: 0\r\n\r\n";

    fn plugin_with(
        provider_name: &str,
        port: u16,
        fail_open: bool,
        upstream: &[&str],
        downstream: &[&str],
    ) -> MeshAuthz {
        let slice = json!({
            "node_id": "node-a",
            "namespace": "default",
            "version": "test",
            "mesh_policies": [{
                "name": "delegate-admin",
                "namespace": "default",
                "scope": { "kind": "mesh_wide" },
                "rules": [{
                    "to": [{ "paths": ["/admin/*"] }],
                    "action": { "custom": { "provider": provider_name } },
                }],
            }],
            "ext_authz_providers": [{
                "name": provider_name,
                "service": "127.0.0.1",
                "port": port,
                "timeout_ms": 500,
                "fail_open": fail_open,
                "status_on_error": 403,
                "headers_to_upstream_on_allow": upstream,
                "headers_to_downstream_on_allow": downstream,
            }],
        });
        match MeshAuthz::new_with_http_client(
            &json!({ "mesh_slice": slice }),
            Some(PluginHttpClient::default()),
        ) {
            Ok(plugin) => plugin,
            Err(error) => panic!("generation builds: {error}"),
        }
    }

    /// Two effective `mesh_authz` instances on one request (an operator global
    /// beside the force-injected `__mesh_authz`) must each apply ONLY their own
    /// allowed result: a shared staging slot let the second check overwrite the
    /// first, so instance A consumed B's result and a forged A-owned header
    /// reached the backend.
    #[tokio::test]
    async fn two_instances_apply_only_their_own_allowed_results() {
        let stub_a = start_stub(StubBehavior::Raw(ALLOW_WITH_MUTATIONS)).await;
        let stub_b = start_stub(StubBehavior::Raw(TENANT_ALLOW)).await;
        let a = plugin_with(
            "instance-a-ext-authz",
            stub_a.port,
            false,
            &["x-auth-request-user"],
            &["set-cookie"],
        );
        let b = plugin_with(
            "instance-b-ext-authz",
            stub_b.port,
            false,
            &["x-tenant"],
            &["set-cookie"],
        );
        let mut ctx = ctx();
        assert!(matches!(
            a.authorize(&mut ctx).await,
            PluginResult::Continue
        ));
        assert!(matches!(
            b.authorize(&mut ctx).await,
            PluginResult::Continue
        ));

        let mut upstream = HashMap::from([
            ("x-auth-request-user".to_string(), "mallory".to_string()),
            ("X_Auth_Request_User".to_string(), "mallory".to_string()),
            ("x-tenant".to_string(), "forged".to_string()),
            ("x-request-id".to_string(), "abc-123".to_string()),
        ]);
        let _ = a.before_proxy(&mut ctx, &mut upstream).await;
        let _ = b.before_proxy(&mut ctx, &mut upstream).await;
        assert_eq!(
            upstream.get("x-auth-request-user").map(String::as_str),
            Some("alice"),
            "instance A installs its own provider's value"
        );
        assert!(!upstream.contains_key("X_Auth_Request_User"));
        assert_eq!(
            upstream.get("x-tenant").map(String::as_str),
            Some("tenant-b"),
            "instance B installs its own provider's value"
        );
        assert_eq!(
            upstream.get("x-request-id").map(String::as_str),
            Some("abc-123")
        );

        // The WebSocket handshake hook reads (does not consume) the staging:
        // each instance applies only its own cookie, exactly once.
        let mut handshake = HashMap::new();
        a.apply_websocket_handshake_response_headers(&ctx, 101, &mut handshake);
        b.apply_websocket_handshake_response_headers(&ctx, 101, &mut handshake);
        assert_eq!(
            handshake.get("set-cookie").map(String::as_str),
            Some("session=refreshed; Path=/\nb-session=1; Path=/")
        );

        let mut response = HashMap::from([("set-cookie".to_string(), "backend=1".to_string())]);
        let _ = a.after_proxy(&mut ctx, 200, &mut response).await;
        let _ = b.after_proxy(&mut ctx, 200, &mut response).await;
        assert_eq!(
            response.get("set-cookie").map(String::as_str),
            Some("backend=1\nsession=refreshed; Path=/\nb-session=1; Path=/"),
            "each provider's cookie appears exactly once"
        );
    }

    #[tokio::test]
    async fn a_downstream_only_instance_cannot_erase_another_instances_fail_open_strip() {
        // A's provider fails open: A must still strip the forged A-owned
        // header. B is downstream-only; its staging must not overwrite A's.
        let stub_a = start_status_stub(503).await;
        let stub_b = start_stub(StubBehavior::Raw(TENANT_ALLOW)).await;
        let a = plugin_with(
            "fail-open-a-ext-authz",
            stub_a.port,
            true,
            &["x-auth-request-user"],
            &[],
        );
        let b = plugin_with(
            "downstream-only-b-ext-authz",
            stub_b.port,
            false,
            &[],
            &["set-cookie"],
        );
        let mut ctx = ctx();
        assert!(matches!(
            a.authorize(&mut ctx).await,
            PluginResult::Continue
        ));
        assert!(matches!(
            b.authorize(&mut ctx).await,
            PluginResult::Continue
        ));
        let mut upstream = forged_upstream_headers();
        let _ = a.before_proxy(&mut ctx, &mut upstream).await;
        let _ = b.before_proxy(&mut ctx, &mut upstream).await;
        assert!(!upstream.contains_key("x-auth-request-user"));
        assert!(!upstream.contains_key("X_Auth_Request_User"));
        let mut response = HashMap::new();
        let _ = a.after_proxy(&mut ctx, 200, &mut response).await;
        let _ = b.after_proxy(&mut ctx, 200, &mut response).await;
        assert_eq!(
            response.get("set-cookie").map(String::as_str),
            Some("b-session=1; Path=/")
        );
    }

    /// A header an earlier plugin removed from the materialized request view is
    /// not forwarded to the provider from the retained raw block.
    #[tokio::test]
    async fn a_header_removed_before_authorization_is_not_forwarded_to_the_provider() {
        let stub = start_stub(StubBehavior::Allow).await;
        let slice = json!({
            "node_id": "node-a",
            "namespace": "default",
            "version": "test",
            "mesh_policies": [{
                "name": "delegate-admin",
                "namespace": "default",
                "scope": { "kind": "mesh_wide" },
                "rules": [{
                    "to": [{ "paths": ["/admin/*"] }],
                    "action": { "custom": { "provider": "removal-ext-authz" } },
                }],
            }],
            "ext_authz_providers": [{
                "name": "removal-ext-authz",
                "service": "127.0.0.1",
                "port": stub.port,
                "timeout_ms": 500,
                "status_on_error": 403,
                "include_request_headers_in_check": ["x-role", "x-request-id"],
            }],
        });
        let plugin = match MeshAuthz::new_with_http_client(
            &json!({ "mesh_slice": slice }),
            Some(PluginHttpClient::default()),
        ) {
            Ok(plugin) => plugin,
            Err(error) => panic!("generation builds: {error}"),
        };
        let mut ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/admin/reports".to_string(),
        );
        let mut raw = http::HeaderMap::new();
        raw.insert("host", "api.example.com".parse().expect("header value"));
        raw.insert("x-role", "admin".parse().expect("header value"));
        raw.insert("x-request-id", "abc-123".parse().expect("header value"));
        ctx.set_raw_headers(raw);
        ctx.materialize_headers();
        // An earlier plugin strips the untrusted client field.
        ctx.headers.remove("x-role");
        assert!(matches!(
            plugin.authorize(&mut ctx).await,
            PluginResult::Continue
        ));
        let seen = stub.last_request.lock().expect("stub request").clone();
        assert!(
            seen_header_lines(&seen, "x-role").is_empty(),
            "a removed header must not be resurrected for the provider: {seen}"
        );
        assert_eq!(
            seen_header_lines(&seen, "x-request-id"),
            vec!["abc-123".to_string()]
        );
    }

    #[tokio::test]
    async fn the_live_datapath_stamps_the_peer_identity_and_merges_denial_cookies() {
        let stub = start_stub(StubBehavior::Raw(MULTI_LINE_DENIAL)).await;
        let slice = json!({
            "node_id": "node-a",
            "namespace": "default",
            "version": "test",
            "mesh_policies": [{
                "name": "delegate-admin",
                "namespace": "default",
                "scope": { "kind": "mesh_wide" },
                "rules": [{
                    "to": [{ "paths": ["/admin/*"] }],
                    "action": { "custom": { "provider": "sample-ext-authz" } },
                }],
            }],
            "ext_authz_providers": [{
                "name": "sample-ext-authz",
                "service": "127.0.0.1",
                "port": stub.port,
                "timeout_ms": 500,
                "status_on_error": 403,
                "headers_to_downstream_on_deny": ["set-cookie", "www-authenticate"],
            }],
        });
        let plugin = match MeshAuthz::new_with_http_client(
            &json!({ "mesh_slice": slice }),
            Some(PluginHttpClient::default()),
        ) {
            Ok(plugin) => plugin,
            Err(error) => panic!("generation builds: {error}"),
        };
        let mut ctx = ctx();
        ctx.peer_spiffe_id = Some(
            ferrum_edge::identity::SpiffeId::new("spiffe://cluster.local/ns/shop/sa/frontend")
                .expect("valid spiffe id"),
        );
        // A client-supplied copy of the identity header is never what the
        // provider sees.
        ctx.headers.insert(
            "x-ferrum-source-principal".to_string(),
            "spiffe://cluster.local/ns/evil/sa/forged".to_string(),
        );
        match plugin.authorize(&mut ctx).await {
            PluginResult::Reject {
                status_code,
                headers,
                ..
            } => {
                assert_eq!(status_code, 302);
                assert_eq!(
                    headers.get("set-cookie").map(String::as_str),
                    Some("oauth_state=s1; Path=/\ncsrf_nonce=n1; Path=/")
                );
                assert_eq!(
                    headers.get("www-authenticate").map(String::as_str),
                    Some("Bearer realm=\"mesh\", Basic realm=\"mesh\"")
                );
            }
            other => panic!("expected the provider's denial, got {other:?}"),
        }
        let seen = stub.last_request.lock().expect("stub request").clone();
        assert_eq!(
            seen_header_lines(&seen, "x-ferrum-source-principal"),
            vec!["spiffe://cluster.local/ns/shop/sa/frontend".to_string()]
        );
    }
}

// ── Per-provider attribution ──────────────────────────────────────────────

#[tokio::test]
async fn checks_are_attributed_to_their_admitted_provider_with_a_duration() {
    // A provider name no other test uses: the registry is process-wide.
    const NAME: &str = "attribution-ext-authz";
    let allow = start_stub(StubBehavior::Allow).await;
    let mut allowing = provider(allow.port);
    allowing.name = NAME.to_string();
    let executor = executor(vec![allowing]);
    let _ = check(&executor, NAME, &request_headers()).await;
    let _ = check(&executor, NAME, &request_headers()).await;

    let (outcomes, timed) = ferrum_edge::plugins::mesh::ext_authz::provider_snapshot(NAME)
        .expect("the admitted provider is registered");
    // The stub closes each connection after answering, so a pooled second
    // check can race that close; what is pinned here is attribution, not the
    // stub's keep-alive behaviour.
    assert_eq!(
        outcomes.iter().map(|(_, count)| *count).sum::<u64>(),
        2,
        "both checks are attributed to the provider: {outcomes:?}"
    );
    assert!(
        outcomes.iter().any(|(outcome, _)| *outcome == "allowed"),
        "{outcomes:?}"
    );
    assert_eq!(timed, 2, "every dispatched check records one duration");

    let mut rendered = String::new();
    ferrum_edge::plugins::mesh::ext_authz::render_prometheus(&mut rendered, "");
    assert!(
        rendered.contains(&format!(
            "ferrum_mesh_ext_authz_provider_checks_total{{provider=\"{NAME}\",outcome=\"allowed\"}}"
        )),
        "per-provider outcome series missing:\n{rendered}"
    );
    assert!(
        rendered.contains(&format!(
            "ferrum_mesh_ext_authz_check_duration_seconds_count{{provider=\"{NAME}\"}} 2"
        )),
        "per-provider duration histogram missing:\n{rendered}"
    );
    assert!(
        rendered.contains(&format!(
            "ferrum_mesh_ext_authz_check_duration_seconds_bucket{{provider=\"{NAME}\",le=\"+Inf\"}} 2"
        )),
        "histogram +Inf bucket must equal the count:\n{rendered}"
    );
}

/// A scrape racing live checks must never emit a finite bucket above `+Inf`,
/// and `+Inf` must always equal `_count`: both are derived from one read of
/// the bucket slots.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_scrape_racing_live_checks_keeps_the_histogram_consistent() {
    const NAME: &str = "histogram-race-ext-authz";
    let stub = start_stub(StubBehavior::Allow).await;
    let mut source = provider(stub.port);
    source.name = NAME.to_string();
    let executor = Arc::new(executor(vec![source]));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let executor = Arc::clone(&executor);
        workers.push(tokio::spawn(async move {
            let headers = request_headers();
            for _ in 0..25 {
                let _ = check(&executor, NAME, &headers).await;
            }
        }));
    }

    let bucket_prefix =
        format!("ferrum_mesh_ext_authz_check_duration_seconds_bucket{{provider=\"{NAME}\",le=\"");
    let count_prefix =
        format!("ferrum_mesh_ext_authz_check_duration_seconds_count{{provider=\"{NAME}\"}} ");
    let mut scrapes = 0usize;
    loop {
        let done = workers.iter().all(|worker| worker.is_finished());
        let mut rendered = String::new();
        ferrum_edge::plugins::mesh::ext_authz::render_prometheus(&mut rendered, "");
        let mut finite = Vec::new();
        let mut inf = None;
        let mut count = None;
        for line in rendered.lines() {
            if let Some(rest) = line.strip_prefix(&bucket_prefix) {
                let (le, value) = rest.split_once("\"} ").expect("bucket line shape");
                let value: u64 = value.parse().expect("bucket value");
                if le == "+Inf" {
                    inf = Some(value);
                } else {
                    finite.push(value);
                }
            } else if let Some(value) = line.strip_prefix(&count_prefix) {
                count = Some(value.parse::<u64>().expect("count value"));
            }
        }
        if let (Some(inf), Some(count)) = (inf, count) {
            assert_eq!(inf, count, "+Inf must equal _count:\n{rendered}");
            assert!(
                finite.windows(2).all(|pair| pair[0] <= pair[1]),
                "finite buckets must be cumulative:\n{rendered}"
            );
            assert!(
                finite.iter().all(|bucket| *bucket <= inf),
                "no finite bucket may exceed +Inf:\n{rendered}"
            );
            scrapes += 1;
        }
        if done {
            break;
        }
        tokio::task::yield_now().await;
    }
    for worker in workers {
        worker.await.expect("worker completes");
    }
    assert!(scrapes > 0, "at least one scrape observed the histogram");
}
