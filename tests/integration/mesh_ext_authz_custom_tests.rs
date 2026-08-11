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
