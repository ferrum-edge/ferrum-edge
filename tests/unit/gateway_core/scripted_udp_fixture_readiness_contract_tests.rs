//! Static contract: the scripted UDP functional fixture must bind readiness
//! to the spawned child (issue #4373).
//!
//! `include_str!` only — no runtime, no production bypass.

const UDP_FIXTURE: &str = include_str!("../../functional/scripted_backend_udp_tests.rs");

fn squeezed(src: &str) -> String {
    src.chars().filter(|c| !c.is_whitespace()).collect()
}

fn helper_region(src: &str) -> &str {
    let start = src
        .find("fn mint_observability_token()")
        .expect("scripted UDP fixture must mint a per-attempt observability token");
    let end = src
        .find("struct GatewayFixture")
        .expect("scripted UDP fixture must keep GatewayFixture after the spawn helper");
    &src[start..end]
}

#[test]
fn scripted_udp_fixture_binds_readiness_to_spawned_child_identity() {
    let region = helper_region(UDP_FIXTURE);
    let compact = squeezed(region);

    assert!(
        compact.contains("crate::common::wait_for_child_gateway_readiness(child,"),
        "readiness must use the shared child-bound wait_for_child_gateway_readiness barrier"
    );
    assert!(
        compact.contains("wait_for_owned_gateway(&mutchild,admin_port,&observability_token)"),
        "the barrier must be bound to the child spawned by this attempt"
    );
    assert!(
        compact.contains("env(\"FERRUM_METRICS_BEARER_TOKEN\",observability_token)"),
        "each spawn must configure FERRUM_METRICS_BEARER_TOKEN for this child"
    );
    assert!(
        compact.contains("env_remove(\"FERRUM_METRICS_ALLOWED_CIDRS\")"),
        "a leaked CIDR allowlist must not let a foreign listener answer detail-tier /health"
    );

    let extra_at = compact
        .find("for(k,v)inextra_env{cmd.env(k,v);}")
        .expect("extra_env must still be applied");
    let token_at = compact
        .find("env(\"FERRUM_METRICS_BEARER_TOKEN\",observability_token)")
        .expect("identity token env must be present");
    assert!(
        token_at > extra_at,
        "identity env must be applied after extra_env so callers cannot replace this child's token"
    );

    assert!(
        compact.contains("Uuid::new_v4()"),
        "each spawn attempt must mint a unique observability identity"
    );
    assert!(
        region.contains("ready: true"),
        "the barrier must require authenticated health detail with ready:true"
    );
    // `Child::try_wait` before and after every probe now lives in the shared
    // helper; the `child_readiness_*` tests in `tests/common/gateway_harness.rs`
    // pin it.
    assert!(
        compact.contains("std::process::Stdio::null()")
            && !compact.contains("std::process::Stdio::piped()"),
        "capture must stay on files or null; piped stdio deadlocks"
    );
    assert!(
        !region.contains("async fn wait_for_health")
            && !compact.contains("r.status().is_success()"),
        "unauthenticated /health 2xx must not admit the spawn attempt"
    );
}

#[test]
fn scripted_udp_amplification_assertion_is_not_retried() {
    let src = UDP_FIXTURE;
    let start = src
        .find("async fn udp_amplification_cumulative_multi_datagram_budget()")
        .expect("cumulative amplification test must exist");
    let rest = &src[start..];
    let end = rest
        .find("async fn dtls_passthrough_sni_routes_to_correct_backend()")
        .unwrap_or(rest.len());
    let test = &rest[..end];
    let compact = squeezed(test);

    assert_eq!(
        compact.matches("start_gateway_with_retry(").count(),
        1,
        "the cumulative budget test must spawn the gateway once"
    );
    assert_eq!(
        compact.matches("recv_batch_with_deadline(").count(),
        1,
        "the cumulative budget test must make one receive observation"
    );
    assert_eq!(
        compact.matches("ScriptedUdpBackend::builder").count(),
        1,
        "the cumulative budget test must spawn the scripted backend once"
    );
    let gateway_at = compact
        .find("start_gateway_with_retry(")
        .expect("start_gateway_with_retry must appear");
    let backend_at = compact
        .find("ScriptedUdpBackend::builder")
        .expect("ScriptedUdpBackend::builder must appear");
    assert!(
        gateway_at < backend_at,
        "gateway readiness must complete before the scripted backend expect deadline starts"
    );
    assert!(
        compact.contains("assert_eq!(received.len(),2,"),
        "the cumulative budget assertion must remain a single authoritative check"
    );
    let recv_at = compact
        .find("recv_batch_with_deadline(")
        .expect("recv_batch_with_deadline must appear");
    assert!(
        !compact[recv_at..].contains("start_gateway_with_retry("),
        "a failed reply count must not respawn the gateway and retry the assertion"
    );
}
