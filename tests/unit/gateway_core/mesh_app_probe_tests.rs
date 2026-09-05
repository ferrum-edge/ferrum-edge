//! Request → target mapping for the mesh application-probe server (#4533).
//!
//! The server exists so kubelet can probe the sidecar instead of the
//! application port, which is what lets the injector stop punching
//! destination-port-wide `RETURN` holes in inbound capture. Its whole
//! admissible surface is the injector-supplied target list, so these tests pin
//! that NOTHING in a request can name a host, port, path, or scheme.

use ferrum_edge::modes::mesh::app_probe::{
    APP_PROBE_PATH_PREFIX, AppProbeGrpc, AppProbeHttpGet, AppProbeScheme, AppProbeServer,
    AppProbeSpec, AppProbeTcpSocket, DEFAULT_APP_PROBE_PORT, DEFAULT_PROBE_TIMEOUT_SECONDS,
    MAX_PROBE_TIMEOUT_SECONDS, app_probe_key, app_probe_path, parse_app_probes,
    validate_probe_container_name,
};
use hyper::{Method, StatusCode};

fn http_spec(port: u16) -> AppProbeSpec {
    AppProbeSpec::from_http_get(
        AppProbeHttpGet {
            path: "/livez".to_string(),
            port,
            scheme: AppProbeScheme::Http,
            host: None,
            http_headers: Vec::new(),
        },
        DEFAULT_PROBE_TIMEOUT_SECONDS,
    )
}

fn server_with_one_target() -> AppProbeServer {
    let mut targets = std::collections::BTreeMap::new();
    targets.insert(app_probe_key("app", "livenessProbe"), http_spec(8080));
    AppProbeServer::new(targets)
}

#[test]
fn rewritten_path_round_trips_to_its_registered_target() {
    let server = server_with_one_target();
    let path = app_probe_path("app", "livenessProbe");
    assert_eq!(path, format!("{APP_PROBE_PATH_PREFIX}app/livenessProbe"));
    let (container, probe, spec) = server.resolve_target(&path).expect("registered target");
    assert_eq!(container, "app");
    assert_eq!(probe, "livenessProbe");
    assert_eq!(spec.http_get.as_ref().map(|h| h.port), Some(8080));
}

#[test]
fn unknown_container_or_probe_field_resolves_to_nothing() {
    let server = server_with_one_target();
    for path in [
        "/app-probe/other/livenessProbe",
        "/app-probe/app/readinessProbe",
        "/app-probe/app",
        "/app-probe/",
        "/app-probe/app/livenessProbe/extra",
        "/healthz",
        "/",
    ] {
        assert!(
            server.resolve_target(path).is_none(),
            "{path} must not resolve to a probe target"
        );
    }
}

/// The server takes no target from the request: there is no host, port, or
/// path parameter to supply, and a path that merely *looks* like one is an
/// unregistered key.
#[test]
fn request_supplied_targets_are_never_honored() {
    let server = server_with_one_target();
    for path in [
        "/app-probe/127.0.0.1:9999/livenessProbe",
        "/app-probe/app/livenessProbe?port=9999",
        "/app-probe/../app/livenessProbe",
        "/app-probe/%2e%2e/app/livenessProbe",
        "/app-probe/http://example.com/livenessProbe",
    ] {
        assert!(
            server.resolve_target(path).is_none(),
            "{path} must not resolve to a probe target"
        );
    }
}

#[tokio::test]
async fn unregistered_target_is_404_and_runs_no_probe() {
    let server = server_with_one_target();
    assert_eq!(
        server
            .handle_request(&Method::GET, "/app-probe/app/readinessProbe")
            .await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        server.handle_request(&Method::GET, "/metrics").await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn non_probe_methods_are_rejected() {
    let server = server_with_one_target();
    for method in [Method::POST, Method::PUT, Method::DELETE, Method::CONNECT] {
        assert_eq!(
            server
                .handle_request(&method, &app_probe_path("app", "livenessProbe"))
                .await,
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} must not drive a probe"
        );
    }
}

#[test]
fn recorded_probes_round_trip_through_the_env_encoding() {
    let mut targets = std::collections::BTreeMap::new();
    targets.insert(app_probe_key("app", "livenessProbe"), http_spec(8080));
    targets.insert(
        app_probe_key("metrics", "readinessProbe"),
        AppProbeSpec::from_tcp_socket(AppProbeTcpSocket { port: 9090 }, 2),
    );
    targets.insert(
        app_probe_key("grpcsvc", "startupProbe"),
        AppProbeSpec::from_grpc(
            AppProbeGrpc {
                port: 50051,
                service: Some("readiness".to_string()),
            },
            5,
        ),
    );
    let encoded = serde_json::to_string(&targets).expect("encode");
    assert_eq!(parse_app_probes(&encoded).expect("decode"), targets);
}

#[test]
fn empty_probe_env_is_an_empty_target_set() {
    assert!(parse_app_probes("").expect("empty").is_empty());
    assert!(parse_app_probes("   ").expect("blank").is_empty());
    assert!(parse_app_probes("{}").expect("empty object").is_empty());
}

#[test]
fn malformed_probe_env_fails_closed() {
    for raw in [
        // Not an object.
        "[]",
        // Two handlers on one probe.
        r#"{"app/livenessProbe":{"httpGet":{"port":8080},"tcpSocket":{"port":9090}}}"#,
        // No handler at all.
        r#"{"app/livenessProbe":{"timeoutSeconds":1}}"#,
        // Unknown probe field.
        r#"{"app/warmupProbe":{"tcpSocket":{"port":9090}}}"#,
        // Key is not `<container>/<probeField>`.
        r#"{"livenessProbe":{"tcpSocket":{"port":9090}}}"#,
        // Container name that could not have come from a real pod spec.
        r#"{"a b/livenessProbe":{"tcpSocket":{"port":9090}}}"#,
        // Unknown field (deny_unknown_fields).
        r#"{"app/livenessProbe":{"tcpSocket":{"port":9090},"exec":{"command":["x"]}}}"#,
    ] {
        assert!(
            parse_app_probes(raw).is_err(),
            "{raw} must be refused rather than partially honored"
        );
    }
}

#[test]
fn recorded_timeout_is_bounded() {
    let spec = AppProbeSpec::from_tcp_socket(AppProbeTcpSocket { port: 9090 }, 0);
    assert_eq!(
        spec.timeout_seconds, 1,
        "a zero timeout would never succeed"
    );
    let spec = AppProbeSpec::from_tcp_socket(AppProbeTcpSocket { port: 9090 }, u64::MAX);
    assert_eq!(spec.timeout_seconds, MAX_PROBE_TIMEOUT_SECONDS);
}

#[test]
fn container_names_that_cannot_address_a_probe_are_refused() {
    for name in ["", "App", "a/b", "a b", "a?b", "a%2fb", "../etc"] {
        assert!(
            validate_probe_container_name(name).is_err(),
            "'{name}' must not become part of a rewritten probe path"
        );
    }
    for name in ["app", "my-app-1", "a"] {
        assert!(validate_probe_container_name(name).is_ok(), "'{name}'");
    }
}

#[test]
fn default_probe_port_matches_the_istio_status_port() {
    assert_eq!(DEFAULT_APP_PROBE_PORT, 15020);
}

// ── Admission (issue #4625) ──────────────────────────────────────────────
//
// The probe listener is plaintext, wildcard-bound, and deliberately exempt from
// inbound mesh capture, so every peer that can reach the Pod IP reaches it
// without mTLS or `mesh_authz`. Two independent ceilings bound that: a
// connection cap taken in the accept loop before any task/HTTP state exists,
// and an active-probe budget taken before the loopback probe runs.

mod admission {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    use ferrum_edge::config::EnvConfig;
    use ferrum_edge::modes::mesh::app_probe::{
        AppProbeAdmission, AppProbeAdmissionRejection, AppProbeBudget, AppProbeServer,
        DEFAULT_APP_PROBE_MAX_ACTIVE_PROBES, DEFAULT_APP_PROBE_MAX_CONNECTIONS,
        DEFAULT_APP_PROBE_MAX_CONNECTIONS_PER_IP, parse_app_probes,
    };
    use ferrum_edge::overload::OverloadState;
    use ferrum_edge::util::conn_limit::ConnRejectReason;
    use hyper::{Method, StatusCode};

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, last))
    }

    /// A target whose loopback port is closed, so the probe itself resolves
    /// fast and deterministically without a fixture backend.
    fn one_target_server(admission: Arc<AppProbeAdmission>) -> AppProbeServer {
        let targets = parse_app_probes(
            r#"{"app/livenessProbe":{"httpGet":{"path":"/livez","port":1,"scheme":"HTTP"},"timeoutSeconds":1}}"#,
        )
        .expect("targets parse");
        AppProbeServer::with_admission(targets, admission)
    }

    /// A partial-header flood cannot hold more sockets than the ceiling: the
    /// permit is what bounds it, and it is taken before anything is allocated.
    #[test]
    fn the_connection_cap_admits_exactly_max_connections() {
        let admission = AppProbeAdmission::new(4, 0, 0, None);
        let permits: Vec<_> = (0..4)
            .map(|i| {
                admission
                    .try_admit(ip(i))
                    .expect("the first four probe connections are admitted")
            })
            .collect();
        assert_eq!(admission.limiter_snapshot().active_connections, 4);

        let rejected = admission
            .try_admit(ip(9))
            .expect_err("the fifth connection is over the ceiling");
        assert_eq!(
            rejected,
            AppProbeAdmissionRejection::Limit(ConnRejectReason::MaxConnections)
        );
        assert_eq!(rejected.as_label(), "max_connections");

        // RAII release on every exit shape — the permit is dropped when the
        // connection task ends, whatever ended it.
        drop(permits);
        assert_eq!(admission.limiter_snapshot().active_connections, 0);
        assert!(admission.try_admit(ip(9)).is_ok());
    }

    /// Kubelet dials from the node, so one hostile source must not be able to
    /// take the share kubelet's own probes need.
    #[test]
    fn one_source_cannot_take_the_whole_connection_budget() {
        let admission = AppProbeAdmission::new(8, 2, 0, None);
        let noisy = ip(5);
        let _first = admission.try_admit(noisy).expect("first");
        let _second = admission.try_admit(noisy).expect("second");
        let rejected = admission
            .try_admit(noisy)
            .expect_err("the third from one source exceeds its share");
        assert_eq!(
            rejected,
            AppProbeAdmissionRejection::Limit(ConnRejectReason::MaxConnectionsPerIp)
        );
        assert_eq!(rejected.as_label(), "max_connections_per_ip");
        // Kubelet's own source is unaffected.
        assert!(admission.try_admit(ip(6)).is_ok());
        // IPv6 peers share the same dimension.
        let peer = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2));
        let _v6 = admission.try_admit(peer).expect("first v6");
        let _v6b = admission.try_admit(peer).expect("second v6");
        assert!(admission.try_admit(peer).is_err());
    }

    /// Critical overload admits no new probe connection, and the refusal costs
    /// no slot — the flag is checked before the semaphore is touched.
    #[test]
    fn critical_overload_admits_no_probe_connection() {
        let overload = Arc::new(OverloadState::new());
        let admission = AppProbeAdmission::new(64, 8, 8, Some(Arc::clone(&overload)));
        assert!(admission.try_admit(ip(1)).is_ok());

        overload
            .reject_new_connections
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let rejected = admission
            .try_admit(ip(1))
            .expect_err("critical overload admits nothing");
        assert_eq!(rejected, AppProbeAdmissionRejection::Overload);
        assert_eq!(rejected.as_label(), "overload");
        assert_eq!(admission.rejected_overload(), 1);
        let snapshot = admission.limiter_snapshot();
        assert_eq!(snapshot.rejected_max_connections, 0);
        assert_eq!(snapshot.rejected_max_connections_per_ip, 0);

        overload
            .reject_new_connections
            .store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(admission.try_admit(ip(1)).is_ok());
    }

    /// With no overload state wired (standalone construction) the listener
    /// never sheds on that dimension.
    #[test]
    fn without_overload_state_only_the_caps_apply() {
        let admission = AppProbeAdmission::new(2, 0, 0, None);
        let _a = admission.try_admit(ip(1)).expect("first");
        let _b = admission.try_admit(ip(2)).expect("second");
        assert_eq!(
            admission.try_admit(ip(3)).unwrap_err(),
            AppProbeAdmissionRejection::Limit(ConnRejectReason::MaxConnections)
        );
        assert_eq!(admission.rejected_overload(), 0);
    }

    /// The active-probe budget is a second, independent dimension: it bounds
    /// executing probes, not sockets, and releases on drop.
    #[test]
    fn the_active_probe_budget_bounds_concurrent_probes() {
        let budget = Arc::new(AppProbeBudget::new(2));
        assert_eq!(budget.max(), 2);
        let first = budget.try_acquire().expect("first probe admitted");
        let second = budget.try_acquire().expect("second probe admitted");
        assert_eq!(budget.active(), 2);
        assert!(budget.try_acquire().is_err());
        assert_eq!(budget.rejected(), 1);

        drop(first);
        assert_eq!(budget.active(), 1);
        let _third = budget.try_acquire().expect("a released slot is reusable");
        assert_eq!(budget.active(), 2);
        drop(second);
        assert_eq!(budget.active(), 1);
    }

    /// `0` keeps meaning unlimited on the probe budget, as on every other cap.
    #[test]
    fn a_zero_active_probe_budget_is_unlimited() {
        let budget = Arc::new(AppProbeBudget::new(0));
        assert_eq!(budget.max(), 0);
        let permits: Vec<_> = (0..128)
            .map(|_| budget.try_acquire().expect("unlimited"))
            .collect();
        assert_eq!(budget.active(), 128);
        assert_eq!(budget.rejected(), 0);
        drop(permits);
        assert_eq!(budget.active(), 0);
    }

    /// An over-budget probe request is SHED, not queued: a bounded 503 with a
    /// fixed body and `Connection: close`, and no probe runs.
    #[tokio::test]
    async fn an_over_budget_probe_request_is_shed_with_connection_close() {
        let admission = Arc::new(AppProbeAdmission::new(0, 0, 1, None));
        let server = one_target_server(Arc::clone(&admission));

        // Occupy the whole budget the way an in-flight probe would.
        let held = admission.budget().try_acquire().expect("hold the one slot");

        let response = server
            .handle_request_detailed(&Method::GET, "/app-probe/app/livenessProbe")
            .await;
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.close, "an over-budget refusal retires the socket");
        assert_eq!(response.body, "app probe budget exhausted\n");
        assert_eq!(admission.budget().rejected(), 1);

        // Below the ceiling the ordinary path is unchanged: the probe runs and
        // reports its own outcome, on a keep-alive connection.
        drop(held);
        let response = server
            .handle_request_detailed(&Method::GET, "/app-probe/app/livenessProbe")
            .await;
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(!response.close);
        assert_eq!(
            response.body, "app probe failed\n",
            "a probe against a closed loopback port is a probe FAILURE, not a budget refusal"
        );
    }

    /// The budget is taken after target resolution, so an unknown target still
    /// costs nothing and still 404s.
    #[tokio::test]
    async fn an_unknown_target_never_consumes_the_probe_budget() {
        let admission = Arc::new(AppProbeAdmission::new(0, 0, 1, None));
        let server = one_target_server(Arc::clone(&admission));
        let response = server
            .handle_request_detailed(&Method::GET, "/app-probe/app/nope")
            .await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
        assert!(!response.close);
        assert_eq!(admission.budget().active(), 0);
        assert_eq!(admission.budget().rejected(), 0);
    }

    /// Defaults are non-zero and per-IP never exceeds the global cap, which is
    /// the condition `validate_mesh_app_probe_limits` refuses.
    #[test]
    fn defaults_are_safe_and_come_from_the_env_config() {
        const {
            assert!(DEFAULT_APP_PROBE_MAX_CONNECTIONS > 0);
            assert!(DEFAULT_APP_PROBE_MAX_CONNECTIONS_PER_IP > 0);
            assert!(DEFAULT_APP_PROBE_MAX_ACTIVE_PROBES > 0);
            assert!(DEFAULT_APP_PROBE_MAX_CONNECTIONS_PER_IP <= DEFAULT_APP_PROBE_MAX_CONNECTIONS);
        }

        let env_config = EnvConfig::default();
        assert_eq!(
            env_config.mesh_app_probe_max_connections,
            DEFAULT_APP_PROBE_MAX_CONNECTIONS
        );
        assert_eq!(
            env_config.mesh_app_probe_max_connections_per_ip,
            DEFAULT_APP_PROBE_MAX_CONNECTIONS_PER_IP
        );
        assert_eq!(
            env_config.mesh_app_probe_max_active_probes,
            DEFAULT_APP_PROBE_MAX_ACTIVE_PROBES
        );
        assert!(env_config.validate_mesh_app_probe_limits().is_ok());

        let admission = AppProbeAdmission::from_env_config(&env_config, None);
        let snapshot = admission.limiter_snapshot();
        assert_eq!(snapshot.max_connections, DEFAULT_APP_PROBE_MAX_CONNECTIONS);
        assert_eq!(
            snapshot.max_connections_per_ip,
            DEFAULT_APP_PROBE_MAX_CONNECTIONS_PER_IP
        );
        assert_eq!(
            admission.budget().max(),
            DEFAULT_APP_PROBE_MAX_ACTIVE_PROBES
        );
    }

    /// A per-IP cap above the global cap can never fire, so it is a startup
    /// error rather than a silent no-op; an out-of-range value is refused
    /// rather than clamped.
    #[test]
    fn unenforceable_limits_are_refused_at_configuration_time() {
        let unreachable_share = EnvConfig {
            mesh_app_probe_max_connections: 8,
            mesh_app_probe_max_connections_per_ip: 9,
            ..EnvConfig::default()
        };
        let err = unreachable_share
            .validate_mesh_app_probe_limits()
            .expect_err("a per-IP cap above the global cap can never fire");
        assert!(
            err.contains("FERRUM_MESH_APP_PROBE_MAX_CONNECTIONS_PER_IP"),
            "{err}"
        );

        // Disabling the per-IP cap deliberately is still allowed.
        let share_disabled = EnvConfig {
            mesh_app_probe_max_connections: 8,
            mesh_app_probe_max_connections_per_ip: 0,
            ..EnvConfig::default()
        };
        assert!(share_disabled.validate_mesh_app_probe_limits().is_ok());

        // A disabled global cap makes the per-IP cap the only bound; that is a
        // coherent configuration, not an error.
        let global_disabled = EnvConfig {
            mesh_app_probe_max_connections: 0,
            mesh_app_probe_max_connections_per_ip: 4096,
            ..EnvConfig::default()
        };
        assert!(global_disabled.validate_mesh_app_probe_limits().is_ok());

        let over = ferrum_edge::util::conn_limit::MAX_CONN_LIMIT + 1;
        for (label, env_config) in [
            (
                "FERRUM_MESH_APP_PROBE_MAX_CONNECTIONS",
                EnvConfig {
                    mesh_app_probe_max_connections: over,
                    ..EnvConfig::default()
                },
            ),
            (
                "FERRUM_MESH_APP_PROBE_MAX_CONNECTIONS_PER_IP",
                EnvConfig {
                    mesh_app_probe_max_connections: 0,
                    mesh_app_probe_max_connections_per_ip: over,
                    ..EnvConfig::default()
                },
            ),
            (
                "FERRUM_MESH_APP_PROBE_MAX_ACTIVE_PROBES",
                EnvConfig {
                    mesh_app_probe_max_active_probes: over,
                    ..EnvConfig::default()
                },
            ),
        ] {
            let err = env_config
                .validate_mesh_app_probe_limits()
                .expect_err("an out-of-range cap is refused, never clamped");
            assert!(err.contains(label), "{err}");
        }
    }
}
