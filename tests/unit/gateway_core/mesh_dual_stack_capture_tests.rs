//! Dual-stack Sidecar TCP capture contracts (issues #4271 and #4276).
//!
//! Sidecar capture is netfilter REDIRECT, and the injector emits the redirect
//! rules PER ADDRESS FAMILY against the SAME ports. Three properties make that
//! model safe, and each is a silent black hole or a hairpin loop if lost:
//!
//! * the listener plan covers every family whose rules exist, or a captured
//!   connection lands on a port with no listener and is refused;
//! * a dual-stack accept's IPv4-mapped local address selects the IPv4 conntrack
//!   socket option, or `SO_ORIGINAL_DST` answers `ENOENT` and multi-port
//!   disambiguation plus pre-handshake `portLevelMtls` selection are lost;
//! * the outbound chain returns locally destined traffic BEFORE any REDIRECT,
//!   or every intra-pod `127.0.0.1` connection is hairpinned into the mesh
//!   outbound proxy.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ferrum_edge::capture::{CaptureConfig, CaptureMode, Ip6TablesMode, IptablesPlan};
use ferrum_edge::config::env_config::EnvConfig;
use ferrum_edge::modes::mesh::{
    MeshListener, MeshListenerKind, MeshRuntimeConfig, MeshTrafficDirection,
};
use ferrum_edge::socket_opts::{is_ipv6_unavailable_io_error, original_dst_lookup_addr};

use crate::unit::env_lock::EnvGuard;

/// Every variable this suite sets or depends on being absent. `EnvGuard`
/// snapshots and restores all of them, and holds the process-wide env lock for
/// the duration, so a parallel suite can neither observe nor leak into this
/// state.
const MESH_ENV_KEYS: &[&str] = &[
    "FERRUM_MODE",
    "FERRUM_DP_CP_GRPC_URLS",
    "FERRUM_CP_DP_GRPC_JWT_SECRET",
    "FERRUM_MESH_ALLOW_NO_CA",
    "FERRUM_MESH_TOPOLOGY",
    "FERRUM_MESH_INBOUND_LISTEN_ADDR",
    "FERRUM_MESH_OUTBOUND_LISTEN_ADDR",
    "FERRUM_MESH_CAPTURE_IPV6_ENABLED",
    "FERRUM_MESH_IP6TABLES_ENABLED",
    "FERRUM_MESH_CAPTURE_INCLUDE_CIDRS",
    "FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS",
    "FERRUM_MESH_CAPTURE_UDP_ENABLED",
    "FERRUM_NODE_AGENT_INGRESS_REDIRECT_IFACES",
];

/// Build a Sidecar `MeshRuntimeConfig` with `extra` applied on top of the
/// minimum viable mesh env, and hand it to `assert`.
fn with_sidecar_runtime<F: FnOnce(&MeshRuntimeConfig)>(extra: &[(&str, &str)], assert: F) {
    let guard = EnvGuard::new(MESH_ENV_KEYS);
    for &key in MESH_ENV_KEYS {
        guard.unset(key);
    }
    guard.set("FERRUM_MODE", "mesh");
    guard.set("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051");
    guard.set(
        "FERRUM_CP_DP_GRPC_JWT_SECRET",
        "secret-padding-for-32-char-min!!",
    );
    // These tests plan listeners; they do not exercise the PERMISSIVE-no-CA
    // startup gate, so acknowledge the no-CA dev posture explicitly.
    guard.set("FERRUM_MESH_ALLOW_NO_CA", "true");
    for (key, value) in extra {
        guard.set(key, value);
    }

    let env = EnvConfig::from_env().expect("mesh env config");
    let runtime = MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
    assert(&runtime);
}

fn listeners_for(
    runtime: &MeshRuntimeConfig,
    direction: MeshTrafficDirection,
    kind: MeshListenerKind,
) -> Vec<MeshListener> {
    runtime
        .listener_plan()
        .into_iter()
        .filter(|listener| listener.direction == direction && listener.kind == kind)
        .collect()
}

#[test]
fn sidecar_capture_listener_plan_is_unchanged_without_ipv6_capture() {
    with_sidecar_runtime(&[], |runtime| {
        let inbound = listeners_for(
            runtime,
            MeshTrafficDirection::Inbound,
            MeshListenerKind::MtlsTermination,
        );
        let outbound = listeners_for(
            runtime,
            MeshTrafficDirection::Outbound,
            MeshListenerKind::PlaintextCapture,
        );

        assert_eq!(inbound.len(), 1, "{inbound:#?}");
        assert_eq!(outbound.len(), 1, "{outbound:#?}");
        assert_eq!(
            inbound[0].addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 15006)
        );
        assert_eq!(
            outbound[0].addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 15001)
        );
        assert!(
            !inbound[0].dual_stack && !outbound[0].dual_stack,
            "the IPv4-only default must not request a dual-stack bind"
        );
        runtime
            .validate_capture_listener_families()
            .expect("the shipped defaults must be a serviceable capture configuration");
    });
}

#[test]
fn sidecar_inbound_wildcard_becomes_one_dual_stack_listener_under_ipv6_capture() {
    with_sidecar_runtime(&[("FERRUM_MESH_CAPTURE_IPV6_ENABLED", "true")], |runtime| {
        let inbound = listeners_for(
            runtime,
            MeshTrafficDirection::Inbound,
            MeshListenerKind::MtlsTermination,
        );

        // Exactly ONE listener: a dual-stack `[::]` bind already owns the IPv4
        // wildcard on that port, so a sibling `0.0.0.0` listener would be
        // `EADDRINUSE`.
        assert_eq!(inbound.len(), 1, "{inbound:#?}");
        assert_eq!(
            inbound[0].addr,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 15006)
        );
        assert!(
            inbound[0].dual_stack,
            "the wildcard capture listener must disable IPV6_V6ONLY explicitly"
        );
    });
}

#[test]
fn sidecar_loopback_outbound_becomes_a_listener_per_family_under_ipv6_capture() {
    with_sidecar_runtime(&[("FERRUM_MESH_CAPTURE_IPV6_ENABLED", "true")], |runtime| {
        let outbound = listeners_for(
            runtime,
            MeshTrafficDirection::Outbound,
            MeshListenerKind::PlaintextCapture,
        );

        // TWO listeners, not one dual-stack socket: `REDIRECT` in `OUTPUT`
        // delivers to `127.0.0.1` for IPv4 and `::1` for IPv6, and a dual-stack
        // socket bound to `[::1]` does NOT receive IPv4 loopback traffic.
        let addrs: Vec<SocketAddr> = outbound.iter().map(|listener| listener.addr).collect();
        assert_eq!(addrs.len(), 2, "{outbound:#?}");
        assert!(addrs.contains(&SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 15001)));
        assert!(addrs.contains(&SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 15001)));
        assert!(
            outbound.iter().all(|listener| !listener.dual_stack),
            "a specific-address bind is never dual-stack: {outbound:#?}"
        );
    });
}

#[test]
fn sidecar_capture_ipv6_is_derived_from_the_same_gate_that_emits_ip6tables_rules() {
    // An IPv6 include CIDR is exactly what makes `IptablesPlan::for_config`
    // emit `ip6tables` REDIRECTs, so it must also plan an IPv6-capable listener.
    with_sidecar_runtime(
        &[("FERRUM_MESH_CAPTURE_INCLUDE_CIDRS", "0.0.0.0/0,fd00::/8")],
        |runtime| {
            let inbound = listeners_for(
                runtime,
                MeshTrafficDirection::Inbound,
                MeshListenerKind::MtlsTermination,
            );
            assert!(
                inbound.len() == 1 && inbound[0].addr.ip().is_ipv6() && inbound[0].dual_stack,
                "an IPv6 include CIDR must plan a dual-stack inbound listener: {inbound:#?}"
            );
        },
    );

    // `FERRUM_MESH_IP6TABLES_ENABLED=false` suppresses the IPv6 rule block, so
    // the listener plan must go back to IPv4-only rather than claiming a port
    // for a family nothing redirects.
    with_sidecar_runtime(
        &[
            ("FERRUM_MESH_CAPTURE_INCLUDE_CIDRS", "0.0.0.0/0,fd00::/8"),
            ("FERRUM_MESH_IP6TABLES_ENABLED", "false"),
        ],
        |runtime| {
            let inbound = listeners_for(
                runtime,
                MeshTrafficDirection::Inbound,
                MeshListenerKind::MtlsTermination,
            );
            assert!(
                inbound.len() == 1 && inbound[0].addr.ip().is_ipv4() && !inbound[0].dual_stack,
                "disabled ip6tables must plan the IPv4 listener alone: {inbound:#?}"
            );
        },
    );
}

#[test]
fn malformed_capture_include_cidr_fails_listener_family_validation() {
    with_sidecar_runtime(
        &[("FERRUM_MESH_CAPTURE_INCLUDE_CIDRS", "not-a-cidr")],
        |runtime| {
            let err = runtime
                .validate_capture_listener_families()
                .expect_err("malformed include CIDR must fail closed at startup");
            assert!(
                err.contains("FERRUM_MESH_CAPTURE_INCLUDE_CIDRS"),
                "the startup error must name the offending variable: {err}"
            );
        },
    );
}

#[test]
fn malformed_capture_exclude_cidr_fails_listener_family_validation() {
    with_sidecar_runtime(
        &[("FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS", "10.0.0.0/64")],
        |runtime| {
            let err = runtime
                .validate_capture_listener_families()
                .expect_err("malformed exclude CIDR must fail closed at startup");
            assert!(
                err.contains("FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS"),
                "the startup error must name the offending variable: {err}"
            );
        },
    );
}

#[test]
fn capture_ipv6_env_errors_withhold_values_and_preserve_fields_and_recovery() {
    use ferrum_edge::capture::capture_ipv6_enabled_from_env;
    use ferrum_edge::startup::sanitize_startup_cause;

    for (key, raw, expected) in [
        (
            "FERRUM_MESH_CAPTURE_IPV6_ENABLED",
            "'capture-secret`5589`\"\nvisible-tail",
            "Invalid FERRUM_MESH_CAPTURE_IPV6_ENABLED <redacted scalar>. Expected true, false, 1, or 0",
        ),
        (
            "FERRUM_MESH_IP6TABLES_ENABLED",
            "'capture-secret`5589`\"\nvisible-tail",
            "Invalid FERRUM_MESH_IP6TABLES_ENABLED <redacted scalar>. Expected: auto, true, or false",
        ),
        (
            "FERRUM_MESH_CAPTURE_INCLUDE_CIDRS",
            "'capture-secret`5589`\"\nvisible-tail",
            "FERRUM_MESH_CAPTURE_INCLUDE_CIDRS: CIDR <redacted scalar> must include a prefix length",
        ),
        (
            "FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS",
            "'capture-secret`5589`\"\nvisible-tail/8",
            "FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS: CIDR <redacted scalar> has invalid IP address",
        ),
        (
            "FERRUM_MESH_CAPTURE_INCLUDE_CIDRS",
            "fd00::/'capture-secret`5589`\"\nvisible-tail",
            "FERRUM_MESH_CAPTURE_INCLUDE_CIDRS: CIDR <redacted scalar> has invalid prefix length",
        ),
        (
            "FERRUM_MESH_CAPTURE_INCLUDE_CIDRS",
            "10.0.0.0/33",
            "FERRUM_MESH_CAPTURE_INCLUDE_CIDRS: CIDR <redacted scalar> prefix length <redacted scalar> exceeds max 32",
        ),
        (
            "FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS",
            "fd00::/129",
            "FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS: CIDR <redacted scalar> prefix length <redacted scalar> exceeds max 128",
        ),
    ] {
        let guard = EnvGuard::new(MESH_ENV_KEYS);
        guard.set("FERRUM_MESH_CAPTURE_IPV6_ENABLED", "");
        guard.set("FERRUM_MESH_IP6TABLES_ENABLED", "auto");
        guard.set("FERRUM_MESH_CAPTURE_INCLUDE_CIDRS", "");
        guard.set("FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS", "");
        guard.set(key, raw);
        let error = capture_ipv6_enabled_from_env().unwrap_err();
        assert_eq!(sanitize_startup_cause(error, &[]), expected);
    }

    let guard = EnvGuard::new(MESH_ENV_KEYS);
    guard.set("FERRUM_MESH_CAPTURE_IPV6_ENABLED", "false");
    guard.set("FERRUM_MESH_IP6TABLES_ENABLED", "auto");
    guard.set("FERRUM_MESH_CAPTURE_INCLUDE_CIDRS", "fd00::/8");
    guard.set("FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS", "");
    let error = capture_ipv6_enabled_from_env().unwrap_err();
    let rendered = sanitize_startup_cause(&error, &[]);
    assert_eq!(rendered, error);
    assert!(rendered.contains("FERRUM_MESH_CAPTURE_IPV6_ENABLED=false contradicts"));
    assert!(rendered.contains("FERRUM_MESH_IP6TABLES_ENABLED=false (or remove the IPv6 CIDRs)"));
    assert!(rendered.contains("leaving ip6tables REDIRECTs without a listener"));

    // Recovery and explicit/derived precedence must retain the same decisions.
    guard.set("FERRUM_MESH_IP6TABLES_ENABLED", "disabled");
    assert!(!capture_ipv6_enabled_from_env().unwrap());
    guard.set("FERRUM_MESH_CAPTURE_IPV6_ENABLED", "");
    guard.set("FERRUM_MESH_IP6TABLES_ENABLED", "auto");
    assert!(capture_ipv6_enabled_from_env().unwrap());
    guard.set("FERRUM_MESH_CAPTURE_INCLUDE_CIDRS", "0.0.0.0/0");
    assert!(!capture_ipv6_enabled_from_env().unwrap());
    guard.set("FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS", "fd00::/8");
    assert!(capture_ipv6_enabled_from_env().unwrap());
    guard.set("FERRUM_MESH_CAPTURE_IPV6_ENABLED", "TRUE");
    guard.set("FERRUM_MESH_IP6TABLES_ENABLED", "invalid-but-bypassed");
    assert!(capture_ipv6_enabled_from_env().unwrap());
}

#[test]
fn explicit_false_cannot_contradict_locally_configured_ipv6_rules() {
    let guard = EnvGuard::new(MESH_ENV_KEYS);
    for &key in MESH_ENV_KEYS {
        guard.unset(key);
    }
    guard.set("FERRUM_MODE", "mesh");
    guard.set("FERRUM_DP_CP_GRPC_URLS", "http://cp:50051");
    guard.set(
        "FERRUM_CP_DP_GRPC_JWT_SECRET",
        "secret-padding-for-32-char-min!!",
    );
    guard.set("FERRUM_MESH_ALLOW_NO_CA", "true");
    guard.set("FERRUM_MESH_CAPTURE_IPV6_ENABLED", "false");
    guard.set("FERRUM_MESH_CAPTURE_INCLUDE_CIDRS", "0.0.0.0/0,fd00::/8");

    let env = EnvConfig::from_env().expect("mesh env config");
    let runtime = MeshRuntimeConfig::from_env_config(&env).expect("mesh runtime config");
    let err = runtime
        .validate_capture_listener_families()
        .expect_err("a listener-only false override must not leave IPv6 REDIRECT rules live");
    assert!(
        err.contains("FERRUM_MESH_CAPTURE_IPV6_ENABLED=false"),
        "{err}"
    );
    assert!(err.contains("FERRUM_MESH_IP6TABLES_ENABLED=false"), "{err}");
}

#[test]
fn a_specific_capture_address_under_ipv6_capture_is_a_startup_error() {
    with_sidecar_runtime(
        &[
            ("FERRUM_MESH_CAPTURE_IPV6_ENABLED", "true"),
            ("FERRUM_MESH_OUTBOUND_LISTEN_ADDR", "10.0.0.5:15001"),
        ],
        |runtime| {
            let err = runtime
                .validate_capture_listener_families()
                .expect_err("a specific IPv4 literal cannot serve the ip6tables REDIRECTs");
            assert!(
                err.contains("FERRUM_MESH_OUTBOUND_LISTEN_ADDR"),
                "the startup error must name the offending variable: {err}"
            );

            // `listener_plan()` stays infallible for read-only callers: it warns
            // and keeps the configured address alone. The serving path refuses
            // to start, which is what makes that fallback safe.
            let outbound = listeners_for(
                runtime,
                MeshTrafficDirection::Outbound,
                MeshListenerKind::PlaintextCapture,
            );
            assert_eq!(outbound.len(), 1, "{outbound:#?}");
            assert_eq!(
                outbound[0].addr,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 15001)
            );
        },
    );
}

#[test]
fn an_ephemeral_capture_port_keeps_the_configured_address_alone() {
    // Port 0 is the in-process test / disabled-listener form. Two ephemeral
    // binds would land on two unrelated ports, which no redirect rule can name.
    with_sidecar_runtime(
        &[
            ("FERRUM_MESH_CAPTURE_IPV6_ENABLED", "true"),
            ("FERRUM_MESH_OUTBOUND_LISTEN_ADDR", "127.0.0.1:0"),
        ],
        |runtime| {
            let outbound = listeners_for(
                runtime,
                MeshTrafficDirection::Outbound,
                MeshListenerKind::PlaintextCapture,
            );
            assert_eq!(outbound.len(), 1, "{outbound:#?}");
            assert_eq!(outbound[0].addr.port(), 0);
            runtime
                .validate_capture_listener_families()
                .expect("an ephemeral capture port is not a misconfiguration");
        },
    );
}

#[test]
fn a_v4_mapped_local_address_selects_the_ipv4_conntrack_lookup() {
    // What a dual-stack listener reports for an accepted IPv4 connection.
    let mapped = SocketAddr::new(
        IpAddr::V6(Ipv4Addr::new(10, 4, 2, 1).to_ipv6_mapped()),
        15006,
    );
    assert_eq!(
        original_dst_lookup_addr(mapped),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 4, 2, 1)), 15006),
        "an IPv4-mapped local address describes an IPv4 flow and must use \
         SOL_IP/SO_ORIGINAL_DST"
    );
}

#[test]
fn native_addresses_keep_their_own_conntrack_lookup_family() {
    let native_v6 = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 7)),
        15006,
    );
    assert_eq!(
        original_dst_lookup_addr(native_v6),
        native_v6,
        "native IPv6 must keep IP6T_SO_ORIGINAL_DST"
    );

    let native_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 4, 2, 1)), 15001);
    assert_eq!(original_dst_lookup_addr(native_v4), native_v4);
}

#[test]
fn only_genuine_ipv6_unavailability_permits_the_v4_wildcard_downgrade() {
    assert!(is_ipv6_unavailable_io_error(&std::io::Error::from(
        std::io::ErrorKind::AddrNotAvailable
    )));
    // A real conflict must NOT downgrade: doing so would report the listener
    // started on IPv4 while `ip6tables` still redirects IPv6 at that port.
    assert!(!is_ipv6_unavailable_io_error(&std::io::Error::from(
        std::io::ErrorKind::AddrInUse
    )));
    assert!(!is_ipv6_unavailable_io_error(&std::io::Error::from(
        std::io::ErrorKind::PermissionDenied
    )));
}

fn iptables_config() -> CaptureConfig {
    let mut config = CaptureConfig::explicit(15006, 15001);
    config.mode = CaptureMode::Iptables;
    config.ip6tables_mode = Ip6TablesMode::Auto;
    // Activate the IPv6 rule block so both families are asserted.
    config.include_cidrs = vec!["0.0.0.0/0".to_string(), "::/0".to_string()];
    config
}

fn assert_local_return_precedes_every_redirect(commands: &[String], family: &str) {
    let redirects: Vec<usize> = commands
        .iter()
        .enumerate()
        .filter(|(_, cmd)| cmd.contains("FERRUM_MESH_OUTBOUND") && cmd.contains("-j REDIRECT"))
        .map(|(index, _)| index)
        .collect();
    assert!(
        !redirects.is_empty(),
        "{family}: expected outbound REDIRECT rules to guard: {commands:#?}"
    );
    let local_return = commands
        .iter()
        .position(|cmd| {
            cmd.contains("FERRUM_MESH_OUTBOUND")
                && cmd.contains("-m addrtype --dst-type LOCAL -j RETURN")
        })
        .unwrap_or_else(|| {
            panic!("{family}: no loopback/self RETURN in FERRUM_MESH_OUTBOUND: {commands:#?}")
        });
    assert!(
        commands[local_return].contains("-D FERRUM_MESH_OUTBOUND")
            && commands[local_return].contains("-I FERRUM_MESH_OUTBOUND 1"),
        "{family}: the safety rule must be repositioned at chain head during a reconcile, not \
         merely appended on fresh creation: {commands:#?}"
    );
    assert!(
        redirects.iter().all(|index| local_return < *index),
        "{family}: the loopback/self RETURN must precede every outbound REDIRECT — \
         once REDIRECT fires the chain returns: {commands:#?}"
    );
}

#[test]
fn tcp_outbound_chain_returns_local_destinations_before_every_redirect() {
    let plan = IptablesPlan::for_config(&iptables_config()).unwrap();
    assert_local_return_precedes_every_redirect(&plan.v4_commands, "iptables");
    assert_local_return_precedes_every_redirect(&plan.v6_commands, "ip6tables");
}

#[test]
fn tcp_outbound_local_return_survives_operator_excludes_and_port_includes() {
    let mut config = iptables_config();
    config.exclude_cidrs = vec!["10.0.0.0/8".to_string()];
    config.exclude_ports = vec![5432];
    config.include_outbound_ports = vec![8080];
    config.include_cidrs_explicit = true;

    let plan = IptablesPlan::for_config(&config).unwrap();
    assert_local_return_precedes_every_redirect(&plan.v4_commands, "iptables");
    assert_local_return_precedes_every_redirect(&plan.v6_commands, "ip6tables");
}

#[test]
fn host_netns_tcp_outbound_chain_omits_the_local_return() {
    // In the HOST namespace pod IPs are FORWARDED rather than `LOCAL`, so the
    // discriminator does not describe "this workload's own address" there —
    // the same reason the UDP sibling suppresses its direction split.
    let mut config = iptables_config();
    config.host_netns = true;

    let plan = IptablesPlan::for_config(&config).unwrap();
    assert!(
        !plan
            .v4_commands
            .iter()
            .chain(plan.v6_commands.iter())
            .any(|cmd| cmd.contains("--dst-type LOCAL -j RETURN")),
        "host-netns rendering must not emit the pod-netns LOCAL RETURN: {plan:#?}"
    );
}
