//! Unit coverage for CP gRPC pre-authentication connection admission
//! (private advisory GHSA-2xqr-7j7p-77qp).
//!
//! Two halves:
//!
//! * `EnvConfig::validate_cp_grpc_connection_limits` — safe defaults, the
//!   fail-closed bound checks, and CP-mode scoping.
//! * `ConnLimiter` behaviour that the CP listener depends on and that the
//!   admin-surface tests do not cover: bounded per-IP map cardinality under a
//!   hostile source-address sweep, and per-IP/global interaction.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::util::conn_limit::{ConnLimiter, ConnRejectReason, MAX_CONN_LIMIT};

fn cp_config(max_connections: usize, max_connections_per_ip: usize) -> EnvConfig {
    EnvConfig {
        mode: OperatingMode::ControlPlane,
        cp_grpc_max_connections: max_connections,
        cp_grpc_max_connections_per_ip: max_connections_per_ip,
        ..EnvConfig::default()
    }
}

fn ipv4(n: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(n))
}

#[test]
fn defaults_are_bounded_and_consistent() {
    let defaults = EnvConfig::default();
    assert_eq!(
        defaults.cp_grpc_max_connections, 1024,
        "the CP gRPC listener must ship with a finite default cap"
    );
    assert_eq!(defaults.cp_grpc_max_connections_per_ip, 64);
    assert!(
        defaults.cp_grpc_max_connections_per_ip < defaults.cp_grpc_max_connections,
        "the default per-IP share must be reachable within the default global cap"
    );

    // The shipped defaults validate in CP mode.
    let cp = EnvConfig {
        mode: OperatingMode::ControlPlane,
        ..defaults
    };
    cp.validate_cp_grpc_connection_limits()
        .expect("default CP limits are valid");
}

#[test]
fn per_ip_cap_above_global_cap_is_refused() {
    let error = cp_config(64, 128)
        .validate_cp_grpc_connection_limits()
        .expect_err("an unreachable per-IP cap is a misconfiguration");
    assert!(
        error.contains("FERRUM_CP_GRPC_MAX_CONNECTIONS_PER_IP"),
        "error should name the offending variable: {error}"
    );
}

#[test]
fn per_ip_cap_equal_to_global_cap_is_allowed() {
    cp_config(64, 64)
        .validate_cp_grpc_connection_limits()
        .expect("an exactly-reachable per-IP cap is valid");
}

#[test]
fn disabled_caps_validate() {
    // 0 = unlimited on both knobs is a deliberate operator opt-out, and a
    // per-IP cap alongside an unlimited global cap is a legitimate posture.
    cp_config(0, 0)
        .validate_cp_grpc_connection_limits()
        .expect("both disabled");
    cp_config(0, 32)
        .validate_cp_grpc_connection_limits()
        .expect("per-IP only");
    cp_config(32, 0)
        .validate_cp_grpc_connection_limits()
        .expect("global only");
}

#[test]
fn out_of_range_caps_are_refused_rather_than_silently_clamped() {
    let error = cp_config(MAX_CONN_LIMIT + 1, 0)
        .validate_cp_grpc_connection_limits()
        .expect_err("global cap beyond the semaphore ceiling");
    assert!(error.contains("FERRUM_CP_GRPC_MAX_CONNECTIONS"), "{error}");

    let error = cp_config(0, MAX_CONN_LIMIT + 1)
        .validate_cp_grpc_connection_limits()
        .expect_err("per-IP cap beyond the semaphore ceiling");
    assert!(
        error.contains("FERRUM_CP_GRPC_MAX_CONNECTIONS_PER_IP"),
        "{error}"
    );
}

#[test]
fn non_cp_modes_are_not_gated() {
    // Only CP mode builds the limiter; a stray variable elsewhere must not
    // fail an unrelated gateway's startup.
    let database = EnvConfig {
        mode: OperatingMode::Database,
        ..cp_config(64, 128)
    };
    database
        .validate_cp_grpc_connection_limits()
        .expect("database mode is unaffected");
}

#[test]
fn hostile_source_cardinality_stays_bounded_by_the_global_cap() {
    // A client cycling source addresses must not grow the per-IP map: entries
    // exist only while a permit is live and are evicted at zero.
    let limiter = Arc::new(ConnLimiter::new(8, 2));

    let mut held = Vec::new();
    let mut rejected = 0u32;
    for n in 0..4096u32 {
        match limiter.try_acquire(ipv4(0x0a00_0000 + n)) {
            Ok(permit) => held.push(permit),
            Err(reason) => {
                assert_eq!(reason, ConnRejectReason::MaxConnections);
                rejected += 1;
            }
        }
    }

    assert_eq!(held.len(), 8, "global cap admits exactly 8");
    assert_eq!(rejected, 4096 - 8);
    assert!(
        limiter.tracked_source_ips() <= 8,
        "per-IP map must never exceed the global cap, saw {}",
        limiter.tracked_source_ips()
    );
    assert_eq!(limiter.snapshot().active_connections, 8);

    held.clear();
    assert_eq!(limiter.snapshot().active_connections, 0);
    assert_eq!(
        limiter.tracked_source_ips(),
        0,
        "every per-IP entry is evicted once its permits release"
    );
}

#[test]
fn one_source_cannot_consume_the_global_budget() {
    // The advisory's core per-IP requirement: a single host is capped well
    // below the global pool, leaving room for legitimate peers.
    let limiter = Arc::new(ConnLimiter::new(16, 4));

    let mut attacker = Vec::new();
    for _ in 0..4 {
        attacker.push(
            limiter
                .try_acquire(ipv4(0xc000_0201))
                .expect("attacker within its share"),
        );
    }
    let reason = limiter
        .try_acquire(ipv4(0xc000_0201))
        .expect_err("attacker beyond its per-IP share");
    assert_eq!(reason, ConnRejectReason::MaxConnectionsPerIp);

    // 12 global slots remain for everyone else.
    let mut others = Vec::new();
    for n in 0..12u32 {
        others.push(
            limiter
                .try_acquire(ipv4(0x0a00_0100 + n))
                .expect("legitimate peer admitted"),
        );
    }
    assert_eq!(limiter.snapshot().active_connections, 16);

    let snapshot = limiter.snapshot();
    assert_eq!(snapshot.rejected_max_connections_per_ip, 1);
    assert_eq!(snapshot.rejected_total(), 1);

    // Releasing one attacker slot lets a legitimate peer in immediately.
    attacker.pop();
    limiter
        .try_acquire(ipv4(0x0a00_0200))
        .expect("permit released by drop is reusable");
}

#[test]
fn ipv4_and_ipv6_sources_are_accounted_separately() {
    let limiter = Arc::new(ConnLimiter::new(0, 1));
    let _v4 = limiter
        .try_acquire(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .expect("v4 admitted");
    let _v6 = limiter
        .try_acquire(IpAddr::V6(Ipv6Addr::LOCALHOST))
        .expect("v6 is a distinct source");
    assert!(
        limiter
            .try_acquire(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .is_err(),
        "v4 source is at its per-IP cap"
    );
    assert_eq!(limiter.tracked_source_ips(), 2);
}

#[test]
fn ipv6_per_ip_cap_groups_the_default_prefix_and_folds_mapped_ipv4() {
    let limiter = Arc::new(ConnLimiter::new(0, 1));
    let _first = limiter
        .try_acquire("2001:db8:abcd:12::1".parse().expect("IPv6 address"))
        .expect("first IPv6 address admitted");
    assert_eq!(
        limiter
            .try_acquire("2001:db8:abcd:12::ffff".parse().expect("IPv6 address"))
            .expect_err("same /64 shares the source cap"),
        ConnRejectReason::MaxConnectionsPerIp
    );

    let mapped = Arc::new(ConnLimiter::new(0, 1));
    let _v4 = mapped
        .try_acquire(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        .expect("IPv4 admitted");
    assert_eq!(
        mapped
            .try_acquire("::ffff:192.0.2.1".parse().expect("mapped IPv4"))
            .expect_err("mapped IPv4 shares the native IPv4 quota"),
        ConnRejectReason::MaxConnectionsPerIp
    );
}

#[test]
fn ipv6_per_ip_cap_can_use_host_prefix_accounting() {
    let limiter = Arc::new(ConnLimiter::new_with_ipv6_prefix(0, 1, 128));
    let _first = limiter
        .try_acquire("2001:db8:abcd:12::1".parse().expect("IPv6 address"))
        .expect("first IPv6 host admitted");
    let _second = limiter
        .try_acquire("2001:db8:abcd:12::ffff".parse().expect("IPv6 address"))
        .expect("a distinct IPv6 host has a separate cap");
}
// ============================================================================
// RFC 9298 CONNECT-UDP session admission shares the same ceiling contract
// ============================================================================

fn connect_udp_config(max_sessions: usize) -> EnvConfig {
    EnvConfig {
        http3_connect_udp_max_sessions: max_sessions,
        ..EnvConfig::default()
    }
}

#[test]
fn connect_udp_session_defaults_are_bounded_and_rfc_aligned() {
    let defaults = EnvConfig::default();
    assert_eq!(defaults.http3_connect_udp_max_sessions, 256);
    assert_eq!(
        defaults.http3_connect_udp_idle_timeout_seconds, 120,
        "RFC 9298 §3.2: a UDP proxy SHOULD NOT use an idle timeout below two minutes"
    );
    defaults
        .validate_h3_connect_udp_limits()
        .expect("the shipped default must validate");
}

#[test]
fn connect_udp_session_cap_at_the_ceiling_is_accepted() {
    connect_udp_config(MAX_CONN_LIMIT)
        .validate_h3_connect_udp_limits()
        .expect("exactly the semaphore ceiling is enforceable");
    // The value the accepted boundary is handed to must itself be constructible.
    let _ = tokio::sync::Semaphore::new(MAX_CONN_LIMIT);
}

#[test]
fn connect_udp_session_cap_above_the_ceiling_is_refused_not_clamped_or_unlimited() {
    let error = connect_udp_config(MAX_CONN_LIMIT + 1)
        .validate_h3_connect_udp_limits()
        .expect_err("a cap `Semaphore::new` would panic on must be refused");
    assert!(
        error.contains("FERRUM_HTTP3_CONNECT_UDP_MAX_SESSIONS"),
        "the error must name the offending variable: {error}"
    );
    assert!(
        error.contains("0 to disable"),
        "the error must point at the explicit unlimited opt-out: {error}"
    );

    let error = connect_udp_config(usize::MAX)
        .validate_h3_connect_udp_limits()
        .expect_err("usize::MAX is the obvious operator typo");
    assert!(
        error.contains("FERRUM_HTTP3_CONNECT_UDP_MAX_SESSIONS"),
        "{error}"
    );
}

#[test]
fn connect_udp_session_cap_of_zero_is_the_explicit_unlimited_opt_out() {
    connect_udp_config(0)
        .validate_h3_connect_udp_limits()
        .expect("0 disables the limit deliberately");
}

// ============================================================================
// The advertised CONNECT-UDP idle posture must be the one that actually holds
//
// A CONNECT-UDP tunnel lives on a stream of ONE QUIC connection, and a tunnel
// carrying no datagram generates no QUIC activity either. With the shipped
// defaults the connection idle limit (30s) was well below the tunnel idle
// bound (120s), so the gateway advertised a two-minute RFC 9298 §3.2 posture
// while a different gateway-owned timer closed the connection at thirty
// seconds. The frontend transport idle timeout is therefore derived, not read
// raw — it may only ever be RAISED to the tunnel bound.
// ============================================================================

fn connect_udp_idle_config(
    enabled: bool,
    quic_idle_seconds: u64,
    tunnel_idle_seconds: u64,
) -> EnvConfig {
    EnvConfig {
        http3_connect_udp_enabled: enabled,
        http3_idle_timeout: quic_idle_seconds,
        http3_connect_udp_idle_timeout_seconds: tunnel_idle_seconds,
        ..EnvConfig::default()
    }
}

#[test]
fn the_shipped_default_profile_cannot_be_closed_early_by_the_quic_idle_timer() {
    let defaults = EnvConfig::default();
    assert_eq!(defaults.http3_idle_timeout, 30);
    assert_eq!(defaults.http3_connect_udp_idle_timeout_seconds, 120);
    // Disabled: nothing is derived, the operator's QUIC idle timeout stands.
    assert_eq!(
        defaults.effective_http3_idle_timeout_seconds(),
        30,
        "with CONNECT-UDP off the QUIC idle timeout is untouched"
    );

    // Enabled with the shipped defaults: the connection must outlive the tunnel
    // bound it advertises.
    let enabled = connect_udp_idle_config(true, 30, 120);
    assert_eq!(
        enabled.effective_http3_idle_timeout_seconds(),
        120,
        "an idle tunnel must not be closed at 30s while 120s is advertised"
    );
    assert!(
        enabled.effective_http3_idle_timeout_seconds()
            >= enabled.http3_connect_udp_idle_timeout_seconds,
        "the QUIC idle limit may never undercut the configured tunnel idle limit"
    );
}

#[test]
fn a_larger_operator_quic_idle_timeout_is_never_lowered_to_the_tunnel_bound() {
    // The derivation only raises. An operator who wants long-lived QUIC
    // connections keeps them.
    let config = connect_udp_idle_config(true, 900, 120);
    assert_eq!(config.effective_http3_idle_timeout_seconds(), 900);

    // And a tunnel bound below the QUIC one needs no adjustment at all.
    let config = connect_udp_idle_config(true, 300, 60);
    assert_eq!(config.effective_http3_idle_timeout_seconds(), 300);
}

#[test]
fn a_zero_quic_idle_timeout_keeps_meaning_disabled_rather_than_being_raised() {
    // RFC 9000 §10.1: `max_idle_timeout = 0` DISABLES the idle timer. Raising
    // it to the tunnel bound would SHORTEN the connection lifetime — the exact
    // failure this derivation exists to prevent, in reverse.
    let config = connect_udp_idle_config(true, 0, 120);
    assert_eq!(
        config.effective_http3_idle_timeout_seconds(),
        0,
        "0 disables the QUIC idle timer and already cannot undercut the tunnel"
    );
}

#[test]
fn the_frontend_transport_installs_the_derived_idle_timeout_and_backends_do_not() {
    use std::time::Duration;

    use ferrum_edge::http3::config::Http3ServerConfig;

    let config = Http3ServerConfig::from_env_config(&connect_udp_idle_config(true, 30, 120));
    assert_eq!(
        config.frontend_idle_timeout,
        Duration::from_secs(120),
        "the QUIC listener installs the raised value"
    );
    assert_eq!(
        config.idle_timeout,
        Duration::from_secs(30),
        "the configured value is preserved for the H3 BACKEND pools, which carry no tunnels"
    );
    assert!(
        config.connect_udp_raised_frontend_idle_timeout(),
        "the raise must be observable so the listener can log it instead of overriding silently"
    );

    // With the profile off the two are identical and nothing is logged.
    let config = Http3ServerConfig::from_env_config(&connect_udp_idle_config(false, 30, 120));
    assert_eq!(config.frontend_idle_timeout, config.idle_timeout);
    assert!(!config.connect_udp_raised_frontend_idle_timeout());
    assert!(!Http3ServerConfig::default().connect_udp_raised_frontend_idle_timeout());
}

// ============================================================================
// RFC 9298 §3.1 non-fragmentation is a MUST, so it is a startup precondition
// ============================================================================

#[test]
fn connect_udp_is_refused_at_startup_where_non_fragmentation_cannot_be_enforced() {
    let enabled = EnvConfig {
        http3_connect_udp_enabled: true,
        ..EnvConfig::default()
    };
    let result = enabled.validate_h3_connect_udp_limits();
    if ferrum_edge::http3::connect_udp::CONNECT_UDP_NON_FRAGMENTATION_ENFORCEABLE {
        result.expect("a target with a do-not-fragment option may serve the profile");
    } else {
        let error = result.expect_err(
            "RFC 9298 §3.1 is a MUST: a target that cannot set DF must refuse the profile, \
             not serve it best effort",
        );
        assert!(
            error.contains("FERRUM_HTTP3_CONNECT_UDP_ENABLED"),
            "the error must name the offending variable: {error}"
        );
    }
    // Leaving it off is always valid, on every target.
    EnvConfig::default()
        .validate_h3_connect_udp_limits()
        .expect("the profile is off by default and must validate everywhere");
}
