//! Static contract: the lifecycle rules for bespoke gateway spawners that
//! `.claude/rules/testing.md` sets and `TestGateway` already follows
//! (issue #7077).
//!
//! - Every spawned gateway is owned by `GatewayChildGuard` from the instant of
//!   spawn (issue #4991): no owned `std::process::Child` is held anywhere, so a
//!   panic between spawn and teardown cannot leak a live gateway that keeps its
//!   ports for the rest of the shard.
//! - Teardown goes through the guard (`shutdown_gateway_child`), never a raw
//!   `kill()`: under the coverage shards a SIGKILLed gateway writes no LLVM
//!   profile. `configure_coverage_gateway_command` (or the spawner's own
//!   `FERRUM_SHUTDOWN_DRAIN_SECONDS`) keeps the drain inside that grace period.
//! - The child gets a private `FERRUM_TLS_MANAGED_STORE_PATH`, so a managed TLS,
//!   ACME, lease or TLS event store never lands in the checkout (issue #5706).
//! - Handoff ports come from the port registry (`unbound_port`), not from
//!   binding `127.0.0.1:0` and dropping the listener, which leaves the port in
//!   the ephemeral source range for any outgoing connection to take.
//!
//! Each row pins the exceptions a file legitimately keeps (a non-gateway child
//! such as a netns holder or a `docker` CLI, a deliberately refused port) with
//! the reason, so a new bare child, raw kill or released ephemeral port in one
//! of these files fails here. `include_str!` only: no runtime, no gateway.

/// How a file starts its gateways.
enum Spawner {
    /// The file spawns gateways itself with this many
    /// `GatewayChildGuard::new(...)` wraps.
    Own { guarded_spawns: usize },
    /// The file only uses another file's spawner; that file's row covers
    /// the guard, coverage and managed-store rules.
    Delegated { to: &'static str },
}

struct Site {
    file: &'static str,
    src: &'static str,
    spawner: Spawner,
    /// Raw `.kill()` calls on children that are NOT gateways, with why.
    non_gateway_kills: (usize, &'static str),
    /// Owned `Child` values that are NOT gateways, with why.
    non_gateway_children: (usize, &'static str),
    /// `bind_test("127.0.0.1:0")` listeners dropped to release their port,
    /// that are deliberately not gateway handoffs, with why.
    released_ephemeral_ports: (usize, &'static str),
}

const NONE: (usize, &str) = (0, "");

macro_rules! site {
    ($file:literal, $spawner:expr) => {
        site!($file, $spawner, NONE, NONE, NONE)
    };
    ($file:literal, $spawner:expr, $kills:expr, $children:expr, $released:expr) => {
        Site {
            file: $file,
            src: include_str!(concat!("../../", $file)),
            spawner: $spawner,
            non_gateway_kills: $kills,
            non_gateway_children: $children,
            released_ephemeral_ports: $released,
        }
    };
}

const fn own(guarded_spawns: usize) -> Spawner {
    Spawner::Own { guarded_spawns }
}

const SITES: &[Site] = &[
    site!(
        "functional/functional_a2a_gateway_grpc_card_test.rs",
        own(1)
    ),
    site!("functional/functional_ai_plugins_test.rs", own(1)),
    site!(
        "functional/functional_ai_response_guard_grpc_test.rs",
        own(1)
    ),
    site!("functional/functional_ai_stream_router_test.rs", own(1)),
    site!("functional/functional_db_failover_test.rs", own(7)),
    site!("functional/functional_grpc_plugins_test.rs", own(1)),
    site!("functional/functional_grpc_test.rs", own(1)),
    site!("functional/functional_injector_serving_test.rs", own(1)),
    site!(
        "functional/functional_load_stress_test.rs",
        own(1),
        (1, "the `docker inspect` helper child, not a gateway"),
        NONE,
        NONE
    ),
    site!(
        "functional/functional_mesh_mode_test.rs",
        own(3),
        (7, "the `unshare --net` netns holder process, not a gateway"),
        (
            1,
            "`LivePodNetns` owns the netns holder process, not a gateway"
        ),
        NONE
    ),
    site!(
        "functional/functional_mesh_stock_xds_test.rs",
        Spawner::Delegated {
            to: "functional/functional_mesh_mode_test.rs"
        }
    ),
    site!("functional/functional_mongodb_test.rs", own(3)),
    site!("functional/functional_node_agent_test.rs", own(1)),
    site!(
        "functional/functional_otel_ldap_test.rs",
        own(1),
        NONE,
        NONE,
        (1, "an unlistened LDAP target the plugin must fail to reach")
    ),
    site!("functional/functional_overload_test.rs", own(1)),
    site!(
        "functional/functional_passthrough_test.rs",
        own(1),
        NONE,
        NONE,
        (
            1,
            "the circuit-breaker backend: the first dial must be refused, and \
             the test detects interference in the release window"
        )
    ),
    site!("functional/functional_regex_routing_test.rs", own(1)),
    site!("functional/functional_router_cache_test.rs", own(1)),
    site!("functional/functional_scale_perf_test.rs", own(1)),
    site!("functional/functional_serverless_mirror_test.rs", own(1)),
    site!("functional/functional_service_discovery_test.rs", own(1)),
    site!("functional/functional_sse_test.rs", own(1)),
    site!(
        "functional/functional_stream_listener_failure_test.rs",
        own(4)
    ),
    site!("functional/functional_tcp_proxy_test.rs", own(1)),
    site!("functional/functional_tls_only_test.rs", own(2)),
    site!("functional/functional_websocket_limits_test.rs", own(1)),
    site!("functional/functional_websocket_test.rs", own(1)),
    site!("functional/scripted_backend_udp_tests.rs", own(1)),
    site!("secrets_functional/startup_smoke.rs", own(1)),
];

/// The source with `use` declarations and `//` comments removed (a `//`
/// inside a string literal, such as a URL, is kept).
fn code(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut in_use = false;
    for line in src.lines() {
        let trimmed = line.trim_start();
        if in_use {
            in_use = !trimmed.contains(';');
            continue;
        }
        if trimmed.starts_with("use ")
            || trimmed.starts_with("pub use ")
            || trimmed.starts_with("pub(crate) use ")
        {
            in_use = !trimmed.contains(';');
            continue;
        }
        let mut kept = line;
        let mut from = 0;
        while let Some(offset) = line[from..].find("//") {
            let at = from + offset;
            if line[..at].matches('"').count() % 2 == 0 {
                kept = &line[..at];
                break;
            }
            from = at + 2;
        }
        out.push_str(kept);
        out.push('\n');
    }
    out
}

fn squeezed(src: &str) -> String {
    src.chars().filter(|c| !c.is_whitespace()).collect()
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Occurrences of `Child` used as an owned value type: not a borrow
/// (`&mut Child`, `&Child`), not a path (`Child::id`), not part of a longer
/// identifier (`GatewayChildGuard`, `ChildStderr`).
fn owned_child_types(compact: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (at, _) in compact.match_indices("Child") {
        let end = at + "Child".len();
        if compact[..at].chars().next_back().is_some_and(is_ident)
            || compact[end..].chars().next().is_some_and(is_ident)
            || compact[end..].starts_with("::")
        {
            continue;
        }
        let mut before = &compact[..at];
        for path in ["std::process::", "tokio::process::"] {
            before = before.strip_suffix(path).unwrap_or(before);
        }
        if before.ends_with("&mut") || before.ends_with('&') {
            continue;
        }
        let context_start = compact[..at]
            .char_indices()
            .rev()
            .nth(40)
            .map_or(0, |(index, _)| index);
        found.push(compact[context_start..end].to_string());
    }
    found
}

/// `let <name> = ...bind_test("127.0.0.1:0")` followed within a few lines by
/// `drop(<name>)`: a kernel-ephemeral port released to someone else.
fn released_ephemeral_ports(src: &str) -> usize {
    let lines: Vec<&str> = src.lines().collect();
    let mut released = 0;
    for (index, line) in lines.iter().enumerate() {
        if !line.contains("bind_test(\"127.0.0.1:0\")") {
            continue;
        }
        let Some(rest) = line.trim_start().strip_prefix("let ") else {
            continue;
        };
        let rest = rest.strip_prefix("mut ").unwrap_or(rest);
        let name: String = rest.chars().take_while(|c| is_ident(*c)).collect();
        if name.is_empty() {
            continue;
        }
        let dropped = format!("drop({name})");
        if lines
            .iter()
            .skip(index + 1)
            .take(7)
            .any(|later| squeezed(later).contains(&dropped))
        {
            released += 1;
        }
    }
    released
}

#[test]
fn bespoke_spawners_hold_no_bare_gateway_child() {
    for site in SITES {
        let owned = owned_child_types(&squeezed(&code(site.src)));
        let (allowed, reason) = site.non_gateway_children;
        assert_eq!(
            owned.len(),
            allowed,
            "{}: a spawned gateway must be owned by GatewayChildGuard from the instant of \
             spawn (issue #4991); owned Child types found: {owned:?} (allowed non-gateway: \
             {allowed}, {reason})",
            site.file
        );
    }
}

#[test]
fn bespoke_spawners_wrap_every_gateway_spawn_in_the_guard() {
    for site in SITES {
        let compact = squeezed(&code(site.src));
        let wraps = compact.matches("GatewayChildGuard::new").count();
        match site.spawner {
            Spawner::Own { guarded_spawns } => assert_eq!(
                wraps, guarded_spawns,
                "{}: every gateway spawn site must be wrapped with \
                 GatewayChildGuard::new(...); update the row when a spawn site is added",
                site.file
            ),
            Spawner::Delegated { to } => {
                assert_eq!(
                    compact.matches(".spawn()").count(),
                    0,
                    "{}: this file must spawn only through {to}",
                    site.file
                );
                assert!(
                    SITES.iter().any(|other| other.file == to),
                    "{}: the delegated spawner {to} must have its own row",
                    site.file
                );
            }
        }
    }
}

#[test]
fn bespoke_spawners_never_sigkill_a_gateway() {
    for site in SITES {
        let compact = squeezed(&code(site.src));
        let kills = compact.matches(".kill()").count();
        let (allowed, reason) = site.non_gateway_kills;
        assert_eq!(
            kills, allowed,
            "{}: tear a gateway down through GatewayChildGuard::shutdown (SIGTERM plus a \
             grace period under coverage), not a raw kill() that loses its coverage profile \
             (allowed non-gateway kills: {allowed}, {reason})",
            site.file
        );
    }
}

#[test]
fn bespoke_spawners_bound_drain_and_isolate_the_managed_store() {
    for site in SITES {
        if matches!(site.spawner, Spawner::Delegated { .. }) {
            continue;
        }
        let code = code(site.src);
        assert!(
            code.contains("FERRUM_TLS_MANAGED_STORE_PATH"),
            "{}: a bespoke spawner must point FERRUM_TLS_MANAGED_STORE_PATH at a temp dir \
             that outlives the child, or the gateway writes ./ferrum-managed-tls into the \
             checkout (issue #5706)",
            site.file
        );
        assert!(
            code.contains("configure_coverage_gateway_command(")
                || code.contains("\"FERRUM_SHUTDOWN_DRAIN_SECONDS\""),
            "{}: call configure_coverage_gateway_command so the coverage teardown's SIGTERM \
             fits inside its grace period",
            site.file
        );
    }
}

#[test]
fn bespoke_spawners_lease_handoff_ports_from_the_registry() {
    for site in SITES {
        let released = released_ephemeral_ports(site.src);
        let (allowed, reason) = site.released_ephemeral_ports;
        assert_eq!(
            released, allowed,
            "{}: a port handed to a subprocess must come from \
             crate::scaffolding::ports::unbound_port (outside the ephemeral source range), \
             not from binding 127.0.0.1:0 and dropping the listener; a backend keeps its \
             listener bound (allowed deliberate releases: {allowed}, {reason})",
            site.file
        );
    }
}

/// The scanners themselves: a regression here would silently pass every row.
#[test]
fn lifecycle_scanners_flag_the_shapes_they_exist_to_catch() {
    let bare = squeezed(&code(
        "use std::process::{Child, Command};\n\
         struct Harness { gateway: std::process::Child }\n\
         fn start() -> Child { todo!() }\n\
         fn probe(child: &mut Child, other: &mut std::process::Child) {}\n\
         // a Child in a comment\n\
         let guard: GatewayChildGuard = todo!(); let id = Child::id;\n",
    ));
    assert_eq!(owned_child_types(&bare).len(), 2, "{bare}");

    let released = "let proxy_listener = TcpListener::bind_test(\"127.0.0.1:0\").await?;\n\
                    let port = proxy_listener.local_addr()?.port();\n\
                    drop(proxy_listener);\n\
                    let held = TcpListener::bind_test(\"127.0.0.1:0\").await?;\n";
    assert_eq!(released_ephemeral_ports(released), 1);

    let url = code("let url = \"http://127.0.0.1\"; x.kill(); // y.kill()\n");
    assert_eq!(squeezed(&url).matches(".kill()").count(), 1, "{url}");
}
