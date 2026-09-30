//! Source pins: the path-parameter re-lookup repeats the frontend's mesh
//! route resolution (issue #5948, follow-up to #5937).
//!
//! A `;` request on an opted-in proxy is resolved again with its parameters
//! stripped, and served only when that lookup lands where the request did. The
//! H1/H2 frontend (`src/proxy/mod.rs`) resolves a request inline, because each
//! step there answers its own `502` body and stamps the authorization port,
//! while the re-lookup goes through
//! `RouterCache::resolve_mesh_scoped_route_in_epoch` (`src/router_cache.rs`).
//! The two must run the same steps, in the same order, from the same inputs.
//! If they drift, the re-lookup can name a different route than the one that
//! would serve the stripped path, and the check stops meaning anything.
//!
//! These tests fail when a step is added, removed, or reordered on one side
//! only. Update both sides together, then update the step list here.

const PROXY_SOURCE: &str = include_str!("../../../src/proxy/mod.rs");
const ROUTER_SOURCE: &str = include_str!("../../../src/router_cache.rs");
const HTTP3_SOURCE: &str = include_str!("../../../src/http3/server.rs");

/// The frontend's captured original-destination port signal.
const FRONTEND_ORIG_DST_PORT: &str = "ctx.orig_dst.map(|addr| addr.port())";

/// The mesh resolution steps, in the order the frontend runs them.
const STEPS: &[&str] = &[
    // Host and path lookup.
    "find_proxy_in_epoch(",
    // Direction filter: a wrong-direction mesh winner is re-resolved.
    "mesh_route_direction(",
    "resolve_route_excluding_wrong_direction_in_epoch(",
    // Outbound port-sibling selection, direct Pod-IP routes excluded.
    "is_mesh_outbound_route_id(",
    "is_mesh_outbound_http_bywl_route_id(",
    "select_mesh_outbound_port_route_with_authz_port(",
    // Inbound: the dedicated ingress bind port check, else sibling selection.
    "is_mesh_inbound_route_id(",
    "is_mesh_ingress_bind_route_id(",
    "select_mesh_inbound_port_route(",
];

fn slice_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let from = source
        .find(start)
        .unwrap_or_else(|| panic!("{start:?} not found"));
    let len = source[from..]
        .find(end)
        .unwrap_or_else(|| panic!("{end:?} not found after {start:?}"));
    &source[from..from + len]
}

/// The H1/H2 frontend's route resolution: from the direct Pod-IP decision to
/// the end of inbound port-sibling selection.
fn frontend_resolution() -> &'static str {
    let from = PROXY_SOURCE
        .find("let routed_by_direct_workload = matches!(")
        .expect("frontend direct Pod-IP decision");
    let rest = &PROXY_SOURCE[from..];
    let inbound = rest
        .find("select_mesh_inbound_port_route(")
        .expect("frontend inbound port selection");
    let end = rest[inbound..]
        .find("other => other,")
        .expect("end of frontend inbound port selection");
    &rest[..inbound + end]
}

fn resolver_entry() -> &'static str {
    slice_between(
        ROUTER_SOURCE,
        "pub(crate) fn resolve_mesh_scoped_route_in_epoch(",
        "\n    }\n",
    )
}

fn resolver_mesh_steps() -> &'static str {
    slice_between(
        ROUTER_SOURCE,
        "fn complete_mesh_scoped_resolution(",
        "\n}\n",
    )
}

/// The markers of `steps` found in `region`, in source order. Each marker must
/// occur exactly once, so a duplicated step is caught too.
fn step_order<'a>(region: &str, steps: &[&'a str]) -> Vec<&'a str> {
    let mut found: Vec<(usize, &str)> = steps
        .iter()
        .filter_map(|step| {
            let count = region.matches(step).count();
            assert!(count <= 1, "{step:?} occurs {count} times");
            region.find(step).map(|at| (at, *step))
        })
        .collect();
    found.sort_by_key(|(at, _)| *at);
    found.into_iter().map(|(_, step)| step).collect()
}

/// The argument text of the first `call` in `region`, up to its matching `)`.
fn call_arguments<'a>(region: &'a str, call: &str) -> &'a str {
    let at = region
        .find(call)
        .unwrap_or_else(|| panic!("{call:?} not found"));
    let open = at + call.len();
    let mut depth = 1usize;
    for (offset, byte) in region.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return &region[open..open + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced {call:?}");
}

#[test]
fn the_frontend_runs_the_mesh_steps_in_order() {
    assert_eq!(step_order(frontend_resolution(), STEPS), STEPS);
}

#[test]
fn the_re_lookup_runs_the_same_steps_in_the_same_order() {
    // The entry point runs the lookup and hands the direction re-resolve to
    // the mesh steps as a closure.
    assert_eq!(
        step_order(resolver_entry(), STEPS),
        [STEPS[0], STEPS[2]],
        "resolve_mesh_scoped_route_in_epoch must run only the host and path lookup and \
         pass the direction re-resolve on"
    );
    let mesh_steps = resolver_mesh_steps();
    let expected: Vec<&str> = STEPS
        .iter()
        .copied()
        .filter(|step| *step != STEPS[0] && *step != STEPS[2])
        .collect();
    assert_eq!(step_order(mesh_steps, STEPS), expected);

    // The closure runs where the frontend re-resolves: after the direction
    // test and before any port selection.
    let direction = mesh_steps.find(STEPS[1]).expect("direction test");
    let re_resolve = mesh_steps
        .find("exclude_wrong_direction()")
        .expect("direction re-resolve");
    let outbound = mesh_steps.find(STEPS[3]).expect("outbound arm");
    assert!(direction < re_resolve && re_resolve < outbound);
}

#[test]
fn both_sides_guard_each_step_the_same_way() {
    let frontend = frontend_resolution();
    let resolver = resolver_mesh_steps();
    let pairs = [
        // A mesh route of the other direction is re-resolved.
        ("!= ctx.mesh_direction", "!= mesh.direction"),
        // Port-sibling selection is direction-gated.
        (
            "ctx.mesh_direction == Some(crate::modes::mesh::MeshTrafficDirection::Outbound)",
            "mesh.direction == Some(MeshTrafficDirection::Outbound)",
        ),
        (
            "ctx.mesh_direction == Some(crate::modes::mesh::MeshTrafficDirection::Inbound)",
            "mesh.direction == Some(MeshTrafficDirection::Inbound)",
        ),
        // Direct Pod-IP routes skip outbound sibling selection.
        (
            "&& !crate::modes::mesh::is_mesh_outbound_http_bywl_route_id(",
            "&& !crate::modes::mesh::is_mesh_outbound_http_bywl_route_id(",
        ),
        // A dedicated ingress bind serves only its own frontend port.
        (
            "if route_port == frontend_port",
            "if route_port == frontend_port",
        ),
    ];
    for (in_frontend, in_resolver) in pairs {
        assert!(
            frontend.contains(in_frontend),
            "frontend lost {in_frontend:?}"
        );
        assert!(
            resolver.contains(in_resolver),
            "re-lookup lost {in_resolver:?}"
        );
    }

    // The same port signals select the siblings.
    let frontend_outbound = call_arguments(frontend, STEPS[5]);
    assert!(frontend_outbound.contains(FRONTEND_ORIG_DST_PORT));
    let resolver_outbound = call_arguments(resolver, STEPS[5]);
    assert!(resolver_outbound.contains("mesh.orig_dst_port"));
    let frontend_inbound = call_arguments(frontend, STEPS[8]);
    assert!(frontend_inbound.contains(FRONTEND_ORIG_DST_PORT));
    assert!(frontend_inbound.contains("authority_port"));
    let resolver_inbound = call_arguments(resolver, STEPS[8]);
    assert!(resolver_inbound.contains("mesh.orig_dst_port"));
    assert!(resolver_inbound.contains("mesh.authority_port"));
}

#[test]
fn the_h1_h2_frontend_replays_the_inputs_it_routed_with() {
    let lookup = call_arguments(frontend_resolution(), STEPS[0]);
    for input in [
        "request_host.as_deref()",
        "&path",
        "ctx.frontend_listen_port",
        "is_tls",
        "gateway_listener_identity.as_ref()",
    ] {
        assert!(lookup.contains(input), "frontend lookup lost {input:?}");
    }

    let check = call_arguments(
        PROXY_SOURCE,
        "if let Err(rejection) = check_routed_path_parameters(",
    );
    for input in [
        "&path",
        "host: request_host.as_deref()",
        "frontend_port: ctx.frontend_listen_port",
        "frontend_is_tls: is_tls",
        "gateway_listener: gateway_listener_identity.as_ref()",
        "direction: ctx.mesh_direction",
        "orig_dst_port: ctx.orig_dst.map(|addr| addr.port())",
        "authority_port",
        "routed_by_direct_workload",
    ] {
        assert!(check.contains(input), "the re-lookup lost {input:?}");
    }
}

#[test]
fn the_http3_frontend_runs_only_the_direction_filter() {
    // HTTP/3 runs the lookup and the direction filter, and no mesh port
    // selection or direct Pod-IP decision, so it replays no port signals. If
    // it gains one of those steps, its replay scope must gain the inputs too.
    for step in [
        "mesh_http_egress_by_workload_decision(",
        "select_mesh_outbound_port_route_with_authz_port(",
        "is_mesh_ingress_bind_route_id(",
        "select_mesh_inbound_port_route(",
    ] {
        assert!(
            !HTTP3_SOURCE.contains(step),
            "HTTP/3 now runs {step:?}: replay its port signals in check_routed_path_parameters"
        );
    }
    assert!(HTTP3_SOURCE.contains(STEPS[2]));

    let check = call_arguments(
        HTTP3_SOURCE,
        "if let Err(rejection) = crate::proxy::check_routed_path_parameters(",
    );
    for input in [
        "direction: ctx.mesh_direction",
        "..crate::router_cache::MeshRouteScope::default()",
        "routed_by_direct_workload: false",
    ] {
        assert!(check.contains(input), "HTTP/3 re-lookup lost {input:?}");
    }
}

#[test]
fn request_handling_resolves_through_the_epoch_resolver() {
    // The re-lookup must use the request's epoch and listener. The test-only
    // variant builds a `MeshScopedRoute` without either.
    let check = slice_between(
        PROXY_SOURCE,
        "pub(crate) fn check_routed_path_parameters(",
        "\n}\n",
    );
    assert!(check.contains(".resolve_mesh_scoped_route_in_epoch("));
    for (name, source) in [
        ("src/proxy/mod.rs", PROXY_SOURCE),
        ("src/http3/server.rs", HTTP3_SOURCE),
    ] {
        assert!(
            !source.contains("resolve_mesh_scoped_route_for_test("),
            "{name} must not call the test-only resolver"
        );
    }
}
