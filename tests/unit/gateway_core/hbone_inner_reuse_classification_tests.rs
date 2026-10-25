//! Which plugins let one admitted HBONE CONNECT carry LATER application
//! operations (issue #5583).
//!
//! Source-side reuse keeps the inner application connection inside an admitted
//! tunnel, so the destination's per-CONNECT plugin chain runs ONCE where it
//! would otherwise have run once per operation. The relay is a transparent byte
//! tunnel — the destination never parses the inner requests either way — so
//! every one of those elided runs would have carried IDENTICAL request
//! attributes. The only thing that differs across them is TIME, and only two
//! time-varying decisions are re-issued for a live tunnel: the local authorize
//! verdict (the fence's sweep) and the peer's mTLS credential (the fence's
//! credential gate). Everything else — a rate-limit token, a concurrency
//! permit, a mirror dispatch, an external CUSTOM verdict, a bearer credential's
//! own expiry — would be spent once and then honoured indefinitely.
//!
//! `Plugin::allows_hbone_inner_reuse` is therefore fail-closed by default and
//! this table forces every classification to be deliberate. The companion
//! re-evaluation contract lives in `authorize_reevaluation_contract_tests.rs`;
//! the two are coupled, because a `true` justified by "the sweep re-issues it"
//! is only true while that plugin also opts into `reevaluates_live_admission`.
//!
//! Declaring `true` is a STANDING obligation, not a one-time statement: the
//! fence re-folds this classification over the live chain on every sweep and
//! revokes a tunnel it already advertised to (`reuse_withdrawn`) as soon as the
//! chain stops permitting reuse. The end-to-end proof of both halves —
//! advertisement and withdrawal — runs through the production dispatcher in
//! `tests/integration/hbone_admission_fence_tests.rs`.

use async_trait::async_trait;
use ferrum_edge::plugins::{HboneReuseContext, Plugin, PluginResult, RequestContext};
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The override's signature, whitespace-normalized. Matching the NORMALIZED
/// source means a reindent, a rustfmt change, or a line break inside the
/// signature cannot fail these pins for a reason that has nothing to do with
/// the classification they are about.
const SIGNATURE: &str = "fn allows_hbone_inner_reuse(&self) -> bool {";
const CONTEXT_SIGNATURE: &str =
    "fn allows_hbone_inner_reuse_for(&self, admission: &HboneReuseContext) -> bool {";

/// Collapse every run of whitespace to one space, so source scanning compares
/// tokens rather than layout.
fn normalized(source: &str) -> String {
    source.split_whitespace().collect::<Vec<&str>>().join(" ")
}

/// Every occurrence of `signature` in `source`, with its body returned as a
/// whitespace-normalized expression (`true`, `false`,
/// `self.ext_authz.is_none()`, or a pure listener-facts predicate).
///
/// The bodies this contract admits are single expressions with no braces of
/// their own, so the first `}` after the signature closes the method. A body
/// that needed a brace requires this source pin to be deliberately revisited.
fn classification_bodies(source: &str, signature: &str) -> Vec<String> {
    let flat = normalized(source);
    let mut bodies = Vec::new();
    let mut rest = flat.as_str();
    while let Some(start) = rest.find(signature) {
        let after = &rest[start + signature.len()..];
        let end = after
            .find('}')
            .expect("a classification body must close with `}`");
        bodies.push(after[..end].trim().to_string());
        rest = &after[end..];
    }
    bodies
}

/// Every built-in that classifies itself, keyed by its path under
/// `src/plugins/`, with the exact expression it must return.
///
/// Reusable (`true`) requires case (a) — no per-operation decision and no
/// per-operation side effect — or case (b) — every decision it takes for the
/// tunnel is re-issued by the fence for the tunnel's whole life:
///
/// * `access_control` — (b). Its verdict is a pure function of the request's
///   identity inputs and immutable allow/deny sets, and every published
///   generation requests a sweep that re-runs exactly this hook.
/// * `mesh/authz` — (b) while no external executor is bound. The local tier is
///   re-issued by the sweep; CUSTOM delegation is deliberately not re-consulted,
///   so a bound executor refuses.
/// * `mesh/spiffe_identity` — (b), and the ONLY credential-bearing plugin that
///   qualifies: the credential it reads is the mTLS leaf, which is exactly what
///   the fence's credential gate re-verifies and expires. Only while it carries
///   no operator admission policy: a `require_identity` / `allowed_trust_domains`
///   verdict is a per-CONNECT decision no sweep re-issues.
/// * `mesh/workload_metrics`, `otel_tracing`, `prometheus_metrics`,
///   `proxy_alerts`, `stdout_logging` — (a). Pure observability: no admission
///   decision, no per-request budget, no rejection. Reuse costs record
///   fidelity, not enforcement.
///
/// `mesh/outbound_registry` is classified per admitting CONNECT:
///
/// * A scoped instance qualifies under (a) ONLY when the shared enforcement gate
///   skips this CONNECT's recorded listener facts. Inbound always skips; a
///   matching Outbound or non-mesh listener does not, even if it terminates an
///   authenticated CONNECT. A sweep never re-issues the registry lookup.
///   Inbound reuse and live tunnels survive REGISTRY_ONLY publication because
///   the gate skips them. The shared gate and its position are pinned by
///   [`the_outbound_registry_port_gate_precedes_every_decision_in_its_hook`].
/// * An UNSCOPED instance also skips Inbound, but enforces as a generic Host
///   allowlist on non-mesh listeners. That verdict is a per-operation decision
///   no sweep re-issues, so this instance keeps the fail-closed answer.
///
/// The three literal `false` entries are REDUNDANT against the trait default and kept
/// deliberately, because each one is where an operation is CHARGED and that is
/// the fact a future reader needs at the charge site:
///
/// * `adaptive_concurrency` — takes an in-flight permit per operation.
/// * `rate_limiting` — consumes a token per operation, in every `limit_by`
///   mode.
/// * `request_mirror` — dispatches a shadow request per operation, and in its
///   body-admission form also takes a permit and a byte-budget lease.
///
/// Every other built-in, and every custom plugin, inherits the fail-closed
/// default and is absent from this table.
const EXPECTED_CLASSIFICATION: &[(&str, &str)] = &[
    ("access_control.rs", "true"),
    ("adaptive_concurrency.rs", "false"),
    ("mesh/authz.rs", "self.ext_authz.is_none()"),
    ("mesh/bpf_metrics.rs", "true"),
    (
        "mesh/outbound_registry.rs",
        "!self.outbound_listen_ports.is_empty() && !self.should_enforce_for_request_facts( \
         admission.mesh_direction, admission.frontend_listen_port, )",
    ),
    (
        "mesh/spiffe_identity.rs",
        "!self.require_identity && self.allowed_trust_domains.is_none()",
    ),
    ("mesh/workload_metrics.rs", "true"),
    ("otel_tracing.rs", "true"),
    ("prometheus_metrics.rs", "true"),
    ("proxy_alerts/mod.rs", "true"),
    ("rate_limiting.rs", "false"),
    ("request_mirror.rs", "false"),
    ("stdout_logging.rs", "true"),
];

fn read_source(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn collect_rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            collect_rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Built-in plugin sources that OVERRIDE the classification, as paths relative
/// to `src/plugins/`, paired with the expression they return. `mod.rs` is
/// excluded: it carries the trait's own default, pinned separately below.
fn classifying_plugin_sources() -> Vec<(String, String)> {
    let plugins_dir = repo_root().join("src/plugins");
    let mut files = Vec::new();
    collect_rust_sources(&plugins_dir, &mut files);
    files.sort();
    let mut sources = Vec::new();
    for path in files {
        let relative = path
            .strip_prefix(&plugins_dir)
            .expect("path under src/plugins")
            .to_string_lossy()
            .replace('\\', "/");
        if relative == "mod.rs" {
            continue;
        }
        let source = read_source(&path);
        let mut bodies = classification_bodies(&source, SIGNATURE);
        bodies.extend(classification_bodies(&source, CONTEXT_SIGNATURE));
        assert!(
            bodies.len() <= 1,
            "src/plugins/{relative}: one classification per plugin source"
        );
        if let Some(body) = bodies.into_iter().next() {
            sources.push((relative, body));
        }
    }
    sources
}

#[test]
fn every_builtin_that_classifies_itself_is_in_the_reuse_table() {
    let sources = classifying_plugin_sources();
    let found: Vec<&str> = sources.iter().map(|(path, _)| path.as_str()).collect();
    let expected: Vec<&str> = EXPECTED_CLASSIFICATION.iter().map(|(p, _)| *p).collect();
    if found != expected {
        panic!(
            "built-in HBONE inner-reuse classifications changed: found {found:?}, expected \
             {expected:?}. A plugin may declare `allows_hbone_inner_reuse` as `true` only when it \
             takes no per-operation decision and has no per-operation side effect, or when every \
             decision it takes is re-issued by the HBONE admission fence for the tunnel's whole \
             life. Record the reason in EXPECTED_CLASSIFICATION"
        );
    }

    for ((path, body), (_, expected_body)) in sources.iter().zip(EXPECTED_CLASSIFICATION) {
        assert_eq!(
            body, expected_body,
            "src/plugins/{path}: `allows_hbone_inner_reuse` body changed; a reclassification must \
             move the table entry and its recorded reason together"
        );
    }
}

/// The scoped registry's reuse classification depends on its direction/port
/// gate running before every decision and side effect. Pin the complete gate
/// body so adding a lookup, metric, or new request input cannot silently weaken
/// that proof. Numeric port scoping alone does not identify an inbound listener.
#[test]
fn the_outbound_registry_port_gate_precedes_every_decision_in_its_hook() {
    let src = read_source(&repo_root().join("src/plugins/mesh/outbound_registry.rs"));
    let hook_start = src
        .find("async fn on_request_received(")
        .expect("the outbound registry must implement the request hook");
    let hook = normalized(&src[hook_start..]);
    assert!(
        hook.starts_with(
            "async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult { if \
             !self.should_enforce_for_request(ctx) { return PluginResult::Continue; }"
        ),
        "the direction/port gate must be the FIRST statement and return Continue immediately"
    );

    let flat = normalized(&src);
    assert!(flat.contains(
        "fn should_enforce_for_request(&self, ctx: &RequestContext) -> bool { \
         self.should_enforce_for_request_facts(ctx.mesh_direction, ctx.frontend_listen_port) }"
    ));
    const GATE: &str = "fn should_enforce_for_request_facts( &self, \
        mesh_direction: Option<MeshTrafficDirection>, frontend_listen_port: Option<u16>, \
        ) -> bool {";
    let gate_start = flat.find(GATE).expect("the direction/port gate must exist");
    let after_gate = &flat[gate_start + GATE.len()..];
    let mut depth = 1;
    let gate_end = after_gate
        .char_indices()
        .find_map(|(index, ch)| {
            match ch {
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
            (depth == 0).then_some(index)
        })
        .expect("the gate body must close with `}`");
    let gate_body = after_gate[..gate_end].trim();
    assert_eq!(
        gate_body,
        "if mesh_direction == Some(MeshTrafficDirection::Inbound) { return false; } \
         self.outbound_listen_ports.is_empty() || frontend_listen_port \
         .is_some_and(|port| self.outbound_listen_ports.binary_search(&port).is_ok())",
        "the gate must skip Inbound for every instance and otherwise read only the port scope"
    );
}

/// The default decides every UNCLASSIFIED plugin, including every custom one,
/// and it must be a LITERAL `false` — not a derivation from another marker.
///
/// `!is_authorize_plugin()` was the first attempt and it was wrong: that marker
/// describes participation in the AUTHORIZE PHASE, which is narrower than
/// "takes no per-operation decision anywhere". A plugin that charges a quota or
/// calls an external service from `on_request_received` and reports
/// `is_authorize_plugin() == false` inherited reuse from it. A literal also
/// makes the two markers independent, which is what
/// [`an_authorize_marker_change_alone_cannot_make_a_plugin_reusable`] proves at
/// runtime.
#[test]
fn the_reuse_default_is_a_literal_false() {
    let src = read_source(&repo_root().join("src/plugins/mod.rs"));
    let bodies = classification_bodies(&src, SIGNATURE);
    assert_eq!(
        bodies.len(),
        1,
        "the trait must declare exactly one default classification"
    );
    assert_eq!(
        bodies[0], "false",
        "the default classification must be a literal `false`; deriving it from another marker \
         opts unclassified and custom plugins into reuse through a question that marker does not \
         answer"
    );
    assert!(normalized(&src).contains(
        "fn allows_hbone_inner_reuse_for(&self, _admission: &HboneReuseContext) -> bool { \
         self.allows_hbone_inner_reuse() }"
    ));
}

#[test]
fn the_instance_wrapper_forwards_the_admitting_listener_facts() {
    let src = read_source(&repo_root().join("src/plugin_cache.rs"));
    assert_eq!(
        classification_bodies(&src, CONTEXT_SIGNATURE),
        vec!["self.inner.allows_hbone_inner_reuse_for(admission)"]
    );
}

/// A plugin nobody has classified refuses reuse even when it acts in the
/// request phase and reports `is_authorize_plugin() == false` — the exact shape
/// the derived default admitted by accident.
///
/// What the fixture's hook DOES is deliberately nothing: the classification is
/// a static property of the plugin, not of any request, so a fixture that
/// really charged a quota would prove no more than this one and would need a
/// live limiter to do it. The shape under test is the pair of markers.
#[test]
fn an_unclassified_plugin_with_a_request_phase_hook_refuses_reuse() {
    let plugin = RequestPhasePlugin;
    assert!(
        !plugin.is_authorize_plugin(),
        "this fixture exists to stand for a plugin acting OUTSIDE the authorize phase"
    );
    assert!(
        !plugin.allows_hbone_inner_reuse(),
        "an unclassified plugin must refuse reuse whatever else it declares: the supported custom \
         shape this stands for charges a quota or consults an external service per request, and \
         reuse would spend one charge and one verdict for an unbounded number of later operations"
    );
    assert!(!plugin.allows_hbone_inner_reuse_for(&HboneReuseContext {
        mesh_direction: Some(ferrum_edge::modes::mesh::MeshTrafficDirection::Inbound),
        frontend_listen_port: Some(15008),
    }));
}

/// Flipping ONLY the authorize marker cannot change the reuse answer.
///
/// The two fixtures are identical but for `is_authorize_plugin`. With the old
/// `!is_authorize_plugin()` default this assertion was false by construction:
/// the marker WAS the classification.
#[test]
fn an_authorize_marker_change_alone_cannot_make_a_plugin_reusable() {
    assert!(AuthorizePhasePlugin.is_authorize_plugin());
    assert!(!RequestPhasePlugin.is_authorize_plugin());
    assert_eq!(
        AuthorizePhasePlugin.allows_hbone_inner_reuse(),
        RequestPhasePlugin.allows_hbone_inner_reuse(),
        "the reuse classification must not move with the authorize marker"
    );
    assert!(
        !RequestPhasePlugin.allows_hbone_inner_reuse(),
        "and the shared answer must be the fail-closed one"
    );
}

/// An unclassified plugin that acts in `on_request_received` and reports
/// `is_authorize_plugin() == false` — the position a custom plugin that charges
/// a quota or consults an external service per request occupies.
struct RequestPhasePlugin;

#[async_trait]
impl Plugin for RequestPhasePlugin {
    fn name(&self) -> &str {
        "hbone_reuse_unclassified_request_phase"
    }

    fn is_authorize_plugin(&self) -> bool {
        false
    }

    async fn on_request_received(&self, _ctx: &mut RequestContext) -> PluginResult {
        PluginResult::Continue
    }
}

/// The same fixture with the authorize marker left at its `true` default. The
/// ONLY difference between the two.
struct AuthorizePhasePlugin;

#[async_trait]
impl Plugin for AuthorizePhasePlugin {
    fn name(&self) -> &str {
        "hbone_reuse_unclassified_authorize_phase"
    }

    async fn on_request_received(&self, _ctx: &mut RequestContext) -> PluginResult {
        PluginResult::Continue
    }
}

/// The CONNECT path must fold the chain that ADMITTED this CONNECT — the
/// protocol-scoped slice the dispatcher resolved and passed in — and not
/// re-derive one. `HboneAdmissionView` is a `Copy` record of the protocol
/// selectors and the sweep epoch; it holds no plugins.
///
/// The fold runs ONCE, before `admit()`, and its result is RECORDED on the
/// admission snapshot; the response then reads that field back. One value means
/// the header the source receives and the obligation the fence takes on cannot
/// disagree — and the fence's obligation is what
/// `a_published_custom_authorization_policy_withdraws_reuse_from_a_live_tunnel`
/// and its siblings exercise end to end.
#[test]
fn the_connect_path_records_the_admitting_chain_fold_before_it_advertises() {
    let src = normalized(&read_source(&repo_root().join("src/proxy/hbone_proxy.rs")));
    let fold_call = "admitting_chain_allows_inner_reuse(plugins, &reuse_context)";
    assert!(src.contains("let reuse_context = HboneReuseContext::from(&*ctx);"));
    assert!(
        src.contains(&format!("let chain_allows_inner_reuse = {fold_call};")),
        "the CONNECT path must fold the dispatcher's own `plugins` slice"
    );
    assert!(
        src.contains("advertised_inner_reuse: chain_allows_inner_reuse,"),
        "the fold's result must be recorded on the admission snapshot, so every later sweep can \
         re-judge the eligibility this tunnel was granted"
    );
    assert!(src.contains("advertised_inner_reuse: chain_allows_inner_reuse, reuse_context,"));
    assert!(
        src.contains(
            "let advertise_tunnel_reuse = tunnel.fence_in_force() && \
             tunnel.snapshot().advertised_inner_reuse;"
        ),
        "the advertisement must read the RECORDED value back, not re-fold: the header and the \
         fence's obligation have to be one value"
    );
    assert_eq!(
        src.matches(fold_call).count(),
        1,
        "the CONNECT path folds exactly once"
    );
    assert!(
        !src.contains("admission_view.plugins()"),
        "the admitting chain is the dispatcher's `plugins` slice; the admission view carries \
         only the protocol selectors and the sweep epoch"
    );
}

/// The sweep re-judges eligibility with the SAME fold, over the view it
/// re-resolved for the current generation, and revokes rather than silently
/// leaving a reusable tunnel under a chain that no longer permits reuse.
///
/// It must also stay a pure fold: a sweep provokes no request, so running
/// `authorize`, `on_request_received`, or any quota/external hook here would do
/// to every live tunnel exactly what `Plugin::reevaluates_live_admission`
/// exists to prevent.
#[test]
fn the_sweep_refolds_the_current_chain_for_every_tunnel_that_advertised_reuse() {
    let src = normalized(&read_source(
        &repo_root().join("src/proxy/hbone_admission_fence.rs"),
    ));
    assert!(
        src.contains(
            "if snapshot.advertised_inner_reuse { let current_chain = view.plugins(); if \
             !admitting_chain_allows_inner_reuse(&current_chain, &snapshot.reuse_context) { return \
             Some(HboneRevocationReason::ReuseWithdrawn); } }"
        ),
        "every sweep must re-fold the CURRENT chain for a tunnel that advertised reuse, and \
         revoke it when the chain no longer permits reuse"
    );
    assert!(
        src.contains("use super::hbone_proxy::{ admitting_chain_allows_inner_reuse,"),
        "the sweep must reuse the CONNECT path's own fold so the two cannot drift"
    );
}

/// A datagram tunnel unframes into a local `UdpSocket` and carries no inner
/// request/response exchange a source could pool, so the capability simply does
/// not exist on that surface and the handler must never stamp it — whatever its
/// admitting chain would have classified. It therefore never records the
/// advertisement either, and so is never judged by the withdrawal gate.
#[test]
fn the_datagram_connect_path_never_stamps_the_reuse_header() {
    let src = read_source(&repo_root().join("src/proxy/hbone_proxy.rs"));
    let start = src
        .find("pub(super) async fn handle_hbone_udp_request(")
        .expect("the datagram CONNECT handler must exist");
    let rest = &src[start..];
    let end = rest
        .find("\n/// Resolve the CONNECT authority `host` to concrete IPs")
        .expect("the datagram CONNECT handler must terminate");
    let handler = normalized(&rest[..end]);
    assert!(
        !handler.contains("TUNNEL_REUSE_HEADER"),
        "the datagram CONNECT path must never advertise inner reuse"
    );
    assert!(
        handler.contains("advertised_inner_reuse: false,"),
        "and must record that refusal on its snapshot, so no sweep judges it for a capability it \
         never had"
    );
}
