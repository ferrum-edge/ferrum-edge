//! Parity assertions for invariants shared across sibling protocol paths
//! (issue #4792).
//!
//! Thirteen separately-filed defects shared one shape: a rule was corrected on
//! ONE call site or ONE protocol path and the siblings that share the same rule
//! were left behind. The remedy is not any one of those fixes — it is an
//! assertion at each shared-invariant boundary that enumerates the siblings and
//! fails when a new one is added without the invariant, in the style of the
//! existing three-way `builtin_parity` registry/factory/metadata set-equality
//! check.
//!
//! Each section below owns exactly one invariant and names every path that
//! carries it. Runtime assertions are used wherever the invariant is observable
//! without a live server; where it is not, the assertion is structural over the
//! production sources — the same technique
//! `dp_config_admission_sites_tests.rs` and `allowed_methods_logging_tests.rs`
//! already use — so a sibling added without the invariant fails the build.
//!
//! Companion file: `tests/unit/plugins/waf_body_charset_parity_tests.rs` holds
//! the request/response wide-charset decoding parity table, which needs the WAF
//! plugin surface.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use ferrum_edge::circuit_breaker::CircuitBreaker;
use ferrum_edge::config::types::{CircuitBreakerConfig, Proxy, UpstreamTarget};
use ferrum_edge::config::{BackendEgressPolicy, EnvConfig, PoolConfig};
use ferrum_edge::connection_pool::ConnectionPool;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::http3::client::Http3ConnectionPool;
use ferrum_edge::proxy::grpc_proxy::GrpcConnectionPool;
use ferrum_edge::proxy::http2_pool::Http2ConnectionPool;
use ferrum_edge::service_discovery::filter_discovered_targets;
use ferrum_edge::tls::backend::SvidGenerationMatcher;
use ferrum_edge::util::sharding::pool_shard_amount;
use serde_json::json;

// ---------------------------------------------------------------------------
// Shared source-inventory helpers
// ---------------------------------------------------------------------------

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Read one production source by repository-relative path.
fn source(relative: &str) -> String {
    let path = repository_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{relative} must be readable: {error}"))
}

/// Every `.rs` file under `src/`, sorted, as `(repository-relative path, text)`.
fn production_sources() -> Vec<(String, String)> {
    let root = repository_root();
    let mut stack = vec![root.join("src")];
    let mut out = Vec::new();
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                out.push((relative_path(&root, &path), text));
            }
        }
    }
    out.sort();
    out
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Slice an item body out of `text`, from the first occurrence of `signature`
/// through the first following line that closes at `terminator`'s indentation.
///
/// Indentation-anchored rather than brace-counting so an unbalanced brace
/// inside a format string or comment cannot silently truncate the slice.
fn item_body<'a>(text: &'a str, signature: &str, terminator: &str) -> &'a str {
    let start = text
        .find(signature)
        .unwrap_or_else(|| panic!("`{signature}` must exist in the scanned source"));
    let end = text[start..]
        .find(terminator)
        .unwrap_or_else(|| panic!("`{signature}` must be terminated by `{terminator:?}`"));
    &text[start..start + end + terminator.len()]
}

#[test]
fn mesh_apply_paths_carry_permission_from_preparation_to_commit() {
    let mesh = source("src/modes/mesh/mod.rs");
    let runtime = source("src/modes/mesh/runtime.rs");
    // Startup, ordinary updates, content-no-op updates, and overlay fallback
    // all need the same lifecycle. The behavioral gate tests cover admission
    // races; this inventory catches a caller reintroducing late token minting.
    for (signature, required) in [
        (
            "async fn wait_for_initial_mesh_config(",
            "return Ok((config, Arc::new(slice.clone()), token))",
        ),
        (
            "async fn serve_mesh_runtime(",
            "initial_apply: Option<(Arc<MeshSlice>, revision::MeshRevisionApplyToken)>",
        ),
        (
            "async fn arm_mesh_runtime_startup(",
            "record_applied_slice_with_token(slice, initial_revision_apply_token)",
        ),
        (
            "async fn apply_mesh_slice_generation(",
            "let Some(revision_apply_token) = revision_apply_token else",
        ),
        (
            "fn start_mesh_slice_apply_task(",
            "let revision_apply_token = mesh_state.begin_revision_apply(slice)",
        ),
    ] {
        assert!(
            item_body(&mesh, signature, "\n}").contains(required),
            "{signature} must carry an apply-begin capability"
        );
    }
    let commit = item_body(
        &runtime,
        "    pub fn record_applied_slice_with_token(",
        "\n    }",
    );
    assert!(!commit.contains("begin_revision_apply("));
    assert!(!runtime.contains("pub fn record_applied_slice("));
}

// ---------------------------------------------------------------------------
// (a) Circuit-breaker HALF_OPEN probe-slot release
//
// GHSA-4cq4-3f3f-mq76: a request admitted as a HALF_OPEN probe must release its
// probe slot on EVERY exit — a gateway-side refusal, a recorded backend outcome,
// and (the reported defect) a dropped future when the client disconnects. The
// slot is otherwise held forever: the state machine has no timer out of
// HALF_OPEN, so one abandoned probe sheds every later request to that backend
// for the rest of the process lifetime.
//
// The invariant is now carried by ONE RAII type, `HalfOpenProbeGuard`, rather
// than a bare `bool` threaded through each path's `record_*` call sites. Every
// protocol path that admits a probe owns a guard.
// ---------------------------------------------------------------------------

/// Files that call the shared circuit-breaker admission. Adding a protocol path
/// here without a probe guard is exactly the #4792 shape.
const PROBE_ADMISSION_SITES: &[&str] = &[
    "src/http3/server.rs",
    "src/proxy/hbone_proxy.rs",
    "src/proxy/mod.rs",
];

/// The one RAII type every admitting path must construct.
const SHARED_PROBE_GUARD: &str = "HalfOpenProbeGuard::new(";

/// UDP and TCP bypass the shared admission helper. Count admissions per body,
/// then check each admission arm independently (issue #4979).
const DIRECT_PROBE_ADMISSION_SITES: &[(&str, &str, usize)] = &[
    (
        "src/proxy/udp_proxy.rs",
        "async fn handle_dtls_client_inner(",
        1,
    ),
    ("src/proxy/udp_proxy.rs", "async fn create_session(", 1),
    (
        "src/proxy/tcp_proxy.rs",
        "async fn handle_tcp_connection_inner(",
        2,
    ),
];

/// Files that must own a guard rather than re-deriving the release: the
/// admission sites plus every module they hand the guard to.
const PROBE_GUARD_HOLDERS: &[&str] = &[
    "src/http3/connect_udp.rs",
    "src/http3/cross_protocol.rs",
    "src/http3/server.rs",
    "src/http3/websocket.rs",
    "src/proxy/hbone_proxy.rs",
    "src/proxy/mod.rs",
    "src/proxy/tcp_proxy.rs",
    "src/proxy/udp_proxy.rs",
];

/// Every settle path on the shared guard: `(label, signature, terminator)`.
/// Each must reach the NEUTRAL release or explicitly hand the slot over.
const PROBE_GUARD_SETTLE_PATHS: &[(&str, &str, &str)] = &[
    (
        "explicit gateway-side refusal",
        "    pub fn release_neutral(&self) {",
        "\n    }\n",
    ),
    (
        "dropped future (client disconnect)",
        "impl Drop for HalfOpenProbeGuard {",
        "\n}\n",
    ),
    (
        "gRPC streaming recorder handoff",
        "impl Drop for GrpcStreamingProbeRecorder {",
        "\n}\n",
    ),
];

#[test]
fn every_circuit_breaker_admission_site_carries_a_probe_guard() {
    let admitting: BTreeSet<String> = production_sources()
        .into_iter()
        .filter(|(_, text)| text.contains("backend_dispatch::check_circuit_breaker("))
        .map(|(path, _)| path)
        .collect();
    let expected: BTreeSet<String> = PROBE_ADMISSION_SITES
        .iter()
        .map(|path| (*path).to_string())
        .collect();
    assert_eq!(
        admitting, expected,
        "a new protocol path admits HALF_OPEN circuit-breaker probes; give it a \
         `HalfOpenProbeGuard` and add it to PROBE_GUARD_HOLDERS before listing it here"
    );

    for &site in PROBE_ADMISSION_SITES {
        assert!(
            source(site).contains(SHARED_PROBE_GUARD),
            "{site} admits HALF_OPEN probes but constructs no `{}`",
            SHARED_PROBE_GUARD
        );
    }

    for &(file, signature, count) in DIRECT_PROBE_ADMISSION_SITES {
        let text = source(file);
        let expected_count: usize = DIRECT_PROBE_ADMISSION_SITES
            .iter()
            .filter(|(path, _, _)| *path == file)
            .map(|(_, _, count)| count)
            .sum();
        assert_eq!(
            text.matches("circuit_breaker_cache.can_execute(").count(),
            expected_count,
            "every direct-cache admission in {file} must be listed and own a probe guard"
        );
        let body = item_body(&text, signature, "\n}");
        assert_eq!(
            body.matches("circuit_breaker_cache.can_execute(").count(),
            count,
            "{signature} must retain its direct-cache admission checks"
        );
        for admission in body.split("circuit_breaker_cache.can_execute(").skip(1) {
            let admitted = admission
                .split_once("Err(_) =>")
                .expect("cache admission must handle refusal")
                .0;
            assert!(
                admitted
                    .contains("HalfOpenProbeGuard::for_admitted_probe(&cb, is_half_open_probe)"),
                "{signature} must own each slot on the breaker returned by cache admission"
            );
            if file == "src/proxy/tcp_proxy.rs" {
                assert!(
                    admitted.contains("cb_probe.rearm(&cb, is_half_open_probe)"),
                    "TCP retries must rearm the guard on the newly admitted breaker"
                );
            }
        }
    }
}

#[test]
fn no_dispatch_path_carries_a_bare_probe_flag_beside_the_guard() {
    // #4792 root cause 1: the same rule re-implemented per protocol path. The
    // bare `bool` plumbing is what let a dropped future skip every release, so
    // no holder may reintroduce a local copy of it.
    for &file in PROBE_GUARD_HOLDERS {
        let text = source(file);
        assert!(
            text.contains("cb_probe"),
            "{file} must carry the shared `HalfOpenProbeGuard` as `cb_probe`"
        );
        for banned in [
            "let mut cb_is_half_open_probe",
            "let release_half_open_probe =",
            "ws_cb_probe_slot_available",
            "grpc_cb_probe_slot",
            "cb_retry_probe_slot_available",
            "cb_info.is_half_open_probe",
        ] {
            assert!(
                !text.contains(banned),
                "{file} reintroduced the bare probe flag `{banned}`; thread the shared \
                 `HalfOpenProbeGuard` instead so a dropped future still releases the slot"
            );
        }
    }
}

#[test]
fn every_probe_guard_settle_path_releases_neutrally() {
    let text = source("src/proxy/mod.rs");
    for &(label, signature, terminator) in PROBE_GUARD_SETTLE_PATHS {
        let body = item_body(&text, signature, terminator);
        assert!(
            body.contains("record_neutral("),
            "the {label} settle path must return the probe slot through the NEUTRAL \
             release: a client disconnect is neither a backend success nor a backend \
             failure, and leaving the slot held wedges the breaker"
        );
    }
}

#[test]
fn taking_the_probe_slot_is_what_disarms_the_guard() {
    // The exactly-once property the whole design rests on: every explicit
    // `record_*` argument comes from `take_slot`, which atomically clears the
    // armed flag, so no path can release the same slot twice (a double release
    // decrements a DIFFERENT probe's slot and over-admits).
    let text = source("src/proxy/mod.rs");
    let take = item_body(&text, "    pub fn take_slot(&self) -> bool {", "\n    }\n");
    assert!(
        take.contains("self.armed.swap(false"),
        "`take_slot` must atomically clear the armed flag as it hands the slot over"
    );
    let drop_body = item_body(&text, "impl Drop for HalfOpenProbeGuard {", "\n}\n");
    assert!(
        drop_body.contains("self.armed.swap(false"),
        "the guard's `Drop` must claim the slot with the same atomic swap so it \
         cannot race an explicit release"
    );
}

fn probe_breaker_config() -> CircuitBreakerConfig {
    CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 2,
        timeout_seconds: 0,
        failure_status_codes: vec![500],
        half_open_max_requests: 1,
        trip_on_connection_errors: true,
    }
}

/// A breaker that is OPEN, then has exactly one HALF_OPEN probe admitted.
fn breaker_holding_one_probe() -> CircuitBreaker {
    let cb = CircuitBreaker::new(probe_breaker_config());
    cb.record_failure(500, false, false);
    assert_eq!(cb.state_name(), "open");
    assert!(
        cb.can_execute().expect("timeout 0 admits a probe"),
        "the admitted request must be flagged as the HALF_OPEN probe"
    );
    assert_eq!(cb.half_open_in_flight(), 1);
    cb
}

fn record_probe_success(cb: &CircuitBreaker) {
    cb.record_success(true);
}

fn record_probe_tripping_failure(cb: &CircuitBreaker) {
    cb.record_failure(500, false, true);
}

fn record_probe_non_tripping_status(cb: &CircuitBreaker) {
    cb.record_failure(404, false, true);
}

fn record_probe_connection_failure(cb: &CircuitBreaker) {
    cb.record_failure(502, true, true);
}

fn record_probe_neutral(cb: &CircuitBreaker) {
    cb.record_neutral(true);
}

/// One probe outcome: its label and the breaker call that reports it.
type ProbeOutcome = (&'static str, fn(&CircuitBreaker));

/// Every terminal outcome a dispatch path can record for an admitted probe.
const PROBE_OUTCOMES: &[ProbeOutcome] = &[
    ("record_success", record_probe_success),
    (
        "record_failure(tripping status)",
        record_probe_tripping_failure,
    ),
    (
        "record_failure(non-tripping status)",
        record_probe_non_tripping_status,
    ),
    (
        "record_failure(connection error)",
        record_probe_connection_failure,
    ),
    ("record_neutral", record_probe_neutral),
];

#[test]
fn every_probe_outcome_kind_releases_the_half_open_slot() {
    // Every one of them must return the slot: a path that records nothing —
    // the original gRPC defect — leaks it and wedges the breaker OPEN.
    for &(label, record) in PROBE_OUTCOMES {
        let cb = breaker_holding_one_probe();
        record(&cb);
        assert_eq!(
            cb.half_open_in_flight(),
            0,
            "{label} must release the HALF_OPEN probe slot"
        );
    }
}

// ---------------------------------------------------------------------------
// (b) Prune discovered target health against the LIVE load-balancer snapshot
//
// #4788: the circuit-breaker layer and the active probes pruned against the
// live LB set while the passive health layer pruned against the authored static
// config, so a reload erased ejections for service-discovered endpoints.
// ---------------------------------------------------------------------------

#[test]
fn all_three_target_health_layers_prune_from_one_live_snapshot() {
    let proxy = source("src/proxy/mod.rs");
    let body = item_body(
        &proxy,
        "fn prune_stale_target_health(&self, config: &GatewayConfig) {",
        "\n    }\n",
    );
    assert!(
        body.contains("let lb_snapshot = self.load_balancer_cache.load();"),
        "the prune pass must read the live load-balancer snapshot, not the authored config list"
    );
    for layer in [
        "self.circuit_breaker_cache.prune_stale_targets(",
        "self.health_checker.remove_stale_passive_targets_for_proxy(",
    ] {
        assert!(
            body.contains(layer),
            "`{layer}` must be driven from the same live snapshot as its sibling layers"
        );
    }

    // Neither layer may be pruned from anywhere else in the reload path: a
    // second call site outside this function is how the two drifted apart in
    // the first place.
    for layer in [
        ".circuit_breaker_cache.prune_stale_targets(",
        ".health_checker.remove_stale_passive_targets_for_proxy(",
    ] {
        assert_eq!(
            proxy.matches(layer).count(),
            body.matches(layer).count(),
            "every `{layer}` call site in src/proxy/mod.rs must live inside \
             prune_stale_target_health, against the one live snapshot"
        );
    }
}

#[test]
fn discovery_publication_prunes_both_layers_together() {
    // The other place a target set is published: a service-discovery refresh.
    // Both health layers are pruned there too, against the same snapshot.
    let discovery = source("src/service_discovery/mod.rs");
    for layer in [
        "remove_stale_passive_targets_for_proxy(",
        "prune_stale_targets_for_proxy(",
    ] {
        assert!(
            discovery.contains(layer),
            "a discovery snapshot publication must prune `{layer}` alongside its sibling layer"
        );
    }
}

#[test]
fn active_probing_resolves_targets_through_the_load_balancer_cache() {
    let health = source("src/health_check.rs");
    for helper in [
        "fn reset_latency_after_passive_recovery_inner(",
        "fn recover_due_passive_ejections_inner(",
    ] {
        let body = item_body(&health, helper, "\n}\n");
        assert!(
            body.contains("lb_cache"),
            "`{helper}` must resolve live targets through the load-balancer cache"
        );
    }
}

// ---------------------------------------------------------------------------
// (d) RFC 9113 protocol-NACK classification is ONE predicate
//
// #4772 / #4074: reqwest, the H3 plain bridge and native gRPC each need to know
// whether a backend refused a request before processing it. All three must ask
// the same typed predicate — a second implementation is how one of them missed
// the replay.
// ---------------------------------------------------------------------------

/// Every dispatch path that classifies a protocol NACK, and the shared
/// predicate it must route through.
const PROTOCOL_NACK_CONSUMERS: &[(&str, &str, &str)] = &[
    (
        "reqwest dispatch",
        "src/proxy/mod.rs",
        "retry::reqwest_error_is_protocol_nack",
    ),
    (
        "HTTP/3 plain bridge",
        "src/http3/cross_protocol.rs",
        "crate::retry::reqwest_error_is_protocol_nack",
    ),
    (
        "native gRPC dispatch",
        "src/proxy/grpc_proxy.rs",
        "crate::retry::error_chain_is_protocol_nack",
    ),
];

#[test]
fn every_protocol_nack_consumer_routes_through_the_shared_predicate() {
    for &(label, file, predicate) in PROTOCOL_NACK_CONSUMERS {
        let text = source(file);
        assert!(
            text.contains(predicate),
            "{label} ({file}) must classify protocol NACKs with `{predicate}`"
        );
        assert!(
            !text.contains("h2::Reason::REFUSED_STREAM"),
            "{label} ({file}) must not re-implement the RFC 9113 classification; a second copy \
             is how one path was left without the replay"
        );
    }
}

#[test]
fn the_protocol_nack_predicate_has_exactly_one_implementation() {
    let retry = source("src/retry.rs");
    assert_eq!(
        retry.matches("h2::Reason::REFUSED_STREAM").count(),
        1,
        "the RFC 9113 rejection proof must live in exactly one predicate"
    );
    let body = item_body(
        &retry,
        "pub(crate) fn error_chain_is_protocol_nack(",
        "\n}\n",
    );
    assert!(
        body.contains("downcast_ref::<h2::Error>()") && body.contains("is_remote()"),
        "the shared predicate must stay typed: a substring fallback would replay requests the \
         backend may already have processed"
    );
    assert!(
        item_body(&retry, "pub fn reqwest_error_is_protocol_nack(", "\n}\n")
            .contains("error_chain_is_protocol_nack(e)"),
        "the reqwest entry point must delegate to the shared chain walk"
    );
}

#[test]
fn every_buffered_upload_dispatch_replays_through_one_driver() {
    let proxy = source("src/proxy/mod.rs");
    assert!(
        proxy.contains("pub(crate) async fn send_buffered_upload_with_protocol_nack_replay<"),
        "the buffered-upload replay driver must remain shared"
    );
    let replay_sites = proxy
        .matches("send_buffered_upload_with_protocol_nack_replay(")
        .count();
    assert!(
        replay_sites >= 2,
        "every buffered-upload dispatch site must reach the shared replay driver"
    );
}

// ---------------------------------------------------------------------------
// (e) External secret-suffix resolution across CLI subcommands
//
// #4779: `run` and `validate` resolved `_FILE`/`_VAULT`/`_AWS`/`_AZURE`/`_GCP`
// suffixes; `health` did not, so a secret-backed admin endpoint was invisible to
// the container health check.
// ---------------------------------------------------------------------------

/// How each CLI subcommand obtains externally-sourced `FERRUM_*` settings.
#[derive(Debug, PartialEq, Eq)]
enum SecretResolution {
    /// Resolves the whole environment through `resolve_startup_secrets`.
    StartupRegistry,
    /// Resolves only the endpoint keys it reads, through the same registry.
    SelectedKeys,
    /// Reads no `FERRUM_*` setting at all, so there is nothing to resolve.
    NoFerrumSettings,
}

const CLI_SUBCOMMAND_SECRET_RESOLUTION: &[(&str, SecretResolution)] = &[
    ("Run", SecretResolution::StartupRegistry),
    ("Validate", SecretResolution::StartupRegistry),
    ("Reload", SecretResolution::NoFerrumSettings),
    ("Version", SecretResolution::NoFerrumSettings),
    ("Health", SecretResolution::SelectedKeys),
    ("AmbientUdpPreflight", SecretResolution::StartupRegistry),
];

/// Variant identifiers declared by `cli::Command`.
fn declared_cli_subcommands(cli: &str) -> BTreeSet<String> {
    item_body(cli, "pub enum Command {", "\n}\n")
        .lines()
        .filter_map(|line| {
            let trimmed = line.strip_prefix("    ")?;
            if trimmed.starts_with(' ') || trimmed.starts_with('/') || trimmed.starts_with('#') {
                return None;
            }
            let name = trimmed.split('(').next()?;
            if name.is_empty() || !name.starts_with(char::is_uppercase) {
                return None;
            }
            Some(name.to_string())
        })
        .collect()
}

#[test]
fn every_cli_subcommand_declares_how_it_resolves_external_secrets() {
    let declared = declared_cli_subcommands(&source("src/cli.rs"));
    let covered: BTreeSet<String> = CLI_SUBCOMMAND_SECRET_RESOLUTION
        .iter()
        .map(|(name, _)| (*name).to_string())
        .collect();
    assert_eq!(
        declared, covered,
        "a new CLI subcommand must declare whether it resolves external secret suffixes; `health` \
         was left behind exactly this way (#4779)"
    );
}

#[test]
fn every_settings_reading_subcommand_resolves_through_the_secret_registry() {
    let entry = source("src/gateway_entry.rs");
    let cli = source("src/cli.rs");

    let startup_arms = CLI_SUBCOMMAND_SECRET_RESOLUTION
        .iter()
        .filter(|(_, kind)| *kind == SecretResolution::StartupRegistry)
        .count();
    assert_eq!(
        entry.matches("resolve_startup_secrets()").count(),
        startup_arms + 1,
        "each startup-registry subcommand needs its own `resolve_startup_secrets()` call, plus \
         the definition"
    );
    assert!(
        item_body(&entry, "fn resolve_startup_secrets()", "\n}\n")
            .contains("secrets::resolve_all_env_secrets()"),
        "startup resolution must go through the shared secrets registry"
    );

    // `health` never mutates the process environment, so it resolves only the
    // endpoint keys it reads — through the same registry, with the same
    // conflict and redaction rules.
    let target = item_body(&cli, "fn resolve_health_target(", "\n}\n");
    assert!(
        target.contains("health_env_values(") && !target.contains("std::env::var("),
        "`health` must resolve endpoint inputs through the registry, not raw env reads"
    );
    assert!(
        item_body(&cli, "fn health_env_values(", "\n}\n")
            .contains("crate::secrets::resolve_selected_env_secrets("),
        "`health` must use the shared selected-key secret resolver"
    );

    // The two subcommands that claim to read nothing must actually read
    // nothing: a later `FERRUM_*` read there silently reintroduces the gap.
    for signature in [
        "pub fn execute_version(args: &VersionArgs)",
        "pub fn execute_reload(args: &ReloadArgs)",
    ] {
        let body = item_body(&cli, signature, "\n}\n");
        assert!(
            !body.contains("FERRUM_") && !body.contains("resolve_ferrum_var("),
            "`{signature}` is declared as reading no FERRUM_* setting; it now reads one, so it \
             also needs external secret resolution"
        );
    }
}

// ---------------------------------------------------------------------------
// (f) Dial-identity dedup of a discovery snapshot
//
// #4789: DNS-SD deduplicated endpoints by `host:port` before publication;
// Consul and Kubernetes did not, so one endpoint listed twice took a double
// share of load-balancer traffic.
// ---------------------------------------------------------------------------

fn discovered_target(host: &str, port: u16) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        service_port_policy_key: None,
        weight: 1,
        tags: std::collections::HashMap::new(),
        locality: None,
        path: None,
    }
}

/// Registry providers whose snapshots are deduplicated by dial identity in
/// `filter_discovered_targets`, and the mesh provider that deliberately is not.
const REGISTRY_DEDUP_PROVIDERS: &[&str] = &["consul", "kubernetes"];

#[test]
fn every_registry_provider_dedups_its_snapshot_by_dial_identity() {
    for &provider in REGISTRY_DEDUP_PROVIDERS {
        // The same endpoint spelled two ways: a canonical IPv6 form and its
        // expanded form. Both dial the same socket.
        let admitted = filter_discovered_targets(
            "parity",
            provider,
            vec![
                discovered_target("2001:db8::1", 8080),
                discovered_target("2001:0db8:0:0:0:0:0:1", 8080),
                discovered_target("2001:db8::1", 9090),
            ],
            BackendEgressPolicy::unrestricted(),
        );
        assert_eq!(
            admitted.len(),
            2,
            "{provider} must collapse duplicate dial identities before publication"
        );
        let identities: BTreeSet<(String, u16)> = admitted
            .iter()
            .map(|target| (target.host.clone(), target.port))
            .collect();
        assert_eq!(
            identities,
            BTreeSet::from([
                ("2001:db8::1".to_string(), 8080),
                ("2001:db8::1".to_string(), 9090),
            ]),
            "{provider} must keep one complete record per dial identity"
        );
    }
}

#[test]
fn dns_sd_dedups_in_its_own_adapter_and_the_registry_rule_names_its_providers() {
    // DNS-SD resolves duplicate priority tiers in its SRV adapter, so
    // `filter_discovered_targets` deliberately skips it. That exemption is only
    // safe while the adapter really does dedup — assert both halves, so a
    // fourth provider cannot be added to either side alone.
    let discovery = source("src/service_discovery/mod.rs");
    let filter = item_body(&discovery, "pub fn filter_discovered_targets(", "\n}\n");
    assert!(
        filter.contains(r#"if !matches!(provider_name, "consul" | "kubernetes") {"#),
        "the registry dedup allowlist must name exactly the providers this test exercises"
    );

    let dns_sd = source("src/service_discovery/dns_sd.rs");
    let adapter = item_body(&dns_sd, "pub(crate) fn targets_from_srv_records(", "\n}\n");
    assert!(
        adapter.contains("HashMap<(String, u16), usize>"),
        "the DNS-SD adapter must keep deduplicating on the `host:port` dial identity"
    );
}

// ---------------------------------------------------------------------------
// (g) The `pool_shard_amount` minimum lives in the shared helper
//
// #4785: one caller defended itself with a local `.max(2)` instead of fixing
// the helper, so every other caller kept the original bug and the workaround
// became evidence that someone had already hit it.
// ---------------------------------------------------------------------------

#[test]
fn the_shared_helper_clamps_every_shard_override_to_a_workable_minimum() {
    for override_value in [0usize, 1, 2, 3, 4, 7, 8, 100, 513, usize::MAX] {
        let shards = pool_shard_amount(override_value);
        assert!(
            shards >= 2,
            "pool_shard_amount({override_value}) = {shards}; DashMap rejects a single shard, so \
             the floor must live in the shared helper, not at a call site"
        );
        assert!(
            shards.is_power_of_two(),
            "pool_shard_amount({override_value}) = {shards} must be a power of two"
        );
    }
    assert_eq!(
        pool_shard_amount(1),
        2,
        "an explicit override of one must round up in the helper"
    );
}

#[test]
fn no_caller_carries_a_local_shard_count_workaround() {
    for (path, text) in production_sources() {
        for (index, line) in text.lines().enumerate() {
            let lowered = line.to_lowercase();
            let clamps_a_shard_local = lowered.contains("shard") && lowered.contains(".max(2)");
            let clamps_the_helper = line.contains("pool_shard_amount(") && line.contains(".max(");
            assert!(
                !clamps_a_shard_local && !clamps_the_helper,
                "{path}:{} clamps a shard count at the call site; correct \
                 `crate::util::sharding::pool_shard_amount` instead so one rule lives in one \
                 place (#4785): {line}",
                index + 1
            );
        }
    }
}

#[test]
fn the_stream_throttle_shard_count_comes_from_the_shared_helper() {
    let throttle = source("src/plugins/tcp_connection_throttle.rs");
    assert!(
        throttle.contains("crate::util::sharding::pool_shard_amount(pool_shard_amount)"),
        "tcp_connection_throttle must size its map through the shared helper"
    );
    assert!(
        !throttle.contains(".max(2)"),
        "the local minimum workaround must stay deleted"
    );
}

// ---------------------------------------------------------------------------
// (h) The SVID generation segment matcher matches a DELIMITED segment
//
// #4768: the matcher assumed `|svidg=N` was terminal. The reqwest pool later
// appended an `|rcfg=…` suffix, which silently disabled rotation draining for
// that one pool family.
// ---------------------------------------------------------------------------

const SVID_GENERATION: u64 = 7;

fn svid_parity_proxy() -> Proxy {
    let mut proxy = serde_json::from_value::<Proxy>(json!({
        "id": "svid-parity",
        "namespace": "default",
        "hosts": [],
        "listen_path": "/parity",
        "backend_scheme": "https",
        "backend_host": "backend.example.com",
        "backend_port": 8443
    }))
    .expect("parity proxy must deserialize");
    proxy.resolved_tls.client_cert_path = Some("/var/run/ferrum/svid.pem".to_string());
    proxy.resolved_tls.client_key_path = Some("/var/run/ferrum/svid.key".to_string());
    proxy
}

fn svid_generation_pool() -> ConnectionPool {
    let env_config = EnvConfig {
        gateway_svid_cert_path: Some("/var/run/ferrum/svid.pem".to_string()),
        gateway_svid_key_path: Some("/var/run/ferrum/svid.key".to_string()),
        ..Default::default()
    };
    ConnectionPool::new_with_svid_generation(
        PoolConfig::default(),
        env_config,
        DnsCache::new(DnsConfig::default()),
        None,
        Arc::new(Vec::new()),
        Arc::new(AtomicU64::new(SVID_GENERATION)),
    )
}

#[tokio::test]
async fn every_pool_family_key_is_drained_by_the_svid_generation_matcher() {
    let proxy = svid_parity_proxy();
    let global = PoolConfig::default();

    // The H3 static helper builds a key with no workload SVID in scope; its
    // layout is what matters here, so take the real key and substitute the
    // generation token the runtime path would have written.
    let h3_static = Http3ConnectionPool::pool_key(&proxy, 0);
    assert!(
        h3_static.ends_with("|svidg=static"),
        "the H3 pool key must end at the SVID generation field: {h3_static}"
    );
    let h3 = h3_static.replace("|svidg=static", &format!("|svidg={SVID_GENERATION}"));

    let reqwest = svid_generation_pool().pool_key_for_warmup(&proxy);
    assert!(
        reqwest.contains(&format!("|svidg={SVID_GENERATION}|rcfg=")),
        "the reqwest pool key must carry the client-behavior suffix AFTER the generation — the \
         exact shape that broke the matcher in #4768: {reqwest}"
    );

    // (family label, unsharded key, whether the family appends a `#shard`)
    let families: &[(&str, String, bool)] = &[
        ("reqwest", reqwest, false),
        (
            "direct H2",
            Http2ConnectionPool::pool_key_with_global(&proxy, Some(SVID_GENERATION), &global),
            true,
        ),
        (
            "native gRPC",
            GrpcConnectionPool::pool_key_with_global(&proxy, Some(SVID_GENERATION), &global),
            true,
        ),
        ("HTTP/3", h3, false),
    ];

    let matcher = SvidGenerationMatcher::new(SVID_GENERATION);
    for (label, key, sharded) in families {
        assert!(
            matcher.matches(key),
            "{label} pool key must be drained by the SVID generation matcher: {key}"
        );
        assert!(
            !SvidGenerationMatcher::new(70).matches(key),
            "{label}: generation 70 must not match generation 7 by numeric prefix: {key}"
        );

        // Order independence (issue #4792 proposal item 3): appending a future
        // field must not disable the matcher, which is exactly how the reqwest
        // family lost its drain.
        let extended = format!("{key}|future=1");
        assert!(
            matcher.matches(&extended),
            "{label}: appending a future pool-key field must not disable the drain: {extended}"
        );

        if *sharded {
            for shard in ["#0", "#12"] {
                let sharded_key = format!("{key}{shard}");
                assert!(
                    matcher.matches(&sharded_key),
                    "{label}: the sharded lookup key must still drain: {sharded_key}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Declared response Content-Length ceiling skips bodyless replies (issue #5116)
//
// A representation Content-Length on HEAD / 1xx / 204 / 205 / 304 is not a
// transferable-body size. The shared helper is the single predicate; a sibling
// that compares a parsed Content-Length against the response ceiling without
// going through it reintroduces the 502.
// ---------------------------------------------------------------------------

#[test]
fn response_content_length_ceiling_skips_bodyless_semantics_on_every_path() {
    let proxy = source("src/proxy/mod.rs");
    let helper = item_body(
        &proxy,
        "pub(crate) fn declared_response_length_exceeds_limit(",
        "\n}",
    );
    assert!(
        helper.contains("synthetic_response_omits_body(method, status)"),
        "the shared declared-length ceiling must skip HEAD/1xx/204/205/304"
    );

    for relative in [
        "src/proxy/mod.rs",
        "src/http3/server.rs",
        "src/http3/cross_protocol.rs",
    ] {
        assert!(
            source(relative).contains("declared_response_length_exceeds_limit("),
            "{relative} must run the shared declared-length ceiling"
        );
    }

    for (path, text) in production_sources() {
        assert!(
            !text.contains(
                "&& let Some(len) = content_length\n                && len > effective_max_response_body_size_bytes"
            ),
            "{path} compared a parsed Content-Length against the response ceiling \
             without the bodyless-aware helper"
        );
        assert!(
            !text.contains(
                "&& let Some(len) = content_length\n        && len > effective_max_response_body_size_bytes"
            ),
            "{path} compared a parsed Content-Length against the response ceiling \
             without the bodyless-aware helper"
        );
        assert!(
            !text.contains(
                "content_length.is_some_and(|len| len > effective_max_response_body_size_bytes as u64)"
            ),
            "{path} compared a parsed Content-Length against the response ceiling \
             without the bodyless-aware helper"
        );
    }
}
