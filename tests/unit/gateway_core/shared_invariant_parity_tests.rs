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

#[test]
fn every_startup_failure_site_renders_the_sanitized_cause_chain() {
    let entry = source("src/gateway_entry.rs");
    let diagnostics: Vec<&str> = entry
        .split("error!(")
        .skip(1)
        .map(|invocation| invocation.split(';').next().unwrap())
        .collect();

    for sibling in [
        "Validation error:",
        "Configuration error:",
        "Failed to create tokio runtime:",
        "Failed to initialize the admin audit pipeline:",
        "Failed to register SIGTERM handler:",
        "Failed to register SIGINT handler:",
        "Failed to await Ctrl+C notification:",
        "Failed to register SIGHUP handler:",
        "Fatal error:",
        "FIPS verification failed:",
        "Ambient UDP node preflight failed:",
    ] {
        assert!(
            diagnostics.iter().any(|site| site.contains(sibling)),
            "startup diagnostic inventory lost {sibling}"
        );
    }
    for diagnostic in diagnostics {
        assert!(
            diagnostic.contains("render_startup_error("),
            "startup errors must share cause-chain rendering and redaction: {diagnostic}"
        );
    }
    assert!(
        item_body(&entry, "fn emit_bootstrap_error(", "\n}\n").contains("render_startup_error("),
        "bootstrap failures bypass tracing and must use the same redaction boundary"
    );
}

#[test]
fn startup_redaction_never_derives_database_tls_urls() {
    let entry = source("src/gateway_entry.rs");
    for derivation in [
        "effective_db_url",
        "effective_db_read_replica_url",
        "effective_db_failover_urls",
    ] {
        assert!(
            !entry.contains(derivation),
            "diagnostic inventory must not fetch or persist TLS material: {derivation}"
        );
    }
    for raw_url in [".db_url", ".db_read_replica_url", ".db_failover_urls"] {
        assert!(entry.contains(raw_url), "redaction lost {raw_url}");
    }
}

// ---------------------------------------------------------------------------
// Shared source-inventory helpers
// ---------------------------------------------------------------------------

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn database_tls_snapshot_and_reload_cover_all_sql_consumers() {
    let loader = source("src/config/db_loader.rs");
    assert!(loader.contains("snapshot.pin(options)"));
    // The backup-bootstrap pool snapshots best-effort: it pins the snapshot
    // when the material is readable and otherwise starts from the unmodified
    // URL, so the first successful reconnect restores the retained-material
    // guarantee instead of the gateway failing to come up.
    let offline = item_body(
        &loader,
        "pub async fn connect_offline_with_pool_config(",
        "\n    }",
    );
    assert!(offline.contains("build_pool_options_from_config(&pool_config, db_type)"));
    assert!(offline.contains("Ok(snapshot) => snapshot.pin(options)"));
    assert!(offline.contains("(options, db_url.to_string())"));
    assert!(offline.contains("SqlTlsSnapshot::load_detached("));
    assert!(offline.contains("await_pool_connect_with_timeout("));
    assert!(!offline.contains("SqlTlsSnapshot::load("));
    for path in ["src/modes/database.rs", "src/modes/control_plane.rs"] {
        let mode = source(path);
        assert!(mode.contains("start_db_tls_reload_task("), "{path}");
    }
    let migrate = source("src/modes/migrate.rs");
    // Floor, not an exact count: two production call sites plus the in-crate
    // SQLite pragma test. A new migrate pool must not bypass the helper, but
    // adding one must not need this number edited.
    assert!(
        migrate.matches("connect_any_pool_with_timeout(").count() >= 3,
        "every migrate SQL pool must be opened through connect_any_pool_with_timeout"
    );
    for caller in ["async fn run_db_migrations(", "async fn show_db_status("] {
        let body = item_body(&migrate, caller, "\n}");
        assert!(body.contains("connect_any_pool_with_timeout("), "{caller}");
    }
    assert!(source("src/modes/db_tls_reload.rs").contains("db.reconnect_tls("));
    let env = source("src/config/env_config.rs");
    let source_value = item_body(&env, "fn db_tls_source_param_value(", "\n    }");
    assert!(!source_value.contains("load_material"));
    assert!(!source_value.contains("tempfile"));
    let secondary = item_body(&env, "pub async fn connect_lazy(", "\n    }");
    assert!(secondary.contains("SqlTlsSnapshot::load_detached("));
    assert!(secondary.contains("snapshot.pin(options)"));
    let audit = source("custom_plugins/examples/example_audit_plugin.rs");
    assert!(audit.contains(".connect_lazy(self.options.clone(), 5)"));
    assert!(!audit.contains(".connect_lazy(&backend.effective_url)"));
    for caller in [
        "pub async fn connect_with_pool_config(",
        "pub async fn connect_with_failover(",
        "async fn reconnect_for_topology(",
        "async fn reconnect_tls_pools(",
        "pub async fn connect_read_replica(",
        "pub async fn reconnect_read_replica(",
    ] {
        let body = item_body(&loader, caller, "\n    }");
        assert!(
            body.contains("connect_any_pool_with_timeout(")
                || body.contains("Self::connect_with_pool_config("),
            "{caller}"
        );
    }
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

// ---------------------------------------------------------------------------
// Docker-backed fixtures publish pinned, non-ephemeral host ports (issue #5488)
//
// Siblings: the service-integration fixtures (Consul, OpenLDAP, Redpanda,
// MySQL, ClickHouse, Hydra — issue #3999) and the secret-backend fixtures
// (Vault dev server, LocalStack). Docker auto-assignment draws the published
// port from the host's ephemeral source-port range, so a mapping can collide
// with the test process's own outbound sockets, and a port released by one
// case's container is immediately reusable by the next case in the same
// process. Both fixture families must allocate through `common/host_ports.rs`
// and map the port explicitly instead of reading back what Docker chose.
// ---------------------------------------------------------------------------

/// Every fixture module that starts a container publishing a host port.
const CONTAINER_FIXTURE_SOURCES: [&str; 3] = [
    "tests/service_integration/common/containers.rs",
    "tests/service_integration/common/hydra.rs",
    "tests/secrets_functional/common/containers.rs",
];

#[test]
fn docker_fixtures_pin_host_ports_outside_the_ephemeral_range() {
    for relative in CONTAINER_FIXTURE_SOURCES {
        let text = source(relative);
        assert!(
            text.contains("allocate_host_port") && text.contains("retry_on_host_port_collision"),
            "{relative} must take its host ports from common/host_ports.rs and retry only \
             genuine bind collisions"
        );
        assert!(
            !text.contains("get_host_port_ipv4"),
            "{relative} must not read back a Docker-assigned host port; map it explicitly"
        );
        let images = text.matches("GenericImage::new(").count();
        let mapped = text.matches(".with_mapped_port(").count();
        assert!(
            images > 0 && mapped >= images,
            "{relative}: every started image must publish an explicitly mapped host port \
             ({images} images, {mapped} mappings)"
        );
    }
}

// ---------------------------------------------------------------------------
// Object-valued admin admission fields reject positional sequences
// ---------------------------------------------------------------------------
//
// Invariant: a field documented as an object must not accept a JSON array.
// serde's derived struct visitors implement `visit_seq`, so an array is
// silently read as a *positional* construction — every element fills the next
// declared field and a short array leaves the rest at their `#[serde(default)]`
// values. `[]` therefore became a fully default-constructed object. That is the
// same root cause as the `POST /restore` envelope accepting `[]` and committing
// a destructive empty restore (issue #5538); the nested resource fields listed
// in that issue (`circuit_breaker`, `retry`, `health_checks`,
// `hash_on_cookie_config`) are its siblings, and the remaining object-valued
// optional fields on the same three admin resource structs carry it too.
//
// Siblings: `Proxy::{circuit_breaker, retry, stream_match}`,
// `Upstream::{hash_on_cookie_config, health_checks, service_discovery,
// locality_lb_setting}`, and `PluginConfig::trigger`. The envelope boundaries
// themselves (`POST /restore`, `POST /batch`, and the generic admin resource
// write path) go through `util::json_object::from_json_object_slice`, which is
// asserted structurally below.

/// `(struct, field, one valid object value)` for every field whose
/// deserialization must reject a sequence.
const OBJECT_ONLY_RESOURCE_FIELDS: [(&str, &str, &str); 8] = [
    ("Proxy", "circuit_breaker", "{}"),
    ("Proxy", "retry", "{}"),
    ("Proxy", "stream_match", "{}"),
    ("Upstream", "hash_on_cookie_config", "{}"),
    ("Upstream", "health_checks", "{}"),
    ("Upstream", "service_discovery", r#"{"provider":"dns_sd"}"#),
    ("Upstream", "locality_lb_setting", "{}"),
    (
        "PluginConfig",
        "trigger",
        r#"{"when":{"match":{"method":["GET"]}}}"#,
    ),
];

/// Minimal valid body for each resource struct the table covers.
fn object_only_resource_base(resource: &str) -> serde_json::Value {
    match resource {
        "Proxy" => json!({
            "id": "object-only",
            "listen_path": "/object-only",
            "backend_host": "127.0.0.1",
            "backend_port": 8080,
        }),
        "Upstream" => json!({"id": "object-only", "name": "object-only", "targets": []}),
        "PluginConfig" => json!({
            "id": "object-only",
            "plugin_name": "cors",
            "scope": "global",
        }),
        other => panic!("unmapped resource struct {other}"),
    }
}

/// Deserialize `body` as the named resource struct, reporting only success.
fn object_only_resource_accepts(resource: &str, body: &serde_json::Value) -> bool {
    match resource {
        "Proxy" => {
            serde_json::from_value::<ferrum_edge::config::types::Proxy>(body.clone()).is_ok()
        }
        "Upstream" => {
            serde_json::from_value::<ferrum_edge::config::types::Upstream>(body.clone()).is_ok()
        }
        "PluginConfig" => {
            serde_json::from_value::<ferrum_edge::config::types::PluginConfig>(body.clone()).is_ok()
        }
        other => panic!("unmapped resource struct {other}"),
    }
}

#[test]
fn object_valued_resource_fields_reject_sequences_and_keep_null() {
    for (resource, field, valid_object) in OBJECT_ONLY_RESOURCE_FIELDS {
        let mut sequence = object_only_resource_base(resource);
        sequence[field] = json!([]);
        assert!(
            !object_only_resource_accepts(resource, &sequence),
            "{resource}.{field} must reject an array instead of default-constructing an object"
        );

        let mut nonempty_sequence = object_only_resource_base(resource);
        nonempty_sequence[field] = json!([1, 2, 3]);
        assert!(
            !object_only_resource_accepts(resource, &nonempty_sequence),
            "{resource}.{field} must reject a positional sequence"
        );

        let mut scalar = object_only_resource_base(resource);
        scalar[field] = json!("not-an-object");
        assert!(
            !object_only_resource_accepts(resource, &scalar),
            "{resource}.{field} must reject a scalar"
        );

        // The documented forms still work: absent, explicit null, and a valid
        // object value.
        let absent = object_only_resource_base(resource);
        assert!(
            object_only_resource_accepts(resource, &absent),
            "{resource} must still deserialize with {field} absent"
        );
        let mut null = object_only_resource_base(resource);
        null[field] = serde_json::Value::Null;
        assert!(
            object_only_resource_accepts(resource, &null),
            "{resource}.{field} must still accept an explicit null"
        );
        let mut object = object_only_resource_base(resource);
        object[field] = serde_json::from_str(valid_object)
            .unwrap_or_else(|error| panic!("{resource}.{field} sample parses: {error}"));
        assert!(
            object_only_resource_accepts(resource, &object),
            "{resource}.{field} must still accept an object"
        );
    }
}

/// Fields on the admin resource structs that the table above does not list but
/// that would silently accept a positional sequence.
///
/// Structural, so a newly added object-valued optional field fails the build
/// rather than shipping the gap. A field is a candidate when its type is a
/// plain (non-generic) struct declared in `config/types.rs`, or one of the
/// out-of-module struct types those resources embed. `#[serde(skip)]` fields
/// are derived state that never crosses the wire.
#[test]
fn every_object_valued_admin_resource_field_carries_the_guard() {
    let types = source("src/config/types.rs");

    let mut struct_names: BTreeSet<&str> = types
        .lines()
        .filter_map(|line| line.trim().strip_prefix("pub struct "))
        .map(|rest| {
            rest.split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .next()
                .unwrap_or("")
        })
        .filter(|name| !name.is_empty())
        .collect();
    // Struct-typed fields whose definition lives outside `config/types.rs`.
    struct_names.insert("PluginTrigger");
    struct_names.insert("StreamMatchCriteria");

    for resource in ["Proxy", "Upstream", "PluginConfig"] {
        let header = format!("pub struct {resource} {{");
        let start = types
            .find(&header)
            .unwrap_or_else(|| panic!("{resource} must be declared in config/types.rs"));
        let body = &types[start..];
        let end = body
            .find("\n}\n")
            .unwrap_or_else(|| panic!("{resource} declaration must terminate"));
        let body = &body[..end];

        // Attributes accumulate until the field they decorate.
        let mut attributes = String::new();
        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("///") || trimmed.starts_with("//") || trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with('#') || (!attributes.is_empty() && !trimmed.contains("pub ")) {
                attributes.push_str(trimmed);
                continue;
            }
            let Some(declaration) = trimmed.strip_prefix("pub ") else {
                attributes.clear();
                continue;
            };
            let Some((field, type_text)) = declaration.split_once(": ") else {
                attributes.clear();
                continue;
            };
            let type_text = type_text.trim_end_matches(',');
            let is_candidate = type_text
                .strip_prefix("Option<")
                .and_then(|inner| inner.strip_suffix('>'))
                .filter(|inner| !inner.contains('<'))
                .map(|inner| inner.rsplit("::").next().unwrap_or(inner))
                .is_some_and(|inner| struct_names.contains(inner));
            if is_candidate && !attributes.contains("skip)") && !attributes.contains("skip,") {
                assert!(
                    attributes.contains("json_object::deserialize_optional_object"),
                    "{resource}.{field} is object-valued and must use \
                     `util::json_object::deserialize_optional_object`, or a JSON array \
                     silently default-constructs it (issue #5538). Add it to \
                     OBJECT_ONLY_RESOURCE_FIELDS as well."
                );
                assert!(
                    OBJECT_ONLY_RESOURCE_FIELDS
                        .iter()
                        .any(
                            |(table_resource, table_field, _)| *table_resource == resource
                                && *table_field == field
                        ),
                    "{resource}.{field} carries the object-only guard but is missing from \
                     OBJECT_ONLY_RESOURCE_FIELDS"
                );
            }
            attributes.clear();
        }
    }
}

/// The typed admin body boundaries all parse through the object-only helper.
#[test]
fn admin_typed_body_boundaries_require_a_json_object_envelope() {
    for (relative, context) in [
        ("src/admin/mod.rs", "POST /restore and POST /batch"),
        ("src/admin/crud.rs", "the generic admin resource write path"),
    ] {
        let text = source(relative);
        assert!(
            text.contains("json_object::from_json_object_slice"),
            "{relative} ({context}) must parse typed request bodies through \
             `util::json_object::from_json_object_slice` so a JSON array cannot be read as a \
             positionally/defaults-constructed value (issue #5538)"
        );
    }
}

// The original three-resource check above remains the regression table for
// #5538. This source inventory scans ALL Rust files recursively under src/ for
// derived Deserialize structs/enums, including private wire and persisted types.
// It covers named struct fields (direct, Option, Box), Vec<Struct> and
// Option<Vec<Struct>> elements, and newtype enum variants carrying a named
// struct. Named fields inside enum struct variants are also checked; the
// variant payload itself is NOT guarded by that field check. Enum elements,
// map values, tuples, aliases, arbitrary wrapper nesting, hand-written
// deserializers and raw serde_json::Value boundaries are not discovered here.
// Separate behavioral/boundary tests cover the raw-Value sites changed here.
// Skipped runtime fields are not JSON inputs. Scalar identity parsers and
// field-specific exceptions below must justify why they remain outside this
// admission change. File-backed records are inputs, even when Ferrum wrote them.

/// Field-specific exceptions, never a blanket exception for a config type.
/// These identify internal records, response-only types, remote responses, and
/// non-collection Kubernetes envelopes outside admin/config admission. An
/// exception is a scope decision, not proof that a deserializer rejects arrays.
/// Custom scalar identity types are checked separately against their parser.
const OBJECT_ADMISSION_EXCEPTIONS: &[(&str, &str, &str, &str)] = &[
    (
        "src/modes/mesh/config.rs",
        "MeshEgressUdpDestination",
        "dial_endpoints",
        "Runtime-only allowlist; MeshConfig.egress_udp_destinations is serde(skip).",
    ),
    (
        "src/modes/mesh/federation.rs",
        "NativeFederationBundle",
        "jwt_authorities",
        "Remote federation response, like JwksResponse.keys; not local trust configuration.",
    ),
    (
        "src/modes/mesh/federation.rs",
        "SpiffeJwksDocument",
        "keys",
        "Remote SPIFFE JWKS response, like JwksResponse.keys; not local trust configuration.",
    ),
    (
        "src/modes/mesh/federation.rs",
        "FederationDocument",
        "Native",
        "Remote federation envelope; same scope as NativeFederationBundle.jwt_authorities.",
    ),
    (
        "src/modes/mesh/federation.rs",
        "FederationDocument",
        "SpiffeJwks",
        "Remote SPIFFE JWKS response envelope; same scope as SpiffeJwksDocument.keys.",
    ),
    (
        "src/tls/acme.rs",
        "AcmeOrderRecord",
        "http01_challenges",
        "Persisted CA-order state, read from Ferrum's ACME store; not admin request configuration.",
    ),
    (
        "src/tls/acme.rs",
        "AcmeOrderRecord",
        "tls_alpn01_challenges",
        "Persisted CA-order state, read from Ferrum's ACME store; not admin request configuration.",
    ),
    (
        "src/tls/acme.rs",
        "AcmeOrderRecord",
        "dns01_challenges",
        "Persisted CA-order state, read from Ferrum's ACME store; not admin request configuration.",
    ),
    (
        "src/tls/acme.rs",
        "AcmeOrderRecord",
        "finalization",
        "Persisted generated key/CSR state in the ACME store; not admin request configuration.",
    ),
    (
        "src/tls/events.rs",
        "TlsSourceEvent",
        "sources",
        "Persisted rotation diagnostics, read from Ferrum's event log; not configuration.",
    ),
    (
        "src/tls/events.rs",
        "TlsEventLogFile",
        "events",
        "Persisted rotation diagnostics, read from Ferrum's event log; not configuration.",
    ),
    (
        "src/config_sources/k8s/mod.rs",
        "K8sObject",
        "metadata",
        "Kubernetes API object metadata; a non-collection input outside admin JSON admission.",
    ),
    (
        "src/modes/injector.rs",
        "AdmissionReview",
        "request",
        "Kubernetes webhook request envelope; a non-collection input outside admin JSON admission.",
    ),
    (
        "src/modes/injector.rs",
        "AdmissionRequest",
        "kind",
        "Kubernetes webhook kind metadata; a non-collection input outside admin JSON admission.",
    ),
    (
        "src/modes/injector.rs",
        "AdmissionRequest",
        "resource",
        "Kubernetes webhook resource metadata; non-collection input outside admin JSON admission.",
    ),
    (
        "src/proxy/udp_placement_migration.rs",
        "NodeAttestation",
        "node",
        "Node-local persisted preflight proof; not an admin or mesh configuration document.",
    ),
    (
        "src/proxy/udp_placement_migration.rs",
        "PendingMigration",
        "transition",
        "Node-local persisted placement lifecycle state; not admin or mesh configuration.",
    ),
    (
        "src/proxy/udp_placement_migration.rs",
        "DurablePlacementState",
        "pending",
        "Node-local persisted placement lifecycle state; not admin or mesh configuration.",
    ),
    (
        "src/proxy/udp_placement_migration.rs",
        "DurablePlacementState",
        "completed",
        "Node-local persisted placement lifecycle state; not admin or mesh configuration.",
    ),
    (
        "src/proxy/udp_placement_migration.rs",
        "DurablePlacementState",
        "incarnation",
        "Node-local persisted node-incarnation binding; not admin or mesh configuration.",
    ),
    (
        "src/admin/mesh_remote_clusters.rs",
        "MeshRemoteClustersResponse",
        "discovered",
        "Response-only diagnostics; no admin request deserializes this type.",
    ),
    (
        "src/admin/mesh_remote_clusters.rs",
        "MeshRemoteClustersResponse",
        "configured",
        "Response-only diagnostics; no admin request deserializes this type.",
    ),
    (
        "src/plugins/utils/jwks_store.rs",
        "JwksResponse",
        "keys",
        "Remote JWKS response, not plugin configuration or a gateway trust bundle.",
    ),
    (
        "src/admin/audit_spool.rs",
        "SpooledAuditRecord",
        "event",
        "Private audit spool record, read from the gateway's own spool, not an admin body.",
    ),
    (
        "src/plugins/request_deduplication.rs",
        "SerializableCachedResponse",
        "response_policy",
        "Private cached response provenance, not plugin configuration.",
    ),
    (
        "src/plugins/request_deduplication.rs",
        "SerializableDedupRecord",
        "replay",
        "Private Redis deduplication record, not plugin configuration.",
    ),
];

/// Baseline field keys make a discovery regression actionable even if newly
/// discovered fields keep the total count above its floor. Discovery still
/// checks additions without requiring them to be listed here first.
const EXPECTED_OBJECT_ADMISSION_FIELDS: &[&str] = &[
    "src/admin/api_specs/external_refs.rs:ExternalRefSnapshot.documents",
    "src/admin/backup.rs:ApiSpecsBackupSection.items",
    "src/admin/backup.rs:BatchCreateRequest._gateway_trust_bundles",
    "src/admin/backup.rs:BatchCreateRequest.consumers",
    "src/admin/backup.rs:BatchCreateRequest.plugin_configs",
    "src/admin/backup.rs:BatchCreateRequest.proxies",
    "src/admin/backup.rs:BatchCreateRequest.upstreams",
    "src/admin/backup.rs:RestorePayload.consumers",
    "src/admin/backup.rs:RestorePayload.gateway_trust_bundles",
    "src/admin/backup.rs:RestorePayload.plugin_configs",
    "src/admin/backup.rs:RestorePayload.proxies",
    "src/admin/backup.rs:RestorePayload.upstreams",
    "src/cni/ownership.rs:DurableCniOwnershipDocument.attachments",
    "src/cni/ownership.rs:DurableCniOwnershipRecord.cleanup",
    "src/cni/rpc.rs:WireRequest.valid_attachments",
    "src/cni/spec.rs:CniNetConfig.ferrum",
    "src/cni/spec.rs:CniNetConfig.valid_attachments",
    "src/config/db_backend.rs:IncrementalResultDe.added_or_modified_consumers",
    "src/config/db_backend.rs:IncrementalResultDe.added_or_modified_plugin_configs",
    "src/config/db_backend.rs:IncrementalResultDe.added_or_modified_proxies",
    "src/config/db_backend.rs:IncrementalResultDe.added_or_modified_upstreams",
    "src/config/db_backend.rs:IncrementalResultDe.removed_plugin_config_keys",
    "src/config/db_backend.rs:IncrementalResultDe.removed_proxy_keys",
    "src/config/db_backend.rs:IncrementalResultDe.removed_upstream_keys",
    "src/config/plugin_trigger.rs:PluginTriggerNode.all",
    "src/config/plugin_trigger.rs:PluginTriggerNode.any",
    "src/config/types.rs:GatewayConfig.consumers",
    "src/config/types.rs:GatewayConfig.frontend_tls_certificate_sources",
    "src/config/types.rs:GatewayConfig.plugin_configs",
    "src/config/types.rs:GatewayConfig.proxies",
    "src/config/types.rs:GatewayConfig.upstreams",
    "src/config/types.rs:Proxy.plugins",
    "src/config/types.rs:Upstream.subsets",
    "src/config/types.rs:Upstream.targets",
    "src/config/types.rs:UpstreamLocalityLbSetting.distribute",
    "src/config/types.rs:UpstreamLocalityLbSetting.failover",
    "src/grpc/cp_trust.rs:TrustBundleDocument.keys",
    "src/modes/mesh/app_probe.rs:AppProbeHttpGet.http_headers",
    "src/modes/mesh/app_probe.rs:AppProbeSpec.grpc",
    "src/modes/mesh/app_probe.rs:AppProbeSpec.http_get",
    "src/modes/mesh/app_probe.rs:AppProbeSpec.tcp_socket",
    "src/modes/mesh/config.rs:MeshConfig.destination_rules",
    "src/modes/mesh/config.rs:MeshConfig.ext_authz_providers",
    "src/modes/mesh/config.rs:MeshConfig.extension_configs",
    "src/modes/mesh/config.rs:MeshConfig.mesh_policies",
    "src/modes/mesh/config.rs:MeshConfig.peer_authentications",
    "src/modes/mesh/config.rs:MeshConfig.proxy_configs",
    "src/modes/mesh/config.rs:MeshConfig.request_authentications",
    "src/modes/mesh/config.rs:MeshConfig.service_entries",
    "src/modes/mesh/config.rs:MeshConfig.services",
    "src/modes/mesh/config.rs:MeshConfig.sidecars",
    "src/modes/mesh/config.rs:MeshConfig.telemetry_resources",
    "src/modes/mesh/config.rs:MeshConfig.virtual_service_cors_policies",
    "src/modes/mesh/config.rs:MeshConfig.waypoint_bindings",
    "src/modes/mesh/config.rs:MeshConfig.workloads",
    "src/modes/mesh/config.rs:MeshDestinationRule.subsets",
    "src/modes/mesh/config.rs:MeshExtAuthzProvider.include_additional_headers_in_check",
    "src/modes/mesh/config.rs:MeshJwtRule.from_headers",
    "src/modes/mesh/config.rs:MeshJwtRule.output_claim_to_headers",
    "src/modes/mesh/config.rs:MeshLocalityLbSetting.distribute",
    "src/modes/mesh/config.rs:MeshLocalityLbSetting.failover",
    "src/modes/mesh/config.rs:MeshMetricsConfig.tag_overrides",
    "src/modes/mesh/config.rs:MeshPolicy.rules",
    "src/modes/mesh/config.rs:MeshRequestAuthentication.jwt_rules",
    "src/modes/mesh/config.rs:MeshRule.from",
    "src/modes/mesh/config.rs:MeshRule.to",
    "src/modes/mesh/config.rs:MeshRule.when",
    "src/modes/mesh/config.rs:MeshService.ports",
    "src/modes/mesh/config.rs:MeshService.workloads",
    "src/modes/mesh/config.rs:MeshSidecar.egress",
    "src/modes/mesh/config.rs:MeshSidecar.ingress",
    "src/modes/mesh/config.rs:MeshWaypointBinding.services",
    "src/modes/mesh/config.rs:MultiClusterConfig.east_west_gateways",
    "src/modes/mesh/config.rs:MultiClusterConfig.remote_clusters",
    "src/modes/mesh/config.rs:ServiceEntry.endpoints",
    "src/modes/mesh/config.rs:ServiceEntry.ports",
    "src/modes/mesh/config.rs:TrustBundle.jwt_authorities",
    "src/modes/mesh/config.rs:TrustBundleSet.federated",
    "src/modes/mesh/config.rs:Workload.ports",
    "src/modes/mesh/slice.rs:MeshEgressScopeSnapshot.destination_rules",
    "src/modes/mesh/slice.rs:MeshEgressScopeSnapshot.service_entries",
    "src/modes/mesh/slice.rs:MeshEgressScopeSnapshot.services",
    "src/modes/mesh/slice.rs:MeshSlice.ambient_udp_source_workloads",
    "src/modes/mesh/slice.rs:MeshSlice.destination_rules",
    "src/modes/mesh/slice.rs:MeshSlice.ext_authz_providers",
    "src/modes/mesh/slice.rs:MeshSlice.extension_configs",
    "src/modes/mesh/slice.rs:MeshSlice.local_inbound_services",
    "src/modes/mesh/slice.rs:MeshSlice.local_inbound_workloads",
    "src/modes/mesh/slice.rs:MeshSlice.local_ingress_listeners",
    "src/modes/mesh/slice.rs:MeshSlice.mesh_policies",
    "src/modes/mesh/slice.rs:MeshSlice.node_waypoint_assertors",
    "src/modes/mesh/slice.rs:MeshSlice.node_waypoint_capture_destinations",
    "src/modes/mesh/slice.rs:MeshSlice.node_waypoint_capture_peer_authentications",
    "src/modes/mesh/slice.rs:MeshSlice.peer_authentications",
    "src/modes/mesh/slice.rs:MeshSlice.proxy_configs",
    "src/modes/mesh/slice.rs:MeshSlice.request_authentications",
    "src/modes/mesh/slice.rs:MeshSlice.service_entries",
    "src/modes/mesh/slice.rs:MeshSlice.service_waypoint_bound_services",
    "src/modes/mesh/slice.rs:MeshSlice.services",
    "src/modes/mesh/slice.rs:MeshSlice.telemetry_resources",
    "src/modes/mesh/slice.rs:MeshSlice.virtual_service_cors_policies",
    "src/modes/mesh/slice.rs:MeshSlice.workloads",
    "src/plugins/mesh/authz.rs:NodeWaypointRouteUpstreamConfig.targets",
    "src/plugins/mesh_route_dispatch.rs:MeshRouteDispatchConfig.rules",
    "src/plugins/mesh_route_dispatch.rs:RouteRule.request_transform",
    "src/plugins/mesh_route_dispatch.rs:RouteRule.response_transform",
    "src/proxy/stream_match.rs:StreamMatchCriteria.arms",
    "src/admin/backup.rs:RestorePayload.api_specs",
    "src/config/gateway_trust.rs:GatewayTrustBundleRecord.bundle",
    "src/config/plugin_trigger.rs:PluginTrigger.when",
    "src/config/plugin_trigger.rs:PluginTriggerFieldMatch.value",
    "src/config/plugin_trigger.rs:PluginTriggerIdentityMatch.value",
    "src/config/plugin_trigger.rs:PluginTriggerMatch.consumer",
    "src/config/plugin_trigger.rs:PluginTriggerMatch.cookie",
    "src/config/plugin_trigger.rs:PluginTriggerMatch.header",
    "src/config/plugin_trigger.rs:PluginTriggerMatch.host",
    "src/config/plugin_trigger.rs:PluginTriggerMatch.path",
    "src/config/plugin_trigger.rs:PluginTriggerMatch.query",
    "src/config/plugin_trigger.rs:PluginTriggerMatch.sni",
    "src/config/plugin_trigger.rs:PluginTriggerMatch.spiffe_id",
    "src/config/plugin_trigger.rs:PluginTriggerNode.match_",
    "src/config/plugin_trigger.rs:PluginTriggerNode.not",
    "src/config/types.rs:GatewayConfig.mesh",
    "src/config/types.rs:GatewayConfig.trust_bundles",
    "src/config/types.rs:HealthCheckConfig.active",
    "src/config/types.rs:HealthCheckConfig.passive",
    "src/config/types.rs:PluginConfig.trigger",
    "src/config/types.rs:Proxy.circuit_breaker",
    "src/config/types.rs:Proxy.retry",
    "src/config/types.rs:Proxy.stream_match",
    "src/config/types.rs:ServiceDiscoveryConfig.consul",
    "src/config/types.rs:ServiceDiscoveryConfig.dns_sd",
    "src/config/types.rs:ServiceDiscoveryConfig.kubernetes",
    "src/config/types.rs:ServiceDiscoveryConfig.mesh",
    "src/config/types.rs:SubsetDefinition.traffic_policy",
    "src/config/types.rs:SubsetTrafficPolicy.passive_health_check",
    "src/config/types.rs:SubsetTrafficPolicy.tls",
    "src/config/types.rs:Upstream.hash_on_cookie_config",
    "src/config/types.rs:Upstream.health_checks",
    "src/config/types.rs:Upstream.locality_lb_setting",
    "src/config/types.rs:Upstream.service_discovery",
    "src/config/types.rs:UpstreamPortOverride.locality_lb_setting",
    "src/config/types.rs:UpstreamPortOverride.passive_health_check",
    "src/config/types.rs:UpstreamPortOverride.tcp_keepalive",
    "src/config/types.rs:UpstreamPortOverride.tls",
    "src/modes/mesh/config.rs:MeshAccessLoggingConfig.filter",
    "src/modes/mesh/config.rs:MeshConfig.multi_cluster",
    "src/modes/mesh/config.rs:MeshConfig.trust_bundles",
    "src/modes/mesh/config.rs:MeshDestinationRule.traffic_policy",
    "src/modes/mesh/config.rs:MeshExtAuthzProvider.include_request_body_in_check",
    "src/modes/mesh/config.rs:MeshRule.source_negation",
    "src/modes/mesh/config.rs:MeshSidecar.workload_selector",
    "src/modes/mesh/config.rs:MeshSubset.traffic_policy",
    "src/modes/mesh/config.rs:MeshTelemetryConfig.access_logging",
    "src/modes/mesh/config.rs:MeshTelemetryConfig.metrics",
    "src/modes/mesh/config.rs:MeshTelemetryConfig.tracing",
    "src/modes/mesh/config.rs:MeshTelemetryResource.config",
    "src/modes/mesh/config.rs:MeshTrafficPolicy.connection_pool_http",
    "src/modes/mesh/config.rs:MeshTrafficPolicy.locality_lb_setting",
    "src/modes/mesh/config.rs:MeshTrafficPolicy.outlier_detection",
    "src/modes/mesh/config.rs:MeshTrafficPolicy.tcp_keepalive",
    "src/modes/mesh/config.rs:MeshTrafficPolicy.tls",
    "src/modes/mesh/config.rs:MeshVirtualServiceCorsPolicy.cors",
    "src/modes/mesh/config.rs:PeerAuthentication.selector",
    "src/modes/mesh/config.rs:PolicyScope.selector",
    "src/modes/mesh/config.rs:ServiceEntry.workload_selector",
    "src/modes/mesh/config.rs:TrustBundleSet.local",
    "src/modes/mesh/config.rs:Workload.node_waypoint",
    "src/modes/mesh/config.rs:Workload.selector",
    "src/modes/mesh/config_consumer/file_source.rs:MeshFileDocument.mesh",
    "src/modes/mesh/slice.rs:MeshSlice.multi_cluster",
    "src/modes/mesh/slice.rs:MeshSlice.revision",
    "src/modes/mesh/slice.rs:MeshSlice.runtime_overlay",
    "src/modes/mesh/slice.rs:MeshSlice.sidecar_egress_scope",
    "src/modes/mesh/slice.rs:MeshSlice.trust_bundles",
    "src/plugins/api_chargeback_sink.rs:ApiChargebackSinkConfig.batch",
    "src/plugins/api_chargeback_sink.rs:ApiChargebackSinkConfig.clickhouse",
    "src/plugins/api_chargeback_sink.rs:ApiChargebackSinkConfig.retry",
    "src/plugins/api_chargeback_sink.rs:ApiChargebackSinkConfig.snapshot",
    "src/plugins/api_chargeback_sink.rs:ApiChargebackSinkConfig.spool",
    "src/plugins/api_chargeback_sink.rs:ClickHouseConfig.tls",
    "src/plugins/mesh_route_dispatch.rs:FaultActionConfig.abort",
    "src/plugins/mesh_route_dispatch.rs:FaultActionConfig.delay",
    "src/plugins/mesh_route_dispatch.rs:RouteDestination.backend_tls",
    "src/plugins/mesh_route_dispatch.rs:RouteRule.destination",
    "src/plugins/mesh_route_dispatch.rs:RouteRule.fault",
    "src/plugins/mesh_route_dispatch.rs:RouteRule.match_",
    "src/plugins/mesh_route_dispatch.rs:RouteRule.redirect",
    "src/plugins/mesh_route_dispatch.rs:RouteRule.retry",
    "src/plugins/mesh_route_dispatch.rs:RouteRule.rewrite",
];

/// Strip comments before interpreting attributes so a comment mentioning a
/// guard or `serde(skip)` can never satisfy the invariant.
fn admission_source_without_line_comments(text: &str) -> String {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn every_nested_admin_struct_field_has_an_object_admission_decision() {
    // Named structs are the serde shape that accepts positional sequences.
    // Include definitions across src/, so an imported or fully qualified
    // struct cannot evade the inventory.
    let declaration =
        regex::Regex::new(r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?struct\s+(\w+)[^{;\n]*\{").unwrap();
    let items = regex::Regex::new(concat!(
        r"(?m)^([ \t]*)#\[derive\(([^)]*)\)\]\s*",
        r"(?:#\[[^\]]*\]\s*)*",
        r"(?:pub(?:\([^)]*\))?\s+)?(struct|enum)\s+(\w+)[^{;]*\{",
    ))
    .unwrap();
    let fields = regex::Regex::new(concat!(
        r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?",
        r"([a-z_]\w*)\s*:\s*([^,]+),",
    ))
    .unwrap();
    let skip = regex::Regex::new(r"\bskip(?:_deserializing)?\b").unwrap();
    let field_attributes = regex::Regex::new(r"(?:#\[[^\]]*\]\s*)+$").unwrap();
    let newtype_variants = regex::Regex::new(concat!(
        r"(?m)^[ \t]*([A-Z]\w*)\(\s*",
        r"((?:#\[[^\]]*\]\s*)*)([\w:]+)\s*,?\s*\)",
    ))
    .unwrap();
    let sources = production_sources();
    let struct_names: BTreeSet<String> = sources
        .iter()
        .flat_map(|(_, text)| {
            declaration
                .captures_iter(text)
                .map(|item| item[1].to_string())
        })
        .collect();
    let mut checked = BTreeSet::new();
    let mut exceptions_seen = BTreeSet::new();

    for (path, text) in &sources {
        let text = admission_source_without_line_comments(text);
        for item in items.captures_iter(&text) {
            if !item[2]
                .split(',')
                .any(|derive| derive.trim().rsplit("::").next() == Some("Deserialize"))
            {
                continue;
            }
            let resource = &item[4];
            let body = &text[item.get(0).unwrap().end()..];
            let terminator = format!("\n{}}}", &item[1]);
            let body = &body[..body.find(&terminator).unwrap_or_else(|| {
                panic!("{path}: {resource} must have a terminated declaration")
            })];
            let mut previous_field_end = 0;
            for field in fields.captures_iter(body) {
                let span = field.get(0).unwrap();
                let attributes = field_attributes
                    .find(&body[previous_field_end..span.start()])
                    .map_or("", |attributes| attributes.as_str());
                previous_field_end = span.end();
                let type_text: String = field[2].split_whitespace().collect();
                let optional = type_text.starts_with("Option<");
                let mut inner = type_text.as_str();
                // Box is transparent to serde. Vec retains its array shape
                // but each named-struct element must require an object.
                for wrapper in ["Option<", "Box<"] {
                    if let Some(wrapped) = inner.strip_prefix(wrapper) {
                        inner = wrapped.strip_suffix('>').unwrap_or(wrapped);
                    }
                }
                let collection = inner.starts_with("Vec<");
                for wrapper in ["Vec<", "Box<"] {
                    if let Some(wrapped) = inner.strip_prefix(wrapper) {
                        inner = wrapped.strip_suffix('>').unwrap_or(wrapped);
                    }
                }
                let name = inner.rsplit("::").next().unwrap_or(inner);
                if inner.contains(['<', '>', '&'])
                    || !struct_names.contains(name)
                    || skip.is_match(attributes)
                {
                    continue;
                }
                if name == "SpiffeId" {
                    // SpiffeId is a hand-written string deserializer, not
                    // a derived struct visitor (TrustDomain is likewise a
                    // string newtype and has no named-field declaration).
                    assert!(
                        source("src/identity/spiffe/id.rs")
                            .contains("let raw = String::deserialize(de)?;")
                    );
                    continue;
                }
                if name == "ParsedCidr" {
                    // CIDRs are strings on the wire despite the named Rust
                    // struct; arrays fail in this custom scalar parser.
                    assert!(
                        item_body(
                            &source("src/modes/mesh/config.rs"),
                            "impl<'de> Deserialize<'de> for ParsedCidr",
                            "\n}",
                        )
                        .contains("String::deserialize(deserializer)?")
                    );
                    continue;
                }
                let field_name = &field[1];
                let key = format!("{path}:{resource}.{field_name}");
                if let Some((_, _, _, reason)) = OBJECT_ADMISSION_EXCEPTIONS.iter().find(
                    |(exception_path, exception_resource, exception_field, _)| {
                        *exception_path == path.as_str()
                            && *exception_resource == resource
                            && *exception_field == field_name
                    },
                ) {
                    assert!(!reason.trim().is_empty(), "{key}: justify the exception");
                    exceptions_seen.insert(key);
                    continue;
                }
                let helper = match (collection, optional) {
                    (true, true) => "json_object::deserialize_optional_object_vec",
                    (true, false) => "json_object::deserialize_object_vec",
                    (false, true) => "json_object::deserialize_optional_object",
                    (false, false) => "json_object::deserialize_object",
                };
                let adapter = match (path.as_str(), resource, field_name) {
                    ("src/plugins/mesh_route_dispatch.rs", "RouteRule", "retry") => {
                        Some("deserialize_route_retry")
                    }
                    ("src/plugins/mesh_route_dispatch.rs", "RouteDestination", "backend_tls") => {
                        Some("deserialize_route_backend_tls")
                    }
                    _ => None,
                };
                if let Some(adapter) = adapter {
                    assert!(
                        attributes.contains(adapter),
                        "{key}: retain the wire adapter"
                    );
                    let signature = format!("fn {adapter}<'de, D>(");
                    assert!(
                        item_body(&text, &signature, "\n}").contains(helper),
                        "{key}: the wire adapter must reject positional arrays"
                    );
                } else {
                    assert!(
                        attributes.contains(helper),
                        "{key} ({type_text}) must use {helper}, or have a field-specific \
                         exception with a justification (issues #5557, #5569)"
                    );
                }
                checked.insert(key);
            }
            if &item[3] == "enum" {
                for variant in newtype_variants.captures_iter(body) {
                    let name = variant[3].rsplit("::").next().unwrap();
                    if struct_names.contains(name) {
                        let key = format!("{path}:{resource}.{}", &variant[1]);
                        if let Some((_, _, _, reason)) = OBJECT_ADMISSION_EXCEPTIONS.iter().find(
                            |(exception_path, exception_resource, exception_variant, _)| {
                                *exception_path == path.as_str()
                                    && *exception_resource == resource
                                    && *exception_variant == &variant[1]
                            },
                        ) {
                            assert!(!reason.trim().is_empty(), "{key}: justify the exception");
                            exceptions_seen.insert(key);
                            continue;
                        }
                        assert!(
                            variant[2].contains("json_object::deserialize_object"),
                            "{path}:{resource}::{} must reject a positional struct payload",
                            &variant[1]
                        );
                    }
                }
            }
        }
    }
    let missing: Vec<_> = EXPECTED_OBJECT_ADMISSION_FIELDS
        .iter()
        .copied()
        .filter(|key| !checked.contains(*key))
        .collect();
    assert!(
        checked.len() >= 150 && missing.is_empty(),
        "the admission inventory must not silently shrink: checked {} fields \
         (minimum 150), expected {} baseline keys, missing: {missing:?}",
        checked.len(),
        EXPECTED_OBJECT_ADMISSION_FIELDS.len()
    );
    assert_eq!(
        exceptions_seen,
        OBJECT_ADMISSION_EXCEPTIONS
            .iter()
            .map(|(path, resource, field, _)| format!("{path}:{resource}.{field}"))
            .collect(),
        "remove stale admission exceptions"
    );
}

fn assert_nested_array_error<T: serde::de::DeserializeOwned>(
    body: &serde_json::Value,
    pointer: &str,
) {
    for array in [json!([]), json!([{}]), json!([null, {}, 1])] {
        let mut malformed = body.clone();
        *malformed.pointer_mut(pointer).expect("test field exists") = array;
        let bytes = serde_json::to_vec(&malformed).unwrap();
        let error = match serde_json::from_slice::<T>(&bytes) {
            Ok(_) => panic!("{pointer} accepted a positional array: {malformed}"),
            Err(error) => error,
        };
        assert!(error.is_data(), "{pointer}: {error}");
        assert!(
            error
                .to_string()
                .contains("invalid type: sequence, expected a JSON object"),
            "{pointer} must use the #5555 object-only error shape: {error}"
        );
    }
    assert!(serde_json::from_value::<T>(body.clone()).is_ok());
}

#[test]
fn port_policy_objects_reject_arrays_without_changing_values_or_defaults() {
    use ferrum_edge::config::types::UpstreamPortOverride;

    let body = json!({
        "locality_lb_setting": {"enabled": false},
        "passive_health_check": {"unhealthy_threshold": 7},
        "tcp_keepalive": {"time_seconds": 31},
        "tls": {"verify_server_cert": false},
    });
    for field in [
        "locality_lb_setting",
        "passive_health_check",
        "tcp_keepalive",
        "tls",
    ] {
        assert_nested_array_error::<UpstreamPortOverride>(&body, &format!("/{field}"));
        let mut null = body.clone();
        null[field] = serde_json::Value::Null;
        assert!(serde_json::from_value::<UpstreamPortOverride>(null).is_ok());
    }
    assert!(serde_json::from_value::<UpstreamPortOverride>(json!({})).is_ok());
    let parsed: UpstreamPortOverride = serde_json::from_value(body).unwrap();
    assert_eq!(parsed.tcp_keepalive.unwrap().time_seconds, Some(31));
    assert!(!parsed.tls.unwrap().verify_server_cert);
}

#[test]
fn upstream_health_discovery_and_subset_objects_reject_arrays() {
    use ferrum_edge::config::types::Upstream;

    let body = json!({
        "id": "nested-shapes",
        "targets": [],
        "health_checks": {"active": {}, "passive": {}},
        "service_discovery": {
            "provider": "dns_sd",
            "dns_sd": {"service_name": "backend.example"},
            "kubernetes": {"service_name": "backend"},
            "consul": {"address": "http://localhost:8500", "service_name": "backend"},
            "mesh": {"service_name": "backend"},
        },
        "subsets": [{
            "name": "stable", "labels": {},
            "traffic_policy": {"passive_health_check": {}, "tls": {"mode": "strict"}},
        }],
    });
    for pointer in [
        "/health_checks/active",
        "/health_checks/passive",
        "/service_discovery/dns_sd",
        "/service_discovery/kubernetes",
        "/service_discovery/consul",
        "/service_discovery/mesh",
        "/subsets/0/traffic_policy",
        "/subsets/0/traffic_policy/passive_health_check",
        "/subsets/0/traffic_policy/tls",
    ] {
        assert_nested_array_error::<Upstream>(&body, pointer);
        let mut null = body.clone();
        *null.pointer_mut(pointer).unwrap() = serde_json::Value::Null;
        assert!(serde_json::from_value::<Upstream>(null).is_ok());
    }
}

#[test]
fn boxed_trigger_nodes_and_leaf_objects_reject_arrays() {
    use ferrum_edge::config::plugin_trigger::PluginTrigger;

    let body = json!({"when": {"not": {"match": {
        "header": {
            "name": "x-test", "presence": "present", "multi_value": "any",
            "value": {"exact": ["ok"]},
        },
    }}}});
    for pointer in [
        "/when",
        "/when/not",
        "/when/not/match",
        "/when/not/match/header",
        "/when/not/match/header/value",
    ] {
        assert_nested_array_error::<PluginTrigger>(&body, pointer);
    }
    let parsed: PluginTrigger = serde_json::from_value(body.clone()).unwrap();
    parsed.validate().unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), body);
}

#[test]
fn gateway_trust_and_mesh_telemetry_objects_reject_arrays() {
    use ferrum_edge::config::gateway_trust::GatewayTrustBundleRecord;
    use ferrum_edge::modes::mesh::config::MeshTelemetryConfig;

    // Shape-only fixtures: parsing does not attempt certificate admission.
    let body = json!({"bundle": {"local": {
        "trust_domain": "example.org", "x509_authorities": [], "jwt_authorities": [],
    }}});
    assert_nested_array_error::<GatewayTrustBundleRecord>(&body, "/bundle");
    assert_nested_array_error::<GatewayTrustBundleRecord>(&body, "/bundle/local");

    let body = json!({"tracing": {}, "metrics": {}, "access_logging": {"filter": {}}});
    for pointer in [
        "/tracing",
        "/metrics",
        "/access_logging",
        "/access_logging/filter",
    ] {
        assert_nested_array_error::<MeshTelemetryConfig>(&body, pointer);
        let mut null = body.clone();
        *null.pointer_mut(pointer).unwrap() = serde_json::Value::Null;
        assert!(serde_json::from_value::<MeshTelemetryConfig>(null).is_ok());
    }
    assert!(serde_json::from_value::<MeshTelemetryConfig>(json!({})).is_ok());
}

#[test]
fn plugin_wire_objects_reject_arrays_before_construction() {
    use ferrum_edge::plugins::api_chargeback_sink::ApiChargebackSinkConfig;
    use ferrum_edge::plugins::mesh_route_dispatch::RouteRule;

    let body = json!({
        "match": {}, "destination": {"backend_tls": {}},
        "retry": {"backoff": {"fixed": {"delay_ms": 2}}},
        "fault": {"delay": {"percentage": 1.0, "duration_ms": 2},
                  "abort": {"percentage": 1.0, "status_code": 503}},
        "rewrite": {}, "redirect": {},
    });
    for pointer in [
        "/match",
        "/destination",
        "/destination/backend_tls",
        "/retry",
        "/retry/backoff/fixed",
        "/fault",
        "/fault/delay",
        "/fault/abort",
        "/rewrite",
        "/redirect",
    ] {
        assert_nested_array_error::<RouteRule>(&body, pointer);
    }
    let body = json!({
        "clickhouse": {"tls": {}}, "batch": {}, "retry": {}, "spool": {}, "snapshot": {},
    });
    for pointer in [
        "/clickhouse",
        "/clickhouse/tls",
        "/batch",
        "/retry",
        "/spool",
        "/snapshot",
    ] {
        assert_nested_array_error::<ApiChargebackSinkConfig>(&body, pointer);
    }
    assert!(serde_json::from_value::<ApiChargebackSinkConfig>(json!({})).is_ok());
}

#[test]
fn api_spec_restore_section_requires_an_object_and_preserves_absence() {
    use ferrum_edge::_test_support::restore_envelope_admission_for_test;

    for rejected in [json!([]), json!(["1", []]), json!([{}])] {
        let body = json!({"api_specs": rejected});
        assert!(restore_envelope_admission_for_test(&serde_json::to_vec(&body).unwrap()).is_err());
    }
    for accepted in [
        json!({}),
        json!({"api_specs": null}),
        json!({"api_specs": {"section_version": "1", "items": []}}),
    ] {
        restore_envelope_admission_for_test(&serde_json::to_vec(&accepted).unwrap()).unwrap();
    }
}

#[test]
fn mesh_json_file_document_and_mesh_section_require_objects() {
    use ferrum_edge::modes::mesh::config_consumer::file_source::read_mesh_config_document;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("mesh.json");
    for rejected in [
        json!({"mesh": []}),
        json!({"mesh": [{}]}),
        json!([]),
        json!([null, []]),
        json!([null, {}]),
    ] {
        std::fs::write(&path, serde_json::to_vec(&rejected).unwrap()).unwrap();
        let error = read_mesh_config_document(&path)
            .expect_err("a mesh document and its mesh section must be objects")
            .to_string();
        assert!(
            error.contains("invalid mesh configuration document"),
            "{error}"
        );
        assert!(
            error.contains("invalid type: sequence, expected a JSON object"),
            "{error}"
        );
    }

    std::fs::write(&path, br#"{"mesh": {}}"#).unwrap();
    let mesh = read_mesh_config_document(&path).expect("an empty mesh object remains valid");
    assert!(mesh.mesh_policies.is_empty());
    assert!(mesh.peer_authentications.is_empty());
    assert!(mesh.trust_bundles.is_none());
}

#[test]
fn mesh_config_updates_reject_positional_slice_roots() {
    use ferrum_edge::grpc::proto::{MeshConfigUpdate, MeshSubscribeRequest};
    use ferrum_edge::modes::mesh::config_consumer::update_validation::{
        MeshUpdateConsumer, MeshUpdateExpectation, MeshUpdateRejectReason,
        validate_mesh_config_update,
    };
    use ferrum_edge::modes::mesh::slice::MeshSlice;

    let request = MeshSubscribeRequest {
        node_id: "object-admission-node".to_string(),
        namespace: "object-admission".to_string(),
        ..Default::default()
    };
    let expected = MeshUpdateExpectation::from_subscribe_request(&request);
    // Supply every positional field through the required version; remaining
    // fields have serde defaults. An empty array alone already failed before
    // the root guard and would not catch this regression.
    let positional = json!([
        request.node_id,
        request.namespace,
        "",
        null,
        null,
        null,
        [],
        {},
        false,
        [],
        [],
        "v1",
    ]);
    let slice: MeshSlice = serde_json::from_value(positional.clone())
        .expect("the fixture must exercise serde's positional struct representation");
    let mut update = MeshConfigUpdate {
        version: slice.version.clone(),
        ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
        ..Default::default()
    };
    for consumer in [
        MeshUpdateConsumer::Native,
        MeshUpdateConsumer::RemoteDiscovery,
    ] {
        update.mesh_slice_json = serde_json::to_string(&positional).unwrap();
        let rejection = validate_mesh_config_update(&update, &expected, consumer)
            .expect_err("a positional slice must fail JSON admission");
        assert_eq!(rejection.reason(), MeshUpdateRejectReason::InvalidSliceJson);
        assert!(!rejection.terminates_stream());
        assert!(
            rejection
                .detail()
                .contains("invalid type: sequence, expected a JSON object"),
            "{rejection}"
        );

        update.mesh_slice_json = serde_json::to_string(&slice).unwrap();
        assert!(validate_mesh_config_update(&update, &expected, consumer).is_ok());
    }
}

#[test]
fn typed_plugin_config_value_boundaries_require_objects() {
    use ferrum_edge::plugins::mesh::authz::MeshAuthz;
    use ferrum_edge::plugins::mesh::outbound_registry::OutboundRegistry;
    use ferrum_edge::plugins::mesh::workload_metrics::WorkloadMetrics;
    use ferrum_edge::plugins::mesh_route_dispatch::MeshRouteDispatchConfig;

    for rejected in [json!([]), json!([[], false])] {
        let route_error = MeshRouteDispatchConfig::from_value(&rejected).unwrap_err();
        assert!(route_error.contains("invalid type: sequence, expected a JSON object"));
        let registry_error = match OutboundRegistry::new(&rejected) {
            Ok(_) => panic!("mesh_outbound_registry accepted a positional config"),
            Err(error) => error,
        };
        assert!(registry_error.contains("invalid type: sequence, expected a JSON object"));
    }
    assert!(MeshRouteDispatchConfig::from_value(&json!({})).is_ok());
    assert!(OutboundRegistry::new(&json!({})).is_ok());

    let authz_error = match MeshAuthz::new(&json!({"mesh_slice": []})) {
        Ok(_) => panic!("mesh_authz accepted a positional mesh_slice"),
        Err(error) => error,
    };
    assert!(
        authz_error.contains("invalid type: sequence, expected a JSON object"),
        "{authz_error}"
    );
    let metrics_error = match WorkloadMetrics::new(&json!({"direction_emit": []})) {
        Ok(_) => panic!("workload_metrics accepted a positional direction_emit"),
        Err(error) => error,
    };
    assert!(
        metrics_error.contains("invalid type: sequence, expected a JSON object"),
        "{metrics_error}"
    );
}

#[test]
fn plugin_structs_behind_raw_json_values_retain_object_admission() {
    for (path, signature, terminator, guarded_type) in [
        (
            "src/plugins/mesh_route_dispatch.rs",
            "pub fn from_value(config: &Value)",
            "\n    }",
            "json_object::JsonObject<Self>",
        ),
        (
            "src/plugins/mesh/outbound_registry.rs",
            "pub fn new(config: &Value)",
            "\n    }",
            "JsonObject<OutboundRegistryConfig>",
        ),
        (
            // `MeshAuthz::new` only forwards; the slice is parsed in
            // `new_with_http_client`, so the guard must read that body.
            "src/plugins/mesh/authz.rs",
            "pub fn new_with_http_client(",
            "\n    }",
            "json_object::JsonObject<MeshSlice>",
        ),
        (
            "src/plugins/mesh/workload_metrics.rs",
            "fn parse_direction_emit(config: &Value)",
            "\n}",
            "json_object::JsonObject<DirectionEmit>",
        ),
        (
            "src/modes/mesh/mod.rs",
            "fn mesh_authz_config_policies(config: &serde_json::Value)",
            "\n}",
            "json_object::JsonObject<MeshSlice>",
        ),
    ] {
        let text = admission_source_without_line_comments(&source(path));
        assert!(
            item_body(&text, signature, terminator).contains(guarded_type),
            "{path}: raw JSON must pass the object guard before typed plugin parsing"
        );
    }
}

#[test]
fn plugin_struct_lists_behind_raw_json_values_retain_element_admission() {
    for (path, signature, terminator, guarded_type) in [
        (
            "src/plugins/mesh/authz.rs",
            "fn parse_node_waypoint_route_upstreams(",
            "\n}",
            "json_object::from_json_object_vec_value",
        ),
        (
            "src/plugins/mesh/authz.rs",
            "pub fn new_with_http_client(",
            "\n    }",
            "Vec<crate::util::json_object::JsonObject<MeshPolicy>>",
        ),
        (
            "src/modes/mesh/mod.rs",
            "fn mesh_authz_config_policies(config: &serde_json::Value)",
            "\n}",
            "json_object::from_json_object_vec_value",
        ),
    ] {
        let text = admission_source_without_line_comments(&source(path));
        assert!(
            item_body(&text, signature, terminator).contains(guarded_type),
            "{path}: raw JSON lists must guard every typed struct element"
        );
    }
    let text = admission_source_without_line_comments(&source("src/modes/mesh/slice.rs"));
    let body = item_body(&text, "pub struct MeshSlice {", "\n}");
    let field_attributes = regex::Regex::new(r"(?:#\[[^\]]*\]\s*)+$").unwrap();
    for field in ["virtual_service_l4_proxies", "virtual_service_l4_upstreams"] {
        let declaration = format!("pub {field}:");
        let start = body
            .find(&declaration)
            .expect("MeshSlice L4 field must exist");
        // Inspect this field's full attribute group independently of ordering
        // or whether serde options share one attribute or use separate ones.
        let attributes = field_attributes
            .find(&body[..start])
            .expect("MeshSlice L4 field must carry attributes");
        assert!(
            attributes
                .as_str()
                .contains("json_object::deserialize_object_vec"),
            "MeshSlice.{field}: require objects"
        );
    }
    // xDS can construct a slice without running its Deserialize, so the
    // subsequent Value-to-resource conversion must retain the same guard.
    let text = admission_source_without_line_comments(&source("src/modes/mesh/mod.rs"));
    for signature in [
        "fn decode_virtual_service_l4_proxies(",
        "fn decode_virtual_service_l4_upstreams(",
    ] {
        assert!(
            item_body(&text, signature, "\n}").contains("json_object::from_json_object_value("),
            "{signature}: typed L4 resource elements must require objects"
        );
    }
}

// ---------------------------------------------------------------------------
// One flushing relay byte pump for every tunnelled protocol (issue #5588)
//
// `poll_copy_direction` flushes a writer that is still holding accepted bytes
// whenever its reader returns `Pending`. Buffering writers reach that loop from
// every tunnelled path — userspace TCP/TLS, WebSocket tunnel mode, mesh TCP
// inbound and egress, and the HBONE HTTP/2 CONNECT byte tunnel — so the
// invariant holds only while those paths keep sharing ONE pump. A call site
// that grows its own copy loop, or drops back to
// `tokio::io::copy_bidirectional`, silently leaves the fix behind: tokio tracks
// its own flush debt but reports neither per-direction byte counts nor which
// half failed, and it cannot be raced against the authorization or
// admission-revocation bounds.
// ---------------------------------------------------------------------------

/// The two entry points into the shared relay.
const RELAY_ENTRY_POINT: &str = "tcp_proxy::bidirectional_copy_for_relay(";
const FENCED_RELAY_ENTRY_POINT: &str = "tcp_proxy::bidirectional_copy_for_fenced_relay(";

/// Every `src/**/*.rs` file that calls one of them, as `(path, entry point,
/// what it carries)`. This table is compared for **set equality** against the
/// files that actually call either entry point, not merely checked from the
/// table outwards: a fifth call site — a new tunnelled protocol, or a second
/// copy of an existing one — fails the build until it is listed here and
/// inherits the invariant.
const RELAY_CALL_SITES: &[(&str, &str, &str)] = &[
    (
        "src/proxy/hbone_proxy.rs",
        FENCED_RELAY_ENTRY_POINT,
        "HBONE HTTP/2 CONNECT byte tunnel, under the mesh admission fence",
    ),
    (
        "src/proxy/mesh_tcp_egress.rs",
        RELAY_ENTRY_POINT,
        "mesh captured raw-TCP egress, over an H2 CONNECT tunnel",
    ),
    (
        "src/proxy/mesh_tcp_inbound.rs",
        RELAY_ENTRY_POINT,
        "mesh captured raw-TCP inbound, to the loopback app",
    ),
    (
        "src/proxy/mod.rs",
        RELAY_ENTRY_POINT,
        "raw TCP/TLS passthrough and WebSocket tunnel mode",
    ),
    // Not a datapath: `_test_support` re-exports the fenced entry point so
    // `relay_flush_progress_tests.rs` can drive the production relay rather
    // than a re-typed copy of it. It belongs in the set-equality table because
    // it genuinely calls the entry point; leaving it out would need a
    // by-name exclusion, which is the hole this table exists to close.
    (
        "src/lib.rs",
        FENCED_RELAY_ENTRY_POINT,
        "`_test_support` re-export, not a datapath",
    ),
];

/// Where both entry points are defined, and the one file excluded from the scan
/// below: `tcp_proxy.rs`'s own crate-internal `bidirectional_copy_for_test*`
/// wrappers call the plain relay by its bare name.
const RELAY_DEFINITION_FILE: &str = "src/proxy/tcp_proxy.rs";

/// The bare name inside a path-qualified entry point.
///
/// The scan matches this as well as the module-qualified spelling, so a call
/// site that wrote `use crate::proxy::tcp_proxy::bidirectional_copy_for_relay;`
/// and then called it bare lands in `calling` and has to be listed. It cannot
/// match a declaration instead of a call: both definitions carry a generic
/// parameter list (`…_for_relay<C, B>(`) and the `_test_support` wrapper is
/// `…_for_fenced_relay_for_test(`, so in neither case does a `(` follow the
/// name. Prose mentions are stripped by
/// `admission_source_without_line_comments` before the scan.
fn bare_entry_point(entry_point: &str) -> &str {
    match entry_point.rsplit_once("::") {
        Some((_, name)) => name,
        None => entry_point,
    }
}

#[test]
fn every_tunnelled_relay_path_shares_one_flushing_byte_pump() {
    let calling: BTreeSet<String> = production_sources()
        .into_iter()
        .filter(|(path, text)| {
            if path.as_str() == RELAY_DEFINITION_FILE {
                return false;
            }
            let code = admission_source_without_line_comments(text);
            code.contains(bare_entry_point(RELAY_ENTRY_POINT))
                || code.contains(bare_entry_point(FENCED_RELAY_ENTRY_POINT))
        })
        .map(|(path, _)| path)
        .collect();
    let expected: BTreeSet<String> = RELAY_CALL_SITES
        .iter()
        .map(|(path, _, _)| (*path).to_string())
        .collect();
    assert_eq!(
        calling, expected,
        "a call site reaching the shared relay changed; every tunnelled path must keep \
         using the one flushing copy loop, and each one belongs in RELAY_CALL_SITES"
    );

    for &(path, entry_point, carries) in RELAY_CALL_SITES {
        assert!(
            admission_source_without_line_comments(&source(path)).contains(entry_point),
            "{path} ({carries}): must reach the shared `tcp_proxy` copy loop through \
             `{entry_point}`"
        );
    }

    let tcp_proxy = source("src/proxy/tcp_proxy.rs");
    assert_eq!(
        tcp_proxy.matches("fn poll_copy_direction<").count(),
        1,
        "the flushing copy loop must have exactly one definition"
    );
    let pump = item_body(&tcp_proxy, "fn poll_copy_direction<", "\n}");
    assert!(
        pump.contains("state.needs_flush = true"),
        "an accepted write must record the flush this direction now owes"
    );
    assert!(
        pump.contains("writer.as_mut().poll_flush(cx)"),
        "the reader-pending branch must flush the writer before parking"
    );
    assert!(
        pump.contains("finish_half_close(outcome, state, write_watermark)"),
        "the half-close must resolve through `finish_half_close`, so a `poll_shutdown` \
         that fails is not reported as a clean completion"
    );

    // Only `tcp_proxy.rs` may reach for tokio's bidirectional copy, and there
    // only on the documented all-bounds-disabled fast path.
    for (path, text) in production_sources() {
        if path == "src/proxy/tcp_proxy.rs" {
            continue;
        }
        assert!(
            !admission_source_without_line_comments(&text).contains("copy_bidirectional"),
            "{path}: relays must go through the shared `tcp_proxy` copy loop"
        );
    }
}
