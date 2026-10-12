//! Behavioural regressions for live-suite fixture shell helpers.
//!
//! Each test lifts the exact top-level function definitions out of a fixture
//! script, replaces the external tools those functions call (kubectl, kind,
//! docker, openssl, SPIRE) with recording stubs, and checks the helper's
//! verdict and side effects. Nothing here reaches a cluster, Docker, or SPIRE.
//!
//! - #6292: the CNI recovered-pod probe must OBSERVE a recovery phase; status
//!   reads that fail or come back empty for the whole budget fail the proof.
//! - #6302: the poller-partition fixture removes only resources it created,
//!   by the identity it recorded when it created them.
//! - #6303: NodeWaypoint HTTP and DTLS denial rows require evidence that the
//!   probe ran and, for DTLS, that the backend log was actually read; Service
//!   AuthorizationPolicy rows require the policy's own 403.
//! - #6306: a failed SPIRE `start` stops the children it launched.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

const CNI_RUN_SH: &str = "tests/k8s/cni_lifecycle_live/run.sh";
const POLLER_RUN_SH: &str = "tests/k8s/multicluster-poller-partition/run.sh";
const NODE_WAYPOINT_RUN_SH: &str = "tests/k8s/node_waypoint_ebpf_live/run.sh";
const SPIRE_FIXTURE: &str = "tests/functional/fixtures/two_cluster_spire.sh";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|error| {
        panic!("failed to read {rel}: {error}");
    })
}

/// The verbatim definition of a top-level shell function: either a one-line
/// `name() { ...; }` whose braces balance on that line, or a multi-line
/// `name() {` ... `}` block closed at column 0.
fn shell_function(source: &str, name: &str) -> String {
    let header = format!("{name}() {{");
    let mut lines = source
        .lines()
        .skip_while(|line| *line != header && !is_one_line_definition(line, &header));
    let first = lines
        .next()
        .unwrap_or_else(|| panic!("top-level shell function {name} not found"));
    if first != header {
        return format!("{first}\n");
    }
    let mut body = vec![first];
    for line in lines {
        body.push(line);
        if line == "}" {
            return body.join("\n") + "\n";
        }
    }
    panic!("top-level shell function {name} has no closing brace at column 0");
}

fn is_one_line_definition(line: &str, header: &str) -> bool {
    line.len() > header.len()
        && line.starts_with(header)
        && line.trim_end().ends_with('}')
        && line.matches('{').count() == line.matches('}').count()
}

fn shell_functions(source: &str, names: &[&str]) -> String {
    names
        .iter()
        .map(|name| shell_function(source, name))
        .collect()
}

/// The verbatim top-level line starting with `prefix`.
fn shell_line(source: &str, prefix: &str) -> String {
    let line = source
        .lines()
        .find(|line| line.starts_with(prefix))
        .unwrap_or_else(|| panic!("top-level line starting with {prefix:?} not found"));
    format!("{line}\n")
}

fn run_bash(script: &str, state: &Path, envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new("bash");
    command
        .arg("-c")
        .arg(script)
        .current_dir(state)
        .env("STATE", state);
    for (key, value) in envs {
        command.env(key, value);
    }
    command.output().expect("spawn bash")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write stub executable");
    let mut permissions = fs::metadata(path).expect("stat stub").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("chmod stub");
}

fn path_with(bin: &Path) -> String {
    format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

#[test]
fn shell_function_extracts_one_line_and_multi_line_definitions() {
    let source = r#"log() { printf '%s\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 127; }; }

wait_for() {
  if [[ -n "$1" ]]; then
    need "$1"
  fi
}
after() { :; }
"#;
    assert_eq!(
        shell_function(source, "need"),
        r#"need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 127; }; }
"#
    );
    assert_eq!(
        shell_function(source, "wait_for"),
        r#"wait_for() {
  if [[ -n "$1" ]]; then
    need "$1"
  fi
}
"#
    );
    assert_eq!(
        shell_functions(source, &["log", "after"]),
        r#"log() { printf '%s\n' "$*"; }
after() { :; }
"#
    );
}

// ---------------------------------------------------------------------------
// #6292: CNI lifecycle recovered-pod observation
// ---------------------------------------------------------------------------

/// `sleep` advances bash's own clock so a 120 s budget polls instantly.
/// `kubectl get pod` fails while `$STATE/api-down` exists, otherwise prints
/// `$PHASE` (possibly empty); every other kubectl call succeeds.
const CNI_STUBS: &str = r#"set -euo pipefail
sleep() { SECONDS=$((SECONDS + ${1%.*})); }
kubectl() {
  if [[ "$1 $2" != "get pod" ]]; then
    return 0
  fi
  local reads
  reads=$(( $(cat "$STATE/reads" 2>/dev/null || echo 0) + 1 ))
  echo "$reads" >"$STATE/reads"
  if [[ -e "$STATE/api-down" ]]; then
    echo "Unable to connect to the server: dial tcp 10.96.0.1:443: connect: connection refused" >&2
    return 1
  fi
  printf '%s' "${PHASE:-}"
}
"#;

struct CniProbe {
    verdict: String,
    phase: String,
    reads: u32,
    later: String,
    stderr: String,
}

fn run_cni_recovered_pod_probe(phase: &str, api_down: bool) -> CniProbe {
    let source = read(CNI_RUN_SH);
    let functions = shell_functions(
        &source,
        &[
            "wait_for_pod_not_pending",
            "is_recovered_pod_phase",
            "observe_recovered_pod",
        ],
    );
    let state = TempDir::new().expect("state dir");
    if api_down {
        fs::write(state.path().join("api-down"), "").expect("mark API down");
    }
    // The API recovers after the observation window, so every later stage of
    // the fixture could succeed; the missed observation must still fail.
    let script = format!(
        r#"{CNI_STUBS}{functions}
if phase="$(observe_recovered_pod recovered-pod 120 5)"; then
  echo "VERDICT=ok"
else
  echo "VERDICT=fail"
fi
echo "PHASE=$phase"
echo "READS=$(cat "$STATE/reads")"
rm -f "$STATE/api-down"
PHASE=Failed
echo "LATER=$(kubectl get pod recovered-pod -o jsonpath='{{.status.phase}}')"
"#
    );
    let output = run_bash(&script, state.path(), &[("PHASE", phase)]);
    assert!(
        output.status.success(),
        "harness failed: {}",
        stderr_of(&output)
    );
    let stdout = stdout_of(&output);
    let field = |key: &str| {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")).map(str::to_string))
            .unwrap_or_else(|| panic!("missing {key} in {stdout}"))
    };
    CniProbe {
        verdict: field("VERDICT"),
        phase: field("PHASE"),
        reads: field("READS").parse().expect("numeric read count"),
        later: field("LATER"),
        stderr: stderr_of(&output),
    }
}

#[test]
fn cni_recovered_pod_unreadable_status_for_the_whole_budget_fails_the_proof() {
    let probe = run_cni_recovered_pod_probe("Running", true);
    assert_eq!(probe.verdict, "fail", "stderr: {}", probe.stderr);
    assert_eq!(probe.phase, "", "no phase was ever observed");
    assert!(
        probe.reads >= 20,
        "the helper must keep polling for the whole budget, read {} times",
        probe.reads
    );
    assert_eq!(probe.later, "Failed", "the API recovered after the window");
    assert!(
        probe.stderr.contains("Pod phase never observed")
            && probe.stderr.contains("connection refused"),
        "a missing observation needs a bounded diagnostic naming the last read error: {}",
        probe.stderr
    );
}

#[test]
fn cni_recovered_pod_empty_phase_for_the_whole_budget_fails_the_proof() {
    let probe = run_cni_recovered_pod_probe("", false);
    assert_eq!(probe.verdict, "fail", "stderr: {}", probe.stderr);
    assert_eq!(probe.phase, "");
    assert!(
        probe.stderr.contains("empty status.phase"),
        "stderr: {}",
        probe.stderr
    );
}

#[test]
fn cni_recovered_pod_persistent_pending_fails_distinctly_from_unreadable_status() {
    let probe = run_cni_recovered_pod_probe("Pending", false);
    assert_eq!(probe.verdict, "fail", "stderr: {}", probe.stderr);
    assert_eq!(probe.phase, "Pending", "an observed Pending stays observed");
    assert!(
        probe.stderr.contains("not Running, Succeeded or Failed")
            && !probe.stderr.contains("never observed"),
        "stderr: {}",
        probe.stderr
    );
}

#[test]
fn cni_recovered_pod_unknown_phase_is_not_recovery() {
    let probe = run_cni_recovered_pod_probe("Unknown", false);
    assert_eq!(probe.verdict, "fail", "stderr: {}", probe.stderr);
    assert_eq!(probe.phase, "Unknown");
}

#[test]
fn cni_recovered_pod_observed_terminal_or_running_phase_proves_recovery() {
    for phase in ["Failed", "Succeeded", "Running"] {
        let probe = run_cni_recovered_pod_probe(phase, false);
        assert_eq!(probe.verdict, "ok", "{phase}: {}", probe.stderr);
        assert_eq!(probe.phase, phase);
        assert_eq!(probe.reads, 1, "{phase} is observed on the first read");
    }
}

#[test]
fn cni_stuck_pod_wait_reports_an_observed_pending_phase() {
    let source = read(CNI_RUN_SH);
    let functions = shell_function(&source, "wait_for_pod_not_pending");
    let state = TempDir::new().expect("state dir");
    let script = format!(
        r#"{CNI_STUBS}{functions}
if phase="$(wait_for_pod_not_pending stuck-pod 90 5)"; then
  echo "OK=$phase"
else
  echo "FAIL=$phase"
fi
"#
    );
    let output = run_bash(&script, state.path(), &[("PHASE", "Pending")]);
    assert_eq!(
        stdout_of(&output).trim(),
        "OK=Pending",
        "{}",
        stderr_of(&output)
    );
}

#[test]
fn cni_fixture_routes_recovery_checks_through_the_observation_helpers() {
    let source = read(CNI_RUN_SH);
    assert!(
        source.contains(r#"if ! phase="$(observe_recovered_pod recovered-pod 120)"; then"#),
        "the post-uninstall recovered-pod check must require an observed recovery phase"
    );
    assert!(
        source.contains(r#"if ! phase="$(wait_for_pod_not_pending stuck-pod 90)"; then"#),
        "the stuck-pod check must fail when no phase was observed"
    );
    assert!(
        source.contains(r#"if ! is_recovered_pod_phase "$phase"; then"#),
        "the post-rollback stuck-pod check must use the same recovered-phase set"
    );
    let wait = shell_function(&source, "wait_for_pod_not_pending");
    assert!(
        !wait.contains("|| true"),
        "the phase read must not swallow kubectl failures"
    );
}

// ---------------------------------------------------------------------------
// #6302: multicluster poller-partition cleanup ownership
// ---------------------------------------------------------------------------

/// Recording stubs. kind clusters live in `$STATE/clusters`; a control-plane
/// container id lives in `$STATE/id-<name>`; a container exists while
/// `$STATE/container-<name>` exists. `docker rm` removes a node only by its
/// exact id and `kind delete` resolves the cluster by name, the way the real
/// tools do. `REPLACE_BEFORE_DELETE` swaps that cluster's node for another
/// invocation's same-name replacement immediately before the first
/// destructive call, after every ownership check the fixture could make.
/// A created node carries the token mounted from its kind config's `hostPath`
/// in `$STATE/token-<id>`, which `docker exec <id> cat` reads.
/// `REPLACE_AFTER_CREATE` swaps that cluster's node for another invocation's
/// same-name replacement, carrying a different token, the instant its
/// `kind create` succeeds and before the fixture's first identity inspection.
const POLLER_STUBS: &str = r#"set -euo pipefail
log_call() { printf '%s\n' "$*" >>"$STATE/calls"; }
replace_before_delete() {
  if [[ -n "${REPLACE_BEFORE_DELETE:-}" && ! -e "$STATE/replaced" ]]; then
    touch "$STATE/replaced"
    printf 'node-%s-theirs' "$REPLACE_BEFORE_DELETE" \
      >"$STATE/id-$REPLACE_BEFORE_DELETE-control-plane"
  fi
}
python3() {
  log_call "python3 $*"
  if [[ "$*" == *verify_signal_reload_guard* && "${GUARD_FAIL:-0}" == 1 ]]; then
    return 1
  fi
  if [[ "$*" == *proxy-count* ]]; then
    cat >/dev/null
    printf '4'
  fi
}
curl() { log_call "curl $*"; printf '{}'; }
openssl() {
  log_call "openssl $*"
  if [[ "$1" == rand ]]; then
    printf 'run-token-ours\n'
  fi
}
kubectl() { log_call "kubectl $*"; }
kind() {
  log_call "kind $*"
  case "$1 $2" in
    "get clusters")
      if [[ -f "$STATE/clusters" ]]; then
        cat "$STATE/clusters"
      fi
      ;;
    "create cluster")
      if [[ " ${FAIL_CREATE:-} " == *" $4 "* ]]; then
        return 1
      fi
      printf '%s\n' "$4" >>"$STATE/clusters"
      printf 'node-%s-ours' "$4" >"$STATE/id-$4-control-plane"
      local host_path
      host_path="$(sed -n 's/^ *- hostPath: //p' "$6")"
      cat "$host_path/token" >"$STATE/token-node-$4-ours"
      printf 'context kind-%s\n' "$4" >>"$KUBECONFIG"
      printf '%s' "$KUBECONFIG" >"$STATE/kubeconfig-path"
      if [[ "${REPLACE_AFTER_CREATE:-}" == "$4" ]]; then
        printf 'node-%s-theirs' "$4" >"$STATE/id-$4-control-plane"
        printf 'run-token-theirs\n' >"$STATE/token-node-$4-theirs"
      fi
      ;;
    "delete cluster")
      replace_before_delete
      rm -f "$STATE/id-$4-control-plane"
      ;;
  esac
}
docker() {
  log_call "docker $*"
  case "$1" in
    inspect)
      if [[ "$2" != "-f" ]]; then
        [[ -e "$STATE/container-$2" ]]
      elif [[ "$3" == '{{.Id}}' ]]; then
        cat "$STATE/id-$4" 2>/dev/null
      else
        printf '172.18.0.9'
      fi
      ;;
    exec)
      [[ "$3 $4" == "cat /ferrum-run-provenance/token" ]] || return 1
      cat "$STATE/token-$2" 2>/dev/null
      ;;
    create)
      touch "$STATE/container-$3"
      printf 'toxi-ours'
      ;;
    rm)
      replace_before_delete
      local id="${*: -1}" file
      for file in "$STATE"/id-*; do
        if [[ -f "$file" && "$(cat "$file")" == "$id" ]]; then
          rm -f "$file"
        fi
      done
      ;;
  esac
}
collect_diagnostics() { log_call "collect_diagnostics"; }
create_proxy() { log_call "create_proxy $1"; }
wait_for_curl() {
  log_call "wait_for_curl $1"
  if [[ -n "${REPLACE_CLUSTER:-}" ]]; then
    printf 'node-%s-theirs' "$REPLACE_CLUSTER" >"$STATE/id-$REPLACE_CLUSTER-control-plane"
  fi
  [[ "${FAULT_LAYER_READY:-1}" == 1 ]]
}
TOXI_IP="" NODE_A="" NODE_B=""
IMAGE=stub-image TOXIPROXY_IMAGE=stub-toxiproxy-image
FED_AB=fed-ab DISC_AB=disc-ab FED_BA=fed-ba DISC_BA=disc-ba
FED_AB_PORT=15441 DISC_AB_PORT=15442 FED_BA_PORT=15443 DISC_BA_PORT=15444
trap cleanup EXIT
"#;

struct PollerRun {
    status: i32,
    calls: Vec<String>,
    stderr: String,
    /// The control-plane id each cluster name resolves to after cleanup.
    nodes_after: Vec<(String, String)>,
    /// The kubeconfig kind wrote this run's contexts to, if a cluster was made.
    kubeconfig: Option<PathBuf>,
}

impl PollerRun {
    fn destructive_calls(&self) -> Vec<&str> {
        self.calls
            .iter()
            .map(String::as_str)
            .filter(|call| call.starts_with("docker rm") || call.starts_with("kind delete"))
            .collect()
    }

    fn node_after(&self, cluster: &str) -> Option<&str> {
        self.nodes_after
            .iter()
            .find(|(name, _)| name == cluster)
            .map(|(_, id)| id.as_str())
    }
}

/// Runs `body` with the fixture's own `trap cleanup EXIT` armed, the way
/// run.sh does, with custom resource names so default-name assumptions show.
fn run_poller(
    body: &str,
    existing_clusters: &[&str],
    existing_container: bool,
    envs: &[(&str, &str)],
) -> PollerRun {
    let source = read(POLLER_RUN_SH);
    let owned = [
        shell_line(&source, "OWNED_TOXIPROXY_ID="),
        shell_line(&source, "RUN_KUBECONFIG_DIR="),
        shell_line(&source, "export KUBECONFIG="),
        shell_line(&source, "RUN_PROVENANCE_DIR="),
        shell_line(&source, "RUN_PROVENANCE_MOUNT="),
    ]
    .concat();
    let functions = shell_functions(
        &source,
        &[
            "need",
            "cluster_node_id",
            "release_owned_cluster",
            "cleanup",
            "preflight",
            "write_provenance_kind_config",
            "record_created_cluster",
            "create_clusters_and_fault_layer",
        ],
    );
    let state = TempDir::new().expect("state dir");
    for cluster in existing_clusters {
        fs::write(
            state.path().join(format!("id-{cluster}-control-plane")),
            format!("node-{cluster}-preexisting"),
        )
        .expect("seed pre-existing cluster id");
    }
    if !existing_clusters.is_empty() {
        fs::write(
            state.path().join("clusters"),
            existing_clusters.join("\n") + "\n",
        )
        .expect("seed pre-existing clusters");
    }
    if existing_container {
        fs::write(state.path().join("container-custom-toxi"), "").expect("seed container");
    }
    let script = format!("{POLLER_STUBS}{owned}{functions}{body}\n");
    let mut all_envs = vec![
        ("CLUSTER_A", "custom-a"),
        ("CLUSTER_B", "custom-b"),
        ("TOXIPROXY_CONTAINER", "custom-toxi"),
    ];
    all_envs.extend_from_slice(envs);
    let mut command = Command::new("bash");
    command
        .arg("-c")
        .arg(script)
        .current_dir(state.path())
        .env("STATE", state.path())
        .env("TMPDIR", state.path())
        .env_remove("FERRUM_MULTICLUSTER_LIVE_ACK_DISPOSABLE");
    for (key, value) in &all_envs {
        command.env(key, value);
    }
    let output = command.output().expect("spawn bash");
    let calls = fs::read_to_string(state.path().join("calls"))
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect();
    let nodes_after = ["custom-a", "custom-b"]
        .iter()
        .filter_map(|cluster| {
            fs::read_to_string(state.path().join(format!("id-{cluster}-control-plane")))
                .ok()
                .map(|id| ((*cluster).to_string(), id))
        })
        .collect();
    let kubeconfig = fs::read_to_string(state.path().join("kubeconfig-path"))
        .ok()
        .map(PathBuf::from);
    PollerRun {
        status: output.status.code().unwrap_or(-1),
        calls,
        stderr: stderr_of(&output),
        nodes_after,
        kubeconfig,
    }
}

const ACK: (&str, &str) = ("FERRUM_MULTICLUSTER_LIVE_ACK_DISPOSABLE", "true");

struct Refusal {
    label: &'static str,
    body: &'static str,
    clusters: &'static [&'static str],
    container: bool,
    envs: &'static [(&'static str, &'static str)],
}

const REFUSALS: [Refusal; 6] = [
    Refusal {
        label: "missing acknowledgement",
        body: "preflight",
        clusters: &[],
        container: false,
        envs: &[],
    },
    Refusal {
        label: "failing signal-reload guard",
        body: "preflight",
        clusters: &[],
        container: false,
        envs: &[ACK, ("GUARD_FAIL", "1")],
    },
    Refusal {
        label: "missing prerequisite",
        body: "unset -f curl\nPATH=/nonexistent\npreflight",
        clusters: &[],
        container: false,
        envs: &[ACK],
    },
    Refusal {
        label: "pre-existing cluster A",
        body: "preflight",
        clusters: &["custom-a"],
        container: false,
        envs: &[ACK],
    },
    Refusal {
        label: "pre-existing cluster B",
        body: "preflight",
        clusters: &["custom-b"],
        container: false,
        envs: &[ACK],
    },
    Refusal {
        label: "pre-existing Toxiproxy container",
        body: "preflight",
        clusters: &[],
        container: true,
        envs: &[ACK],
    },
];

#[test]
fn poller_preflight_refusals_make_no_destructive_calls() {
    for refusal in &REFUSALS {
        let run = run_poller(
            refusal.body,
            refusal.clusters,
            refusal.container,
            refusal.envs,
        );
        assert_ne!(run.status, 0, "{}: preflight must refuse", refusal.label);
        assert!(
            run.destructive_calls().is_empty(),
            "{}: a refusal must not delete anything, got {:?}\nstderr: {}",
            refusal.label,
            run.destructive_calls(),
            run.stderr
        );
    }
}

#[test]
fn poller_cleanup_after_successful_creation_removes_exactly_the_created_resources() {
    let run = run_poller(
        "preflight\ncreate_clusters_and_fault_layer\nexit 0",
        &[],
        false,
        &[ACK],
    );
    assert_eq!(run.status, 0, "stderr: {}", run.stderr);
    let mut destructive = run.destructive_calls();
    destructive.sort_unstable();
    assert_eq!(
        destructive,
        vec![
            "docker rm -f -v node-custom-a-ours",
            "docker rm -f -v node-custom-b-ours",
            "docker rm -f toxi-ours",
        ],
        "every container is removed by the id this run created, never by name"
    );
    assert_eq!(run.node_after("custom-a"), None);
    assert_eq!(run.node_after("custom-b"), None);
    let kubeconfig = run.kubeconfig.expect("kind wrote a kubeconfig");
    assert!(
        !kubeconfig.exists(),
        "the run-private kubeconfig holding this run's contexts is removed: {}",
        kubeconfig.display()
    );
}

#[test]
fn poller_cleanup_after_partial_creation_removes_only_the_acquired_subset() {
    let run = run_poller(
        "create_clusters_and_fault_layer",
        &[],
        false,
        &[("FAIL_CREATE", "custom-b")],
    );
    assert_ne!(run.status, 0);
    assert_eq!(
        run.destructive_calls(),
        vec!["docker rm -f -v node-custom-a-ours"],
        "only cluster A was created; stderr: {}",
        run.stderr
    );
}

#[test]
fn poller_cleanup_preserves_a_same_name_replacement() {
    let run = run_poller(
        "create_clusters_and_fault_layer",
        &[],
        false,
        &[("REPLACE_CLUSTER", "custom-a"), ("FAULT_LAYER_READY", "0")],
    );
    assert_ne!(run.status, 0);
    let mut destructive = run.destructive_calls();
    destructive.sort_unstable();
    assert_eq!(
        destructive,
        vec![
            "docker rm -f -v node-custom-a-ours",
            "docker rm -f -v node-custom-b-ours",
            "docker rm -f toxi-ours",
        ],
        "cleanup never resolves a cluster by name"
    );
    assert_eq!(
        run.node_after("custom-a"),
        Some("node-custom-a-theirs"),
        "the same-name replacement survives cleanup"
    );
    assert_eq!(run.node_after("custom-b"), None);
}

#[test]
fn poller_cleanup_preserves_a_replacement_made_after_the_ownership_check() {
    // Every ownership check sees this run's own node; the replacement lands
    // only between those checks and the deletion itself.
    let run = run_poller(
        "preflight\ncreate_clusters_and_fault_layer\nexit 0",
        &[],
        false,
        &[ACK, ("REPLACE_BEFORE_DELETE", "custom-a")],
    );
    assert_eq!(run.status, 0, "stderr: {}", run.stderr);
    assert_eq!(
        run.node_after("custom-a"),
        Some("node-custom-a-theirs"),
        "a replacement created between inspection and deletion survives; calls: {:?}",
        run.destructive_calls()
    );
    assert_eq!(run.node_after("custom-b"), None);
    let mut destructive = run.destructive_calls();
    destructive.sort_unstable();
    assert_eq!(
        destructive,
        vec![
            "docker rm -f -v node-custom-a-ours",
            "docker rm -f -v node-custom-b-ours",
            "docker rm -f toxi-ours",
        ]
    );
}

#[test]
fn poller_refuses_a_node_replaced_before_its_identity_is_recorded() {
    // The replacement lands after `kind create` succeeds and before the
    // fixture's first inspection of the node, so the only id the fixture can
    // ever observe for this name is the replacement's.
    let run = run_poller(
        "preflight\ncreate_clusters_and_fault_layer\nexit 0",
        &[],
        false,
        &[ACK, ("REPLACE_AFTER_CREATE", "custom-a")],
    );
    assert_ne!(run.status, 0, "an unproven node must fail the run");
    assert!(
        run.stderr.contains("does not carry this run's provenance token"),
        "stderr: {}",
        run.stderr
    );
    let provenance_read = "docker exec node-custom-a-theirs cat /ferrum-run-provenance/token";
    assert!(
        run.calls.iter().any(|call| call == provenance_read),
        "the provenance is read through the captured id; calls: {:?}",
        run.calls
    );
    assert!(
        run.destructive_calls().is_empty(),
        "the replacement is neither adopted nor deleted, got {:?}",
        run.destructive_calls()
    );
    assert_eq!(
        run.node_after("custom-a"),
        Some("node-custom-a-theirs"),
        "the same-name replacement survives"
    );
}

// ---------------------------------------------------------------------------
// #6303: NodeWaypoint HTTP and DTLS denial evidence
// ---------------------------------------------------------------------------

const NODE_WAYPOINT_STUBS: &str = r#"set -euo pipefail
WORKLOAD_NS=ferrum-ebpf-live
collect_traffic_failure_diagnostics() { :; }
spiffe_for_sa() { printf 'spiffe://cluster.local/ns/ferrum-ebpf-live/sa/%s' "$1"; }
record_live_assertion() { printf '%s|%s|%s\n' "$1" "$2" "$5" >>"$STATE/records"; }
curl_for_family_from_namespace() {
  printf '%b' "${CURL_OUTPUT:-}"
  return "${CURL_STATUS:-0}"
}
kubectl() {
  case " $* " in
    *" logs "*)
      if [[ "${LOGS_FAIL:-0}" == 1 ]]; then
        echo 'Error from server (NotFound): deployments.apps "dtls-echo" not found' >&2
        return 1
      fi
      printf '%b' "${BACKEND_LOGS:-}"
      ;;
    *" exec "*)
      if [[ "${EXEC_FAIL:-0}" == 1 ]]; then
        echo 'error: unable to upgrade connection: container not found ("dtls")' >&2
        return 1
      fi
      while [[ "$1" != "--" ]]; do
        shift
      done
      shift
      "$@"
      ;;
  esac
}
"#;

fn node_waypoint_functions() -> String {
    let source = read(NODE_WAYPOINT_RUN_SH);
    let mut prelude = shell_line(&source, "LAST_HTTP_DENIAL_EVIDENCE=");
    prelude.push_str(&shell_line(&source, "DTLS_PROBE_RC_MARKER="));
    prelude.push_str(&shell_line(&source, "DTLS_PROBE_DEADLINE_MARKER="));
    let functions = shell_functions(
        &source,
        &[
            "classify_http_denial_probe",
            "forged_assertion_response_is_policy_rejection",
            "expect_blocked_from_namespace",
            "expect_blocked",
            "recorded_expect_blocked",
            "backend_log_payload_count",
            "dtls_denial_probe_from",
            "classify_dtls_denial_probe",
            "dtls_denial_verdict",
        ],
    );
    prelude.push_str(&functions);
    prelude
}

/// The source waypoint's exact body for a CONNECT the destination peer refused
/// with 403, and the same wrapper for an unrelated peer status.
const PEER_403_BODY: &str =
    r#"{"error":"HBONE backend unavailable: tunnel rejected by peer with status 403"}"#;
const PEER_503_BODY: &str =
    r#"{"error":"HBONE backend unavailable: tunnel rejected by peer with status 503"}"#;

#[test]
fn node_waypoint_http_denial_requires_an_executed_probe_and_an_observed_refusal() {
    let functions = node_waypoint_functions();
    let state = TempDir::new().expect("state dir");
    let script = format!(
        r#"{NODE_WAYPOINT_STUBS}{functions}
check() {{
  local evidence verdict=0
  evidence="$(classify_http_denial_probe "$1" "$(printf '%b' "$2")" fail-closed)" || verdict=$?
  printf '%s|%s|%s\n' "$1" "$verdict" "$evidence"
}}
check 0 'denied\n403'
check 0 'upstream\n503'
check 0 'ok-b\n200'
check 0 '\n301'
check 7 '\n000'
check 28 '\n000'
check 52 '\n000'
check 56 '\n000'
check 1 ''
check 126 ''
check 0 ''
check 6 '\n000'
check 28 'partial\n200'
"#
    );
    let output = run_bash(&script, state.path(), &[]);
    assert!(output.status.success(), "{}", stderr_of(&output));
    let expected = [
        "0|0|http-403",
        "0|0|http-503",
        "0|1|unexpected-http-200",
        "0|1|unexpected-http-301",
        "7|0|curl-exit-7",
        "28|0|curl-exit-28",
        "52|0|curl-exit-52",
        "56|0|curl-exit-56",
        "1|2|no-curl-trailer exec_status=1",
        "126|2|no-curl-trailer exec_status=126",
        "0|2|no-curl-trailer exec_status=0",
        "6|2|inconclusive-curl-exit-6-http-000",
        "28|2|inconclusive-curl-exit-28-http-200",
    ];
    assert_eq!(
        stdout_of(&output).lines().collect::<Vec<_>>(),
        expected,
        "a kubectl/exec failure, a missing curl trailer, or a curl setup error \
         is not a denial; only HTTP 4xx/5xx or a curl transport refusal is"
    );
}

#[test]
fn node_waypoint_policy_denial_requires_the_policy_refusal_itself() {
    let functions = node_waypoint_functions();
    let state = TempDir::new().expect("state dir");
    let script = format!(
        r#"{NODE_WAYPOINT_STUBS}{functions}
check() {{
  local evidence verdict=0
  evidence="$(classify_http_denial_probe "$1" "$2" authorization-policy)" || verdict=$?
  printf '%s|%s\n' "$verdict" "$evidence"
}}
check 0 $'denied\n403'
check 0 $'{PEER_403_BODY}\n502'
check 0 $'{{"error":"Not Found"}}\n404'
check 0 $'bad gateway\n502'
check 0 $'{PEER_403_BODY}\n503'
check 0 $'{PEER_503_BODY}\n502'
check 0 $'upstream connect error\n503'
check 0 $'\n503'
check 28 $'\n000'
check 7 $'\n000'
check 56 $'\n000'
check 0 $'ok-a\n200'
check 1 ''
classify_http_denial_probe 0 $'denied\n403' guessed || echo "UNKNOWN=$?"
"#
    );
    let output = run_bash(&script, state.path(), &[]);
    assert!(output.status.success(), "{}", stderr_of(&output));
    let expected = [
        "0|policy-http-403",
        "0|peer-policy-403-via-http-502",
        "2|unattributed-http-404",
        "2|unattributed-http-502",
        "2|unattributed-http-503",
        "2|unattributed-http-502",
        "2|unattributed-http-503",
        "2|unattributed-http-503",
        "2|inconclusive-curl-exit-28-http-000",
        "2|inconclusive-curl-exit-7-http-000",
        "2|inconclusive-curl-exit-56-http-000",
        "1|unexpected-http-200",
        "2|no-curl-trailer exec_status=1",
        "unknown-expected-refusal-guessedUNKNOWN=2",
    ];
    assert_eq!(
        stdout_of(&output).lines().collect::<Vec<_>>(),
        expected,
        "a Service AuthorizationPolicy row passes only on a direct 403 or the \
         source waypoint's attributed peer 403; a route miss, an unrelated 5xx, \
         or a dropped or timed-out connection is inconclusive"
    );
}

#[test]
fn node_waypoint_recorded_http_denial_fails_when_the_probe_never_ran() {
    let functions = node_waypoint_functions();
    let cases = [
        (
            "1",
            "",
            "1",
            "node_waypoint.ipv4.service_deny_same_node|fail|\
             expected-denied-by-authorization-policy;observed=no-curl-trailer exec_status=1",
        ),
        (
            "0",
            "\\n200",
            "1",
            "node_waypoint.ipv4.service_deny_same_node|fail|\
             expected-denied-by-authorization-policy;observed=unexpected-http-200",
        ),
        (
            "0",
            "denied\\n403",
            "0",
            "node_waypoint.ipv4.service_deny_same_node|pass|\
             denied-by-authorization-policy;refusal=policy-http-403",
        ),
        (
            "0",
            "{\"error\":\"HBONE backend unavailable: tunnel rejected by peer with status 403\"}\\n502",
            "0",
            "node_waypoint.ipv4.service_deny_same_node|pass|\
             denied-by-authorization-policy;refusal=peer-policy-403-via-http-502",
        ),
        (
            "0",
            "{\"error\":\"Not Found\"}\\n404",
            "1",
            "node_waypoint.ipv4.service_deny_same_node|fail|\
             expected-denied-by-authorization-policy;observed=unattributed-http-404",
        ),
        (
            "0",
            "upstream\\n503",
            "1",
            "node_waypoint.ipv4.service_deny_same_node|fail|\
             expected-denied-by-authorization-policy;observed=unattributed-http-503",
        ),
        (
            "28",
            "\\n000",
            "1",
            "node_waypoint.ipv4.service_deny_same_node|fail|\
             expected-denied-by-authorization-policy;observed=inconclusive-curl-exit-28-http-000",
        ),
    ];
    for (status, output, expected_return, expected_record) in cases {
        let state = TempDir::new().expect("state dir");
        let script = format!(
            r#"{NODE_WAYPOINT_STUBS}{functions}
if recorded_expect_blocked node_waypoint.ipv4.service_deny_same_node src-b dst-b \
  "same-node Service AuthorizationPolicy DENY" \
  "http://dst-b.ferrum-ebpf-live.svc.cluster.local:8080/" 4 denied-by-authorization-policy; then
  echo "RETURN=0"
else
  echo "RETURN=$?"
fi
"#
        );
        let result = run_bash(
            &script,
            state.path(),
            &[("CURL_STATUS", status), ("CURL_OUTPUT", output)],
        );
        assert!(result.status.success(), "{}", stderr_of(&result));
        assert_eq!(
            stdout_of(&result).trim(),
            format!("RETURN={expected_return}"),
            "status={status} output={output:?}: {}",
            stderr_of(&result)
        );
        let records = fs::read_to_string(state.path().join("records")).expect("records");
        assert_eq!(records.trim(), expected_record, "status={status}");
    }
}

#[test]
fn node_waypoint_backend_log_count_distinguishes_unreadable_from_zero() {
    let functions = node_waypoint_functions();
    let state = TempDir::new().expect("state dir");
    let script = format!(
        r#"{NODE_WAYPOINT_STUBS}{functions}
show() {{
  local count status=0
  count="$(backend_log_payload_count ferrum-ebpf-live dtls-echo "$1")" || status=$?
  printf '%s|%s\n' "$status" "$count"
}}
LOGS_FAIL=1
show dtls-b
LOGS_FAIL=0
BACKEND_LOGS='recv:dtls-a\nrecv:dtls-b\n'
show dtls-b
show dtls-x
BACKEND_LOGS=''
show dtls-b
"#
    );
    let output = run_bash(&script, state.path(), &[]);
    assert!(output.status.success(), "{}", stderr_of(&output));
    assert_eq!(
        stdout_of(&output).lines().collect::<Vec<_>>(),
        ["1|", "0|1", "0|0", "0|0"],
        "an unreadable backend log must never read as zero datagrams"
    );
}

#[test]
fn node_waypoint_dtls_denial_requires_probe_execution_and_a_read_backend_log() {
    let bin = TempDir::new().expect("stub bin dir");
    write_executable(
        &bin.path().join("openssl"),
        "#!/bin/sh\n# Stub openssl s_client for the DTLS denial regression. Modes:\n\
         # hang (outlive the deadline), ignore-term (outlive TERM too),\n\
         # self-term/self-kill (die of an unrelated signal before the\n\
         # deadline), exit (print $STUB_OPENSSL_OUTPUT, exit $STUB_OPENSSL_RC).\n\
         cat >/dev/null\n\
         case \"${STUB_OPENSSL_MODE:-exit}\" in\n\
         hang) exec sleep 30 ;;\n\
         ignore-term) trap '' TERM; exec sleep 30 ;;\n\
         self-term) kill -TERM $$ ;;\n\
         self-kill) kill -KILL $$ ;;\n\
         esac\n\
         if [ -n \"${STUB_OPENSSL_OUTPUT:-}\" ]; then printf '%s\\n' \"$STUB_OPENSSL_OUTPUT\"; fi\n\
         exit \"${STUB_OPENSSL_RC:-1}\"\n",
    );
    let functions = node_waypoint_functions();
    let state = TempDir::new().expect("state dir");
    let script = format!(
        r#"{NODE_WAYPOINT_STUBS}{functions}
verdict_for() {{
  local report hits log_status=0 evidence verdict=0
  report="$(dtls_denial_probe_from ferrum-ebpf-live dtls-src-b 10.0.0.1 15354 dtls-b 1)"
  hits="$(backend_log_payload_count ferrum-ebpf-live dtls-echo dtls-b)" || log_status=$?
  evidence="$(dtls_denial_verdict "$report" "dtls-ok:dtls-b" "$log_status" "$hits")" || verdict=$?
  printf '%s|%s\n' "$verdict" "$evidence"
}}
export STUB_OPENSSL_MODE=hang STUB_OPENSSL_RC=1 STUB_OPENSSL_OUTPUT=''
EXEC_FAIL=1 LOGS_FAIL=1
verdict_for
EXEC_FAIL=1 LOGS_FAIL=0
verdict_for
EXEC_FAIL=0 LOGS_FAIL=1
verdict_for
LOGS_FAIL=0
verdict_for
STUB_OPENSSL_MODE=ignore-term
verdict_for
STUB_OPENSSL_MODE=self-term
verdict_for
STUB_OPENSSL_MODE=self-kill
verdict_for
STUB_OPENSSL_MODE=exit STUB_OPENSSL_RC=143
verdict_for
STUB_OPENSSL_RC=124
verdict_for
STUB_OPENSSL_RC=1
verdict_for
STUB_OPENSSL_OUTPUT='40F7E1B2:error:0A000410:SSL routines:dtls1_read_bytes:sslv3 alert handshake failure:ssl/record/rec_layer_d1.c:613:SSL alert number 40'
verdict_for
STUB_OPENSSL_OUTPUT='Error configuring OpenSSL modules: 40F7E1B2:error:12800067:DSO support routines::could not load the shared library'
verdict_for
STUB_OPENSSL_OUTPUT='BIO_lookup_ex:system lib: Name does not resolve'
verdict_for
STUB_OPENSSL_RC=127 STUB_OPENSSL_OUTPUT=''
verdict_for
STUB_OPENSSL_RC=0 STUB_OPENSSL_OUTPUT='dtls-ok:dtls-b'
verdict_for
STUB_OPENSSL_RC=1 STUB_OPENSSL_OUTPUT=''
BACKEND_LOGS='recv:dtls-b\n'
verdict_for
"#
    );
    let output = run_bash(
        &script,
        state.path(),
        &[("PATH", path_with(bin.path()).as_str())],
    );
    assert!(output.status.success(), "{}", stderr_of(&output));
    assert_eq!(
        stdout_of(&output).lines().collect::<Vec<_>>(),
        [
            "2|probe-did-not-run",
            "2|probe-did-not-run",
            "2|probe-timed-out rc=143 backend-log-unavailable",
            "0|probe-timed-out rc=143 backend_hits=0",
            "0|probe-timed-out rc=137 backend_hits=0",
            "2|probe-killed-without-deadline rc=143",
            "2|probe-killed-without-deadline rc=137",
            "2|probe-killed-without-deadline rc=143",
            "2|probe-inconclusive rc=124",
            "2|probe-inconclusive rc=1",
            "0|probe-peer-alert rc=1 backend_hits=0",
            "2|probe-inconclusive rc=1",
            "2|probe-setup-failed rc=1",
            "2|probe-tool-unavailable rc=127",
            "1|echo-returned backend_hits=0",
            "1|backend_hits=1",
        ],
        "only an expiry of the probe's own deadline or a received DTLS alert, \
         with the backend log read, satisfies a DTLS denial row; an unrelated \
         TERM/KILL, setup, and unrecognized client failures are inconclusive"
    );
}

#[test]
fn node_waypoint_dtls_denial_rows_use_the_provenance_preserving_helpers() {
    let source = read(NODE_WAYPOINT_RUN_SH);
    for payload in ["dtls-b", "dtls-svc-b", "dtls-svc-x"] {
        let read_marker = format!("dtls-echo {payload})");
        let log_read = source
            .lines()
            .find(|line| line.contains(&read_marker))
            .unwrap_or_else(|| panic!("{payload}: the denial row reads no backend log"));
        assert!(
            log_read.contains("backend_log_payload_count"),
            "{payload}: the denial row must read the backend log strictly: {log_read}"
        );
        assert!(
            source.contains(&format!("\"dtls-ok:{payload}\"")),
            "{payload}: the denial row must decide through dtls_denial_verdict"
        );
        assert!(
            !source.contains(&format!("dtls_echo_backend_received {payload})")),
            "{payload}: the zero-on-failure log read must not decide a denial"
        );
    }
    assert_eq!(
        source.matches("dtls_denial_probe_from \"$").count(),
        3,
        "all three DTLS denial rows must use the provenance-preserving probe"
    );
}

// ---------------------------------------------------------------------------
// #6306: two-cluster SPIRE start rollback
// ---------------------------------------------------------------------------

const SPIRE_SERVER_STUB: &str = r#"#!/bin/sh
# Stub spire-server for the two-cluster SPIRE start rollback regression.
case "$1" in
  run)
    root=$(dirname "$3")
    echo "$$" >"$root/stub-server.pid"
    sock="$root/server.sock"
    python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$sock"
    exec sleep 120
    ;;
  bundle)
    printf '%s\n' '-----BEGIN CERTIFICATE-----' 'c3R1Yg==' '-----END CERTIFICATE-----'
    ;;
  token)
    if [ -n "${STUB_TOKEN_FAIL:-}" ]; then
      echo 'stub: token generation refused' >&2
      exit 1
    fi
    echo 'Token: stub-token'
    ;;
esac
"#;

const SPIRE_AGENT_STUB: &str = r#"#!/bin/sh
# Stub spire-agent for the two-cluster SPIRE start rollback regression.
case "$1" in
  run)
    root=$(dirname "$3")
    echo "$$" >"$root/stub-agent.pid"
    if [ -z "${STUB_AGENT_NO_SOCKET:-}" ]; then
      sock="$root/agent.sock"
      python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$sock"
    fi
    exec sleep 120
    ;;
esac
"#;

struct SpireFixture {
    bin: TempDir,
    root: TempDir,
}

impl SpireFixture {
    fn new() -> Self {
        let bin = TempDir::new().expect("stub bin dir");
        write_executable(&bin.path().join("spire-server"), SPIRE_SERVER_STUB);
        write_executable(&bin.path().join("spire-agent"), SPIRE_AGENT_STUB);
        let root = TempDir::new().expect("SPIRE root");
        Self { bin, root }
    }

    fn root(&self) -> String {
        self.root.path().display().to_string()
    }

    fn run(&self, args: &[&str], envs: &[(&str, &str)]) -> Output {
        let mut command = Command::new("bash");
        command
            .arg(repo_root().join(SPIRE_FIXTURE))
            .args(args)
            .env("PATH", path_with(self.bin.path()));
        for (key, value) in envs {
            command.env(key, value);
        }
        command.output().expect("spawn SPIRE fixture")
    }

    fn stub_pid(&self, name: &str) -> Option<String> {
        fs::read_to_string(self.root.path().join(name))
            .ok()
            .map(|pid| pid.trim().to_string())
    }

    fn has(&self, name: &str) -> bool {
        self.root.path().join(name).exists()
    }
}

fn process_alive(pid: &str) -> bool {
    Command::new("sh")
        .args(["-c", "kill -0 \"$1\" 2>/dev/null", "sh", pid])
        .status()
        .expect("spawn kill -0")
        .success()
}

#[test]
fn spire_start_failure_after_server_launch_stops_the_launched_server() {
    let fixture = SpireFixture::new();
    let output = fixture.run(
        &["start", &fixture.root(), "stub-a.test", "18081"],
        &[("STUB_TOKEN_FAIL", "1")],
    );
    assert!(!output.status.success(), "token generation was refused");
    let server = fixture
        .stub_pid("stub-server.pid")
        .expect("the server was launched before the failure");
    assert!(
        !process_alive(&server),
        "a failed start must stop the server it launched; stderr: {}",
        stderr_of(&output)
    );
    assert!(
        !fixture.has("server.pid"),
        "a reaped child's PID file must not survive for a later stop to signal"
    );
    assert!(
        !fixture.has("stub-agent.pid"),
        "the agent was never launched"
    );
}

#[test]
fn spire_start_failure_after_agent_launch_stops_both_children() {
    let fixture = SpireFixture::new();
    let output = fixture.run(
        &["start", &fixture.root(), "stub-a.test", "18082"],
        &[("STUB_AGENT_NO_SOCKET", "1")],
    );
    assert!(!output.status.success());
    assert!(
        stderr_of(&output).contains("SPIRE agent socket did not appear"),
        "stderr: {}",
        stderr_of(&output)
    );
    for name in ["stub-server.pid", "stub-agent.pid"] {
        let pid = fixture.stub_pid(name).expect("child was launched");
        assert!(!process_alive(&pid), "{name}: child must be stopped");
    }
    assert!(!fixture.has("server.pid") && !fixture.has("agent.pid"));
}

#[test]
fn spire_start_failure_before_any_launch_leaves_nothing_to_stop() {
    let fixture = SpireFixture::new();
    let output = fixture.run(&["start", &fixture.root(), "stub-a.test"], &[]);
    assert!(
        !output.status.success(),
        "a missing port is a usage error"
    );
    for name in ["stub-server.pid", "stub-agent.pid", "server.pid", "agent.pid"] {
        assert!(!fixture.has(name), "{name}: nothing may be launched");
    }
}

#[test]
fn spire_successful_start_keeps_both_children_running() {
    let fixture = SpireFixture::new();
    let output = fixture.run(&["start", &fixture.root(), "stub-a.test", "18083"], &[]);
    let server = fixture.stub_pid("stub-server.pid");
    let agent = fixture.stub_pid("stub-agent.pid");
    let server_alive = server.as_deref().is_some_and(process_alive);
    let agent_alive = agent.as_deref().is_some_and(process_alive);
    let server_pid_file = fixture.stub_pid("server.pid");
    let agent_pid_file = fixture.stub_pid("agent.pid");
    let stop = fixture.run(&["stop", &fixture.root()], &[]);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    assert!(server_alive && agent_alive, "start must not roll back");
    assert_eq!(server_pid_file, server, "server.pid names the server");
    assert_eq!(agent_pid_file, agent, "agent.pid names the agent");
    assert!(stop.status.success(), "stderr: {}", stderr_of(&stop));
}
