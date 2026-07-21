# CI/CD Pipeline Documentation

Ferrum Edge includes comprehensive CI/CD pipelines for automated testing, building, and releasing.

## Table of Contents

- [Pipeline Overview](#pipeline-overview)
- [Workflow Inventory](#workflow-inventory)
- [CI Pipeline (ci.yml)](#ci-pipeline-ciyml)
- [Release Pipeline (release.yml)](#release-pipeline-releaseyml)
- [How Releases Work](#how-releases-work)
- [Creating a New Release](#creating-a-new-release)
- [Binaries and Downloads](#binaries-and-downloads)
- [GitHub Actions Secrets](#github-actions-secrets)

## Pipeline Overview

The publish-critical flows are `ci.yml` and `release.yml`: CI validates PRs and
`main`, then publishes `latest` artifacts from `main`; Release publishes
versioned artifacts from `v*` tags. Additional workflows provide coverage,
scheduled dependency governance, live datapath/conformance labs, manual
benchmark suites, and repository maintenance automation.

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| **CI** (`ci.yml`) | Pull Requests, push to `main` | Required validation for PRs and `main`; latest binaries and Docker images after `main` validation |
| **Release** (`release.yml`) | Push tag matching `v*` | Validate the tagged SHA, then publish versioned binaries, GitHub release, and Docker tags |

## Workflow Inventory

Workflow files live under `.github/workflows/`. Keep this table in sync when
adding, removing, or materially changing a workflow.

| Workflow file | Display name | Triggers | Role |
|---|---|---|---|
| `ci.yml` | CI | PRs, push to `main`, manual | Required validation gate plus `latest` prerelease and Docker image publishing from `main`. |
| `coverage.yml` | Coverage | PRs, push to `main`, weekly schedule, manual | Coverage planning/reporting and coverage floor enforcement; `Merge Coverage` is directly required on PRs. |
| `release.yml` | Release | `v*` tag push | Versioned binary, GitHub Release, and Docker publishing after CI/Coverage validation. |
| `gateway-api-conformance.yml` | Gateway API Conformance | PRs, push to `main`, weekly schedule, manual | Upstream Gateway API conformance lab; `Gateway API Conformance` is directly required on PRs. |
| `mesh-e2e-sidecar-live.yml` | Mesh E2E Sidecar Live Datapath | PRs, push to `main`, manual | Release-blocking sidecar datapath validation; `Mesh E2E Sidecar Live` is directly required on PRs. |
| `cross-build-policy.yml` | Cross Build Policy | `pull_request_target` for PRs to `main` | Read-only trusted-base validation of every PR-controlled ARM64 Cross configuration and invocation surface; `Trusted Cross Build Policy` must be directly required after the bootstrap workflow merges. |
| `node-waypoint-ebpf-live.yml` | NodeWaypoint eBPF Live Datapath | Path-filtered PRs, manual | Live eBPF datapath validation in kind. |
| `multicluster-federation-live.yml` | Multicluster Federation Live Datapath | Path-filtered PRs, manual | Live multicluster federation datapath validation. |
| `dependency-audit.yml` | Dependency Audit | Weekly schedule, manual | Scheduled supply-chain governance beyond the per-PR audit gate. |
| `scaling-regression.yml` | Scheduled Scaling Regression | Weekly schedule, manual | Runs the 30k proxy scale and 10k proxy load-stress tests excluded from PR CI. |
| `claude-review.yml` | Claude PR Review | `@claude review` issue comment on PRs | Maintainer-triggered AI review comments. |
| `cleanup-pending-reviews.yml` | Cleanup Pending Deployment Reviews | Schedule, manual | Clears stale pending deployment review state. |
| `prune-stale-prs.yml` | Prune Stale PRs and Branches | Schedule, manual | Repository hygiene for stale PRs/branches. |
| `perf-benchmark.yml` | Multi Protocol Performance Benchmark | Manual | Multi-protocol benchmark suite for selected refs. |
| `payload-size-benchmark.yml` | Payload Size Performance Benchmark | Manual | Payload-size benchmark suite for selected refs. |
| `comparison-benchmark.yml` | Gateway Comparison Benchmark | Manual | Cross-gateway comparison benchmarks. |
| `gateways-protocol-benchmark.yml` | Gateways Protocol Benchmark | Manual | Gateway/protocol benchmark harness. |
| `connection-saturation-benchmark.yml` | Connection Saturation Benchmark | Manual | Connection saturation benchmark suite. |
| `scale-benchmark.yml` | Resources Scale Benchmark | Manual | Large resource/config scale benchmark suite. |

### CI Pipeline Flow

```
Pull Request
    ├─► Trusted Cross Build Policy (`pull_request_target`, base code only)
            └─► Validate proposed Cross/Cargo config, workflows, repo-local
                actions, and referenced scripts as hostile data
    ├─► CI plan
            ├─► Docs/license/agent-only: lightweight Tests aggregate
            └─► Full CI
                    ├─► Format + integration-shard coverage (in CI plan)
                    ├─► Unit+inline-lib / integration-shard / functional-shard tests
                    ├─► Lint, dependency audit, vendored regressions
                    ├─► eBPF/netns live checks when planner marks relevant
                    ├─► Planner-gated mesh / Helm / performance gates
                    └─► Five target release builds
    └─► Dedicated required checks (internally skip unrelated changes)
            ├─► Merge Coverage
            ├─► Gateway API Conformance
            └─► Mesh E2E Sidecar Live

Push to main
    ├─► Full required validation gate
    └─► Four native release builds + isolated Linux ARM64 Cross build
            └─► Tests aggregate passes
                    ├─► Replace latest GitHub prerelease
                    └─► Push per-arch Docker images to Docker Hub and GHCR
                            └─► Create multi-arch Docker manifest (`latest`, `main-<sha>`)
```

### Release Pipeline Flow

```
Push tag v* (e.g., v0.2.0)
    └─► Validate tag matches the Cargo.toml package version
            └─► Validate tag target has successful CI and Coverage runs for the exact SHA
            └─► Four-target native matrix (linux-x86_64 / macos-x86_64 /
                macos-aarch64 / windows-x86_64) + isolated linux-aarch64 Cross job
                    └─► Push versioned Docker images to Docker Hub and GHCR
                            └─► Create Docker manifest tags
                                    └─► Create GitHub Release with binaries and checksums
```

## CI Pipeline (ci.yml)

The CI workflow is triggered by every pull request and every push to `main`.
The `CI Plan` job first selects `full` or `light` mode. Pull requests whose
entire diff is limited to ordinary documentation, `.agents/**`, `.claude/**`,
Markdown outside `vendor/`, or license files use light mode and preserve a fast
`Tests` aggregate without starting the Rust/build matrix. Documentation that
deliberately triggers a live datapath suite (including the mesh, SPIRE,
configuration, NodeWaypoint, and CI contract/runbook files) remains full mode.
The planner runs `git diff --check` for PR diff hygiene and disables rename
detection when classifying paths, so both the source and destination of a rename
are checked.
Any unrecognized path, an empty/unavailable diff, a mixed code-and-docs change,
a push to `main`, or a manual run fails over to full mode. The decision table
and its executable examples live in `.github/scripts/pr_ci_plan.py`. PR
decisions use the planner from the base branch when available, so a planner-only
edit cannot classify itself as light; edits to the planner therefore receive
the full matrix. The required-CI verifier also checks that documentation paths
used by live-suite filters remain in the planner's full-CI set.

The same trusted planner emits fail-closed job outputs for Helm, mesh federation,
the sidecar deployment smoke, eBPF program builds, and eBPF/netns live suites.
PRs outside those curated path sets skip the downstream job before GitHub
allocates a runner. Pushes to `main` and manual runs force all of these gates on.
Rust formatting and the integration-shard coverage contract also run as named
steps in `CI Plan`, avoiding two additional runner allocations. The required
`Tests` aggregate runs the first-party Markdown link checker through its CI
contract verifier (`.github/scripts/check_markdown_links.py`), including in
light mode, so docs-only PRs still validate relative file targets and GitHub
heading slugs.

In full mode, the `Tests` aggregate waits for the planner/format checks, test
shards, lint, dependency audit, vendored patch regressions,
planner-gated mesh/Helm gates, eBPF/netns gates, performance, and the
cross-platform build matrix. In light mode it requires the planner to succeed
and accepts the planned heavy jobs as skipped. Pushes to `main` publish the
`latest` prerelease and Docker images only after the full aggregate and build
matrix pass.

Branch protection must require five independent PR checks: the unchanged `Tests`
aggregate from `ci.yml`, `Merge Coverage` from `coverage.yml`, `Gateway API
Conformance` from `gateway-api-conformance.yml`, `Mesh E2E Sidecar Live` from
`mesh-e2e-sidecar-live.yml`, and `Trusted Cross Build Policy` from
`cross-build-policy.yml`. Each dedicated workflow triggers on every pull
request and fails closed on planning or validation failures. They are required
directly rather than mirrored by runner-holding polling jobs in `ci.yml`.

`cross-build-policy.yml` is bootstrapped by the change that introduces it, so
it cannot emit a `pull_request_target` check until it exists on the default
branch. After that change merges and the first check is visible, a repository
administrator must add `Trusted Cross Build Policy` to the required checks for
`main`. Ordinary pull requests must not modify the trusted verifier or its
workflow; such maintenance requires an explicit branch-protection bypass.

CI uses `concurrency.group: ci-publish-${{ github.ref }}` with `cancel-in-progress: true`, so a newer push to the same branch cancels the older CI run. On `main`, that can interrupt an in-flight publish job such as Docker manifest creation. If the cancellation left publishing incomplete, re-run the newest workflow attempt (the one for the latest `main` SHA) — re-running the older, canceled run would re-publish stale binaries and images as `latest`.

### Jobs

#### 1. CI Plan Static Checks

**Runs**: `ubuntu-latest`

Checks Rust formatting and integration-shard declarations on full-mode pull
requests and pushes to `main`:

```bash
cargo fmt --all -- --check
# Also diffs tests/integration/*.rs against integration::<module> filters in ci.yml.
```

**Failures**:
- Indicate formatting drift
- Indicate a missing or stale integration shard filter
- Must be fixed before merging

#### 2. Test Jobs

**Runs**: `ubuntu-latest`

Runs the required test matrix in parallel for full-mode pull requests and
pushes to `main`. The commands below are grouped by job, not run as one
sequential shell script:

```bash
# test-unit: inline lib first, then the unchanged four-test plugin-hardening
# exact gate, then the complete external unit suite in the same job.
cargo test --lib
cargo test --test unit_tests

# test-integration-{admin-platform,mesh-protocols}
cargo nextest run --archive-file integration-tests-*.tar.zst \
  --workspace-remap . \
  --no-fail-fast \
  <shard filters>

# build-test-artifacts (one job/cache for both archives and both binaries)
cargo build --profile pr-build --bin ferrum-edge
cargo build --config profile.dev.debug=0 --bin ferrum-cni
cargo nextest archive --test integration_tests ...
cargo nextest archive --test functional_tests ...

# test-functional-{application,protocols,data-plane}
cargo nextest run --archive-file functional-tests-*.tar.zst \
  --workspace-remap . \
  --run-ignored=all \
  --no-fail-fast \
  -E 'not test(/test_scale_perf_30k_proxies/) and not test(/test_load_stress_10k_proxies/)'
```

The excluded 30k scale variants (SQLite, PostgreSQL, and MongoDB) and the 10k
PostgreSQL load-stress test run weekly and on manual dispatch in the
`Scheduled Scaling Regression` workflow. Its matrix jobs have independent
failure signals and a three-hour timeout for the large provisioning and load
phases.

**What it tests**:
- Unit tests in `tests/unit_tests.rs`
- Inline `#[cfg(test)]` modules in `src/`
- Secret backend tests compile once with Vault/AWS/GCP/Azure enabled and use
  nextest `--no-fail-fast`; service integration likewise runs Consul and LDAP
  in one independently reported invocation.
- Integration tests split across two shards (`admin-platform`,
  `mesh-protocols`). Each shard runs the prebuilt `integration_tests` nextest
  archive with a visible list of `integration::<file_module>` positional
  filters that nextest ORs together. Integration tests are in-process (no
  gateway binary, no Redis/Mongo services); each shard has a 30-minute cap.
- The `CI Plan` job diffs `ls tests/integration/*.rs` against the union of
  declared shard filters in `ci.yml`. Adding a new `mod foo_tests` without
  wiring it into a shard fails this silent-skip guard.
- Functional tests split across three shards (`application`, `protocols`,
  `data-plane`). `build-test-artifacts` compiles the gateway, CNI binary, and
  both nextest archives in one job/cache; each functional shard downloads the
  existing OS/architecture-keyed artifacts with
  `FERRUM_SKIP_GATEWAY_BUILD=1`. The data-plane shard remains serialized with
  `nextest_jobs: 1` and is the only shard that starts Redis/MongoDB containers.

**Output**:
- Test pass/fail status
- Failures block PR merges and `main` publishing through the `Tests` aggregate

#### 3. Lint Job

**Runs**: `ubuntu-latest`

Enforces code quality:

```bash
cargo clippy --all-targets -- -D warnings
```

**What it checks**:
- Code style and idioms (clippy)

**Failures**:
- Indicate quality issues
- Must be fixed before merging

#### 4. eBPF Build Job

**Runs**: `ubuntu-latest`

The planner schedules this job on PRs only when files under `ebpf/` changed, so
unrelated PRs consume no runner; pushes to `main` and manual runs force it on.
The job installs stable and nightly Rust toolchains plus `bpf-linker`, uses
nightly to build `ferrum-ebpf`, uses stable to run
`cargo test -p ferrum-ebpf-common`, and uploads the compiled `ebpf-programs`
artifact with 14-day retention. If this job is edited, preserve the intent that
the shared-types test runs on stable Rust.

#### 5. NodeWaypoint eBPF Live Datapath Workflow

**Runs**: `ubuntu-24.04`

`node-waypoint-ebpf-live` runs on PRs that touch eBPF, node-agent, NodeWaypoint
identity, netns capture, socket option, TCP scope, chart, or live harness files.
It builds the normal runtime Docker image from the host-built binary, builds the
eBPF userspace binary with `FEATURES=cloud-secrets,ebpf`, builds the
`ferrum-ebpf` BPF ELF with nightly Rust, and packages the `:<tag>-ebpf` runtime
image from those cached host-built artifacts instead of recompiling inside
Docker. It then creates a disposable dual-stack kind cluster with two workers,
mounts bpffs in each kind node, loads both images into the cluster, and installs
the Istio policy CRDs. The runner must provide Docker and a Linux kernel with
cgroup v2 and kernel >= 5.7.

The harness renders the Helm chart to assert enabled eBPF topologies select the
`-ebpf` image, installs NodeWaypoint eBPF mode, checks
`ferrum_node_agent_capture_state`, collects `bpftool` program/link/map evidence,
checks the shared node-agent ↔ ambient pod registry plus per-pod in-netns ready
markers, and verifies every ambient proxy accepted a mesh slice with the live
workloads and policies before traffic starts. It then runs same-node and
cross-node source/destination pod traffic, requiring `src-a` Service ClusterIP
requests to succeed and `src-b` Service ClusterIP plus direct Pod-IP attempts to
be rejected by live `AuthorizationPolicy`. The dual-stack pass verifies IPv6 is
rejected before traffic is admitted until the end-to-end IPv6 NodeWaypoint path
is completed. The harness also emits
`target/node-waypoint-ebpf-live/live-assertions.json`, a machine-readable H2
evidence file using the shared live-assertion schema. These assertion IDs are
observational while NodeWaypoint remains Experimental; they are not part of the
release-blocking sidecar GA contract. The workflow uploads Kubernetes
diagnostics, mesh drift snapshots, pod-registry dumps, live assertions, and
`bpftool` evidence with 14-day retention.

#### 6. Performance Regression Job

**Runs**: `ubuntu-latest`

Runs on full-mode PRs, pushes to `main`, and manual dispatches. PRs first apply a
performance-sensitive path filter; unrelated PRs skip the expensive benchmark
and report success. The PR gate covers proxy and connection hot paths, the
file-mode startup path used by this benchmark, performance fixtures, and
dependency/build-graph inputs. Plugin-internal, admin, secrets, and unrelated
operating-mode changes are excluded because this plain HTTP/1.1 file-mode route
cannot observe them. If the PR diff cannot be computed, the benchmark runs to
fail closed. Relevant PRs and all `main` pushes build the gateway in the
`ci-release` profile, build `tests/performance/backend_server`, start both
services, and run:

```bash
python3 tests/performance/ci_overhead_bench.py \
  --gateway-url http://127.0.0.1:8000/api/users \
  --backend-url http://127.0.0.1:3001/api/users \
  --gateway-health-url http://127.0.0.1:8000/health \
  --concurrency 50 \
  --duration 5 \
  --iterations 3 \
  --warmup 2 \
  --overhead-threshold 50 \
  --output tests/performance/ci_results/overhead_results.json
```

`--overhead-threshold 50` is a percentage threshold: the script fails when median gateway overhead across iterations exceeds 50%.

**Failures**:
- Indicate performance regression issues
- Must be fixed before merging

#### 7. Cross-Platform Build Jobs

**Runs**: `ubuntu-latest`, `macos-latest`, `windows-latest`

Full-mode PRs build the native Linux x86_64 verification binary. Pushes to
`main` build optimized release binaries for Linux x86_64, Linux ARM64, macOS
x86_64, macOS ARM64, and Windows x86_64. Native targets share the ordinary
matrix; Linux ARM64 runs only after code reaches `main`, in the isolated
`build-arm64-cross` job described below. The jobs install the same prerequisites
as the Release pipeline — `protoc` on every OS, `libcurl4-openssl-dev` on Linux,
and NASM on Windows — and build with `--features cloud-secrets` so
Vault/AWS/Azure/GCP secret backends are included. The macOS x86_64 build targets
`x86_64-apple-darwin` with the standard Apple/Rust toolchain (no `cross` needed)
and runs on whichever host architecture GitHub maps `macos-latest` to today
(currently ARM64); pin to a concrete runner image such as `macos-14` if the
host architecture must be guaranteed.

##### Trusted ARM64 Cross boundary

Cross 0.2.5 merges `[package.metadata.cross]` from `Cargo.toml` with the selected
Cross config file, gives `Cross.toml` precedence over Cargo metadata, and then
allows target/build environment variables to override those values. It also
accepts executable or privileged behavior through global Dockerfile,
pre-build, build-mode, and env settings; target-specific image, Dockerfile,
pre-build, runner, build-mode, and env settings; plus container-engine,
container-option, custom-toolchain, and alternate-config inputs. The ARM64
boundary therefore uses a complete allowlist rather than a field denylist:

- `Cross.toml` may contain only the `aarch64-unknown-linux-gnu` target, its exact
  `ghcr.io/cross-rs/aarch64-unknown-linux-gnu:0.2.5` image, the ordered seven
  approved pre-build commands, and the exact fixed-value passthrough entries.
  Global build settings, extra targets/keys, Dockerfiles, runners, build modes,
  volumes, and unfixed passthroughs are rejected.
- `Cargo.toml` must not contain `package.metadata.cross` or
  `workspace.metadata.cross` in table, dotted-key, quoted-key, or inline-table
  form. Unrelated package/workspace metadata, dependency, and version edits
  remain permitted.
- `.cargo/config` is forbidden, and `.cargo/config.toml` is parsed as a complete
  allowlist. The existing build wrapper/incremental values and every target
  linker/rustflags table are exact; only bounded retry and boolean HTTP
  multiplexing transport tuning may vary. Extra build, target, runner, rustc,
  workspace-wrapper, env, alias, credential, registry, or future root keys fail
  closed instead of becoming an alternate executable/toolchain surface.
- `build-arm64-cross` in `ci.yml` and `build-release-arm64-cross` in
  `release.yml` are isolated from the shared native matrix. Their exact job
  blocks, inherited top-level `env` mappings, and workflow trigger blocks are
  hashed by the trusted verifier, and comparison with the current trusted base
  tip rejects any PR-authored mutation while allowing unrelated workflow jobs
  to evolve. Every
  `.yml` and `.yaml` file directly under `.github/workflows`, plus every regular
  file recursively under `.github/actions`, is also compared as a collection.
  The complete `.github/scripts`, `comparison`, `scripts`, `tests/k8s`, and
  `tests/performance` automation roots are semantically compared, and literal
  repo-script edges are resolved transitively; local actions outside
  `.github/actions` and repo commands outside those scanned roots are rejected.
  This prevents moving an invocation into another workflow, action, or helper
  script without freezing benign script edits. Any new or changed Cross
  executable/configuration token outside the isolated jobs is rejected,
  including `env`-wrapped and Cargo-subcommand forms, quoted or nested
  shell/GitHub-interpolated executable spellings, custom step/default `shell`
  templates, YAML block-scalar variants, interpreter input redirection, Python
  process-API positional/keyword forms, literal or command-position
  dynamic GitHub expressions before any Cargo-compatible subcommand or
  toolchain selector, shell-variable executable indirection, partial or whole
  opaque command substitutions, Bash brace expansions and ANSI-C escapes, and
  Cross environment aliases; Bash backslash-newline continuations are
  normalized before scanning. Executable slots are recognized wherever the
  shell creates one, so nested `sh -c`/`bash -lc` scripts, `$(...)`, backtick
  and `<(...)`/`>(...)` substitutions, single-line `case` arms, wrapper
  end-of-options markers (`sudo -- cross`), absolute or home-relative tool
  paths (`/usr/bin/cargo cross`, `~/.cargo/bin/cross`), and Bash aliases bound
  to Cross under `expand_aliases` all resolve to the Cross command word. Because
  an unquoted expansion is word-split before dispatch, each expansion is also
  read as a word separator, so `cross${IFS}build` and
  `cargo${IFS}+stable${IFS}cross build` resolve exactly like literal
  whitespace at the executable, toolchain-selector, and subcommand boundaries.
  A shell can also move Cross out of the command word entirely and still run it
  by dispatching an argument vector that holds it, so a function whose body
  executes its arguments (`run() { "$@"; }`, `go() { exec "$@"; }`, `only() {
  "$1"; }`) makes every call site's argument list a command line, and a command
  line loaded into the positional parameters (`set -- cross build --target
  ...`) is read as one wherever it appears. Which names dispatch their argument
  vector is resolved from the whole program rather than from the line being
  scanned, so a definition and its call site may sit on different lines. A
  function that merely *forwards* its arguments to a named command
  (`f() { curl "$@"; }`) does not dispatch them and stays editable.
  A dynamic expression that occupies a whole command word is replaced by a
  whole command, not just by an executable name, so `run: ${{
  steps.plan.outputs.cmd }}`, a composite action's `run: ${{ inputs.cmd }}`,
  `run: $CMD`, and `run: $(plan)` all fail closed even though no literal
  `build --target` text is left on the line; an expression that is an argument
  to a named command, or that is only data, does not occupy a command word and
  stays editable. Substituting a whole command needs both a line a shell
  evaluates and a slot on it. A raw line scan also reads a workflow's non-`run`
  block scalars and a script's heredoc bodies. Prose block scalars and quoted
  heredoc bodies attached to data-writing commands are not shell-evaluated, so
  no slot on them counts: an expression inside a `prompt: |` block or a
  `cat <<'EOF'` configuration body is data the runner never dispatches,
  backticks there being Markdown rather than substitutions. An interpreter-fed
  heredoc is different: quoting its delimiter suppresses expansion by the outer
  shell, but `python3 <<'PYEOF'` still executes the body as Python, so the body
  is extracted and rescanned in that language. Unquoted heredoc bodies are data
  at line start, but the shell still evaluates command-substitution slots while
  constructing their input, so
  `$()` and backticks there fail closed — and, for the same reason, a
  substitution in such a body is followed as a repository execution edge:
  `cat <<EOF ... $(bash scripts/unsafe.sh) ... EOF` really runs that script, so
  it is recorded and scanned. Only the substitution interior becomes a command;
  the surrounding data line never gains a command slot of its own — including
  for the opaque-ARM64-executable search, which reads a program's command text
  rather than its raw lines, so `cat <<EOF ... $cmd build --target
  aarch64-unknown-linux-gnu ... EOF` is the configuration data it is while the
  same words inside a body `$()` still fail closed. The whole body is joined
  before its substitutions are read, because a substitution may open on one body
  line and close on a later one: `$(` followed by `bash scripts/unsafe.sh` and
  `)` on separate lines runs that script, and reading one physical line at a time
  saw no balanced substitution on the opener and no command slot on the
  continuation, which is still heredoc data. An arithmetic expansion in such a
  body dispatches nothing of its own — `$((scripts/build))` evaluates a division
  — so the expression itself gains no command slot, but the shell still performs
  the command substitutions *inside* an arithmetic expansion before evaluating
  it, so `$(( $(bash scripts/unsafe.sh) + 0 ))` is recursed into and that script
  is recorded and scanned. `$( (cmd) )`, the only spelling that nests a real
  substitution, still executes. Backtick substitutions are paired across
  physical lines too, because the shell permits that spelling and dropping it
  would miss a real execution edge. This can conservatively scan a backtick pair
  in Markdown written by an unquoted documentation heredoc, which is the
  fail-closed side of the ambiguity. Each
  interior runs in a subshell, so it is followed as its own nested program: a
  `cd` inside one resolves that interior's own operands and then ends with the
  subshell, instead of rewriting the working directory every later real line of
  the parent script is resolved against.
  Which bodies are quoted is decided by parsing the delimiter as the shell word
  it is. A shell suppresses body expansion when *any* character of the delimiter
  is quoted and terminates on the dequoted word, so `<<E"OF"` and `<<\EOF` are
  quoted heredocs ending at `EOF`. Reading only a wholly quoted delimiter took
  the first as the unquoted delimiter `E` — leaving the body expandable and
  running the body state past the real terminator — and did not recognize the
  second as a heredoc at all.
  A `<<` inside an arithmetic expansion is the left-shift operator rather than a
  heredoc opener, so a complete balanced `$(( ... ))` is skipped as a unit;
  advancing past only the `$((` left `echo $((1 <<EOF))` able to mark the real
  command lines after it as body data. A heredoc opened after arithmetic on the
  same line is still a heredoc. On a line a shell does evaluate, an
  explicit executable slot — `run:`, a statement
  separator, `$(`, a backtick, a conditional keyword — counts, and so does a bare
  line start, so the same expression alone on its own line inside a `run: |`
  block still fails closed. A raw source line that a backslash continuation
  joins onto the previous one has no line start of its own — `$(printf
  'ferrumedge/ferrum-edge@sha256:%s ' *)` under `docker buildx imagetools create
  ... \` is that command's last argument — so only the bare-line-start allowance
  is withdrawn there; an explicit slot on the continuation line still counts, and
  the joined logical line is scanned in its own right. A wrapper continuation
  (`env \`, `sudo \`, `timeout 30 \`) is the exception that restores the next
  line's slot, because the wrapper has not consumed its executable operand yet —
  but not inside a heredoc body, where the receiving command reads that text as
  input rather than dispatching it, and not when the wrapper is still waiting on
  an option operand. `env -u \` and `sudo -u \` end the line mid-option, so the
  word that follows is the name being unset or the user being assumed, not an
  executable; treating it as a whole-command slot is a deterministic false
  positive rather than a caught dispatch. `timeout` is the same case with a
  positional operand: its duration is mandatory and precedes the command, so
  `timeout --preserve-status \` and `timeout -k 5 \` hand the next line that
  duration, while `timeout 30 \` and `timeout --preserve-status 30 \` have
  already consumed it and do restore the slot. The same mandatory duration is
  modelled in the pattern layer, not only in the token walk: `timeout` is not an
  ordinary wrapper there either, so `timeout --preserve-status $seconds build`
  reads `$seconds` as the duration operand it is and `build` as the executable,
  instead of reporting the benign dynamic duration as an opaque Cross
  executable. The restored raw-line slot also preserves the wrapper's assignment
  semantics: after `env \` or `sudo \`, `FOO=bar $cmd` still dispatches `$cmd`,
  while after `exec \`, `nohup \`, or `timeout 30 \`, `FOO=bar` is the wrapper's
  command argv itself and no later executable slot is invented.
  Leading words that precede the executable without being it do not close the
  slot: a negation (`! cmd`), assignment words (`FOO=bar $cmd`), process
  wrappers, `env` and its options, and any number of spaced or unspaced subshell
  openers (`(`, `((`, `( (`) may all sit between the command start and an opaque
  executable word, in any combination and on either side of the opener. That one
  interleaved layer is shared by every executable-slot matcher, including the
  literal Cross scan, so `env FOO=1 sudo BAR=2 env cross build --target
  aarch64-unknown-linux-gnu` is recognized in workflows and reached shell
  automation alike; a layer that fixed wrappers before assignment words and
  allowed only a single `env` described just one of those orderings. An
  executable assembled from expansions that then dispatches a Cargo or Cross
  subcommand (`"$cmd" build`) is opaque for every target, not only the protected
  ARM64 one, so it fails closed in trusted-automation revalidation as well.
  The cheap check that decides which lines reach that analysis is held to the
  same vocabulary as the analysis itself, because a narrower gate drops a line
  before the substitution can fail closed on it. It therefore accepts the same
  command starts, the same interleaved assignment/wrapper/`env` prefix layer,
  and command substitutions as executable words, so `FOO=1 $cmd build`,
  `env $cmd build`, and `$(pick-cross) build` are all analyzed. It also accepts
  the two further spellings the ordinary Cargo/Cross parser accepts: a literal
  `cross` subcommand, since `$tool cross build` runs Cross when `$tool` is
  `cargo`, and a toolchain selector, since `$tool +nightly build` runs Cross
  when `$tool` is `cross`. A command substitution with nested parentheses is
  one expansion to the scanner but not to the cheap pattern, so every balanced
  `$(...)` span is collapsed to a single placeholder before that gate runs and
  `$( (printf cross) ) build --target aarch64-unknown-linux-gnu` reaches the
  analysis it would otherwise be dropped before. When the substitution or a
  backtick pair spans physical lines, only the newlines inside that one shell
  word are joined before classification; unrelated commands on adjacent lines
  remain separate. Widening that gate reports
  nothing by itself — every admitted line is still decided by the substitution,
  the Cross-subcommand check, and the command-context check.
  The interleaved assignment/wrapper/`env` prefix layer is one model shared by
  every discovery pattern, not only by opaque-executable scanning, so
  `env sudo bash scripts/unsafe.sh`, `sudo FOO=bar bash scripts/unsafe.sh`,
  `env sudo make -C build all`, and `env sudo python3 -m ci.build` are recorded
  as the repository script, dispatcher manifest, and Python module they really
  execute. Every alternative in that layer consumes a whole word, so it widens
  the accepted orderings of prefix words without opening data or argument
  positions.
  A block-scalar body is one string value rather than YAML structure, so prose in
  an action input declares no mapping key, alias, or merge key: `--allowedTools
  "Bash(gh pr comment:*)"` inside a `claude_args: |` body is not a `comment:` key
  aliased to `*)`. The body's text still reaches the action and is still searched
  for the Cross executable, the Cross image, and the protected target.
  A backslash-escaped backtick is literal text and
  opens no slot, so ``echo "- Test: \`${{ matrix.test }}\`"`` writes Markdown in a
  real `run:` block and stays editable. An executable heredoc is unaffected
  throughout: it is extracted and rescanned as its own program, where its lines
  are command lines again. Every queued heredoc on a command is consumed in
  opener order, so a later body in `cat <<D <<'PY' | python3` cannot hide behind
  the first delimiter. Only an outer pipeline attaches a body to an
  interpreter; pipes inside quotes, substitutions, backticks, subshells, or
  process substitutions remain nested command syntax rather than receivers of
  the heredoc.
  Binding Cross to another executable name is itself a Cross surface: linking,
  copying, moving, or installing the Cross binary under a new name, and writing
  a wrapper script whose body runs Cross, are all detected, and every later
  command-start dispatch through that name — including PATH-prepended,
  `./bin/`-relative, and assignment-prefixed forms — is expanded back to the
  Cross command word. A dynamic shim name fails closed. Shim sources are
  tokenized before the Cross token is required, so a quote- or escape-split
  source (`ln -s ~/.cargo/bin/cr"oss" bin/cr`) still binds the shim. Python
  helpers are analyzed through local process-API aliases (`run =
  subprocess.run`) and shell-wrapper argv (`subprocess.run(['sh', '-c', ...])`).
  `asyncio.create_subprocess_shell`/`create_subprocess_exec`, including their
  imported and renamed forms, are tracked alongside `os` and `subprocess`, and
  the variadic-argv APIs (`create_subprocess_exec`, `os.execl*`, `os.spawnl*`)
  have their spread arguments joined into the single command they dispatch.
  In JavaScript, importing `child_process` at all is the dispatch surface, so a
  destructured or renamed binding (`const {execSync} = require('child_process')`,
  `import {spawn as run} from 'node:child_process'`) is protected exactly like
  a `child_process.exec(...)` member call.
  Workflow `run` bodies are dispatched through their effective step, job, or
  workflow-level shell; Python shells and executable Python heredocs therefore
  receive the same AST analysis, while dynamic or unsupported shells fail
  closed. Shell, Python, Perl, PHP, R, JavaScript/TypeScript, PowerShell, awk,
  and BusyBox script launchers are recognized when resolving repository paths.
  Only shell, Python, and PowerShell file bodies have language-aware transitive
  readers; an explicit unsupported interpreter for any repository helper
  therefore fails closed instead of relying on a suffix or being downgraded to
  a bare shell reading.
  Inline interpreter source is dispatched the same way: a `run:` step that
  hands a program to Python (`-c`), PowerShell (`-Command`, any unambiguous
  prefix), Node, Deno, Bun, Perl, Ruby, PHP, Lua, R, Julia, Elixir, Groovy,
  Scala, osascript, awk, or Tcl has that program inspected rather than skipped,
  so `perl -e 'system("cross build ...")'` and `node -e ...` are rejected.
  Python inline source gets the same AST analysis as a Python shell; other
  languages have their string literals read as command text and any other
  process dispatch inside inline source treated as an unresolvable executable.
  Shell-assembled inline source (`perl -e "$PROGRAM"`) and a PowerShell
  `-EncodedCommand` fail closed, while a field reference such as awk's `$1` or
  a Perl `$name` sigil stays readable so ordinary one-liners are not frozen.
  Because shell variables are case-sensitive but equally executable, source
  that is nothing but one parameter expansion (`python3 -c "$cmd"`) and source
  referencing any name — lowercase included — that the enclosing shell program
  assigns are both treated as generated. An inline-source operand attached to
  its option letter (`perl -e'print "safe"'`) or to a single-dash long option
  is parsed as the program it is, rather than being frozen as a missing
  operand. An interpreter that reads its program from stdin is dispatched the
  same way as a shell that does, so `python3 <<< '<source>'` and
  `python3 < <(printf '<source>')` are inspected in the interpreter's own
  language instead of only in POSIX shell. Only an *unescaped* literal producer
  is folded into readable source: `echo` behavior varies between shells and
  `printf` decodes backslash escapes in its format, so `printf '\x63ross ...' |
  bash` and `echo -e '\x63ross ...' | bash` would otherwise be read as harmless
  text while the receiving shell runs Cross. A backslash anywhere in an `echo`
  operand, in a `%s` operand, or in a literal `printf` format therefore leaves
  the produced program opaque, which fails closed. That decision belongs to the
  producer rather than to the executable word, so it is reached from both
  directions: pull-request comparison and exact-tree revalidation of reached
  shell automation both reject an undecodable stdin program. Deciding it only
  under the opaque-executable analysis meant the tree path — which enters
  through the literal scan — accepted on `main` what comparison had rejected on
  the pull request. Literal shell commands extracted from Python process APIs
  re-enter that same opaque-stdin scope, including commands discovered through
  an explicit Python interpreter edge to a suffixless helper or an inline
  `python -c` program.
  A `shell: pwsh`/`powershell` body, a PowerShell `-Command` operand, a
  PowerShell heredoc, and a `SHELL ["pwsh", ...]` Dockerfile selection are
  parsed as PowerShell rather than as POSIX shell: `Start-Process`,
  `Start-Job`, `Start-ThreadJob`, and `Invoke-Command` process operands and the
  `&`/`.` call operators resolve to the executable word, while
  `Invoke-Expression`/`iex`, a computed call-operator target, a
  `[Diagnostics.Process]::Start` dispatch, and an unreadable process operand
  fail closed. A bare `$variable` stays a value expression, because PowerShell
  requires a call operator to execute a computed word.
  `env -S`/`--split-string` operands are tokenized into the argv they become
  rather than discarded as option arguments, in separated, joined
  (`--split-string=...`), and attached (`-S...`) spellings. `flock` and
  `script` are followed to their process operands, both the positional argv
  form after `flock`'s lock operand and the `-c`/`--command` shell-program
  form.
  A remote (non-`./`) `uses:` step is code this repository does not own, so a
  step whose action reference names Cross, whose inputs include a Cross-enabling
  key (`use-cross`, `cross-version`, and equivalents under case and separator
  normalization, in block or flow mappings), or whose input values carry the
  protected ARM64 target, the pinned Cross image, or the `cross` executable is a
  build-execution surface; a dynamic `uses:` reference fails closed. Benign
  pinned actions with unrelated inputs stay editable. A local (`./`) action is
  extracted and scanned as a file of its own, but the workflow's `with:` values
  are part of its executable surface too — a composite action with
  `run: ${{ inputs.cmd }}` executes whatever the call site passes — so a local
  step's inputs are held to the same Cross-input, target, and expression rules;
  only the `./` reference itself is exempt from the literal-reference check.
  The step is read as the
  single YAML mapping it is, so key order does not matter: a `with:` block
  written **above** the `uses:` line is scanned exactly like one written below
  it. Keys and values are read the way the runner parses them, not as raw
  source text: quoted spellings (`'use-cross'`, `"use-cross"`) and
  double-quoted escape sequences (`"use-cross"`, `"uses"` written with an
  escape, `args: "build --target aarch64-unknown-linux-gnu"`, and matrix
  values collected from quoted scalars) are all decoded before any Cross or
  target token is searched for. A double-quoted scalar continued with
  a trailing backslash is folded the way the runner folds it, so a target split
  across two source lines is still detected. A YAML merge key
  (`with: {<<: *cross_inputs}`) supplies inputs the step never spells, and a
  YAML alias, anchor, or tag resolves outside the step in a `uses:` reference
  (`uses: *cargo_action`) and in any value position alike (`with:
  *cargo_inputs`, `args: *arm_target`), so all of them fail closed rather than
  being read as the literal text they appear to be — the runner expands an
  aliased input map into the action's inputs before it runs, so a step that
  spells neither `use-cross: true` nor the protected target can still deliver
  both. A step written entirely as a YAML flow mapping
  (`- {uses: actions-rs/cargo@<sha>, with: {use-cross: true}}`) is the same step
  to the runner, including when the entry spans several source lines, so those
  sequence entries are entered and held to the identical reference and input
  rules instead of being skipped for not starting a line with a key. Input values are resolved rather
  than compared as literal text: an expression such as
  `args: build --target ${{ matrix.target }}` is expanded against the enclosing
  job's `matrix`, `env`, and `inputs` **declarations** — a step's `with:` keys
  are arguments to an action, never definitions, so a self-referential input
  such as `target: ${{ matrix.target }}` cannot shadow the real matrix value.
  Every expression on a line is expanded *together*, because the runner
  concatenates them all before the action sees the value, so
  `--target ${{ matrix.arch }}-${{ matrix.rest }}` assembled from literal
  fragments is caught; a line with more combinations than the enumeration limit
  fails closed. Any expansion reaching the protected target is a surface.
  A value this scanner cannot see is *unknown*, not empty: `secrets.*`,
  `github.*`, `runner.*`, `steps.*`, and `needs.*` are not author-populated
  value sets, and a prior step or job output can be set to the ARM64 target,
  so an unknown value fails closed whenever the same input already declares a
  `--target` argument. Ordinary credential and context inputs carry no target
  argument and stay editable. One narrow exception exists so release downloads
  can be isolated to exact artifact names, which necessarily name the protected
  target: for `actions/download-artifact` **pinned to a full commit SHA**, the
  target string in an artifact `name`/`path`/`pattern` input is not a surface,
  because the action only selects an already-published artifact for the current
  job and cannot start a build. `actions/upload-artifact` names and paths remain
  protected surfaces because they control the artifact identity consumed by
  later publishing jobs. That carve-out accepts the block and flow spellings of
  the same YAML (`with: {name: ...}`) equally, and applies only when every key
  on the line is one of those closed artifact inputs. The
  Cross image, a `cross` executable token, every Cross-enabling input key, any
  other input key, an unpinned reference, and any other action are all still
  surfaces; self-test fixtures assert each of those boundaries.
  Heredoc parsing is quote-aware and rejects unterminated bodies. Repository
  working-directory state changes only after each `cd` execution point and is
  rejected when conditional or loop control flow makes it ambiguous. Dockerfile
  instruction parsing is enabled only for Dockerfile-named inputs containing a
  real `FROM` instruction, so ordinary Python beginning with `from` remains
  Python. Baseline and proposed automation diagnostics are aggregated before
  surface comparison, ensuring a malformed baseline cannot suppress proposed
  findings. Generated-artifact exemptions are limited to an exact allowlist of
  literal build outputs; variable-prefixed pseudo-paths are not allowlisted,
  and a generated-looking *directory prefix* confers no exemption of its own.
  None of `target/`, `results/`, `coverage-report/`, `benchmark-results/`,
  `comparison-results/`, or `tmp/` is ignored by git, so a pull request can
  commit a script under any of them; such a script is ordinary repository code
  and is reported as outside the scanned automation roots unless it is one of
  the exact allowlisted build outputs. Those exact allowlisted outputs are
  exempt only while nothing commits them, so the pull-request comparison
  additionally requires the full proposed repository tree listing
  (`--proposed-tree-listing`, a `git ls-tree -rz --name-only` enumeration of the
  proposed commit) and rejects any commit that adds a file at one of them.
  Checking the materialized `--automation-dir` instead would be vacuous: that
  directory is reconstructed from the approved automation roots alone and could
  never show a committed executable at a repository-root path such as
  `conformance` or `ferrum-edge-linux-x86_64`. The extraction contract requires
  the listing to be passed, so a policy workflow that drops the flag is
  rejected.
  Repo-controlled build dispatchers are followed rather than trusted: a step
  running `make`, `npm`/`pnpm`/`yarn`, `just`, or `task` resolves to the
  matching root or `-C`-relocated `Makefile`, `package.json` `scripts`,
  `justfile`, or `Taskfile`, which is then scanned and frozen like any
  referenced script, and a dispatcher whose manifest is not in the scanned set
  fails closed. Make recipes are read as the shell text make emits rather than
  as raw shell: variables the makefile assigns are substituted with their real
  values, which catches `CARGO = cross` followed by `$(CARGO) build ...`, and
  `$(MAKE)`/`$(MAKE_COMMAND)` resolve to the make executable so an ordinary
  recursive-make recipe is followed as a dispatcher instead of being frozen as
  an opaque command substitution. Every other `$(...)`, including
  `$(shell ...)` and other make functions, stays opaque and keeps failing
  closed. Detection stays anchored to command positions, so prose or a
  comment mentioning `cargo install cross` does not freeze unrelated edits.
  An automation file needs no recognized extension to be executable. A reference
  under a conventional tool directory (`ci/`, `bin/`, `build/`, `scripts/`,
  `tool`, `tools/`, `dev/`, `hack/`) is followed as a repository command even
  when the name carries no suffix, and a reached file that is extensionless —
  and is not a build-dispatcher manifest — is revalidated as shell rather than
  skipped for having no detectable language. Those two halves are what close the
  edge: the first makes `ci/unsafe` and `scripts/build` discoverable without a
  `./` prefix or an interpreter word, the second makes them scannable once
  discovered. Every scanned automation root is spelled there as well —
  `.github/scripts/`, `comparison/`, `tests/k8s/`, and `tests/performance/` —
  because a root this policy already scans is exactly where a direct
  `run: .github/scripts/build` would otherwise go unrecorded, just as omitting
  `scripts/` once left `run: scripts/build` unscanned.
  Python automation reached this way has dynamic process commands rejected
  rather than silently dropped, so an argv assembled into a variable
  (`cmd = ['python3', 'ci/unsafe.py']; subprocess.run(cmd)`) fails closed
  instead of reading as an unresolvable literal. The same rejection applies to a
  Python heredoc a reached shell script executes (`python3 <<'PY' ... PY`),
  which would otherwise be the one Python surface that accepted a variable
  process command.
  The interpreter an invocation names is carried with the path it runs, because
  it is the only evidence of language a file with neither suffix nor shebang
  has. `python3 ci/unsafe` therefore reads that file as Python — extracting and
  checking its process calls — instead of reporting it as automation with no
  scannable interpreter, while the extensionless shell revalidation above still
  runs. The two readings are a union rather than a choice, so nothing an earlier
  class already rejected stops being rejected, and a bare `./ci/unsafe` that
  names no interpreter invents none. A bare extensionless reference is read as
  shell during traversal as well as during revalidation, so `run: scripts/build`
  is followed into the script instead of being reported as automation with no
  scannable interpreter by the very stage whose successor does scan it; an
  explicit interpreter and a build-dispatcher manifest keep their own readings.
  PowerShell provenance is replayed the same way Python provenance is: `pwsh
  scripts/opaque` reaching an extensionless file adds a cmdlet reading to the
  shell one, so `Start-Process cross -ArgumentList 'build --target ...'` — which
  is not a dispatch in POSIX shell at all — still fails closed. Pull-request
  surface comparison receives the same provenance and applies it to both the
  merge-base and the proposed tree, so a proposed no-shebang `scripts/opaque`
  reached by `python3 scripts/opaque` is compared as Python rather than as
  unread text, and the two sides stay symmetric.
  Provenance is applied whenever it appears, not only the first time a path is
  reached. A suffixless script already reached bare and read as shell is re-read
  when a later edge names `python3` or `pwsh` for it, so the process calls inside
  that alternate-language reading are followed too; skipping on reachability
  alone meant `scripts/a` discovered first as shell and later as `python3
  scripts/a` never had its `subprocess.run(['bash', 'scripts/unsafe.sh'])` edge
  added. Provenance only accumulates, so the walk settles in a bounded number of
  passes and reports rather than assumes if it cannot.
  A reached build-dispatcher recipe is shell, so it is scanned with the whole
  trusted-shell surface policy rather than a subset of it: literal Cross, wrapped
  literal Cross, generated inline shell, an opaque ARM64 execution, an opaque
  Cross executable for *any* target (`cmd=$(printf cross); "$cmd" build`), and an
  undecodable stdin producer such as `printf '\x63ross build --target ...' | bash`
  all fail closed during exact-tree revalidation and not only during pull-request
  comparison. A recipe whose producer is an ordinary unescaped literal stays
  readable and stays editable.
  Those raw-text searches read a program's command text rather than its raw
  lines, for the same reason the opaque-ARM64 search does. A reached script that
  *writes* a literal template — `cat <<'EOF'` holding `bash -c "$(render)"` — is
  not executing that inline shell, so the quoted body no longer reports a
  generated inline shell surface that would block safe automation edits. The
  narrowing is not a weakening: an unquoted body's substitutions are re-emitted
  as the command lines they really are, backslash continuations are folded first,
  and an unterminated heredoc withdraws the narrowing and reads the program raw.
  Cross-sensitive jobs, local-action files, and
  reachable scripts are represented by full digests, while unrelated workflow,
  action, and script additions or edits remain permitted. The isolated jobs use
  only pinned external setup actions before revalidation.
- The `needs` fields that connect ARM64 artifacts to `latest-release`, CI and
  release Docker publishing, and `create-release` are separately protected;
  the CI publishers' success conditions are protected too. Only those direct
  publication-control fields are frozen, so unrelated implementation changes
  inside the publishing jobs remain permitted.
- The Docker jobs never name the ARM64 artifact literally; they select it
  through matrix values. Their `strategy` block and the two steps that consume
  it — `Download Linux binary` (`name: binary-${{ matrix.binary_target }}` /
  `release-binaries-${{ matrix.binary_target }}`) and `Prepare Docker context`
  (which copies `${{ matrix.binary_asset }}` and `${{ matrix.cni_asset }}` into
  `${{ matrix.arch_dir }}`) — are therefore frozen as one artifact-selection
  contract in both workflows. Without it a pull request could repoint the
  `linux/arm64` row at the x86_64 artifact and publish an ARM64 image
  containing the wrong binary while the protected ARM64 build still succeeded.
  Freezing those two steps alone would still leave the rest of the job able to
  rewrite the context they prepared: a pull request could keep the matrix and
  both steps byte-for-byte identical, add a second download of the x86_64
  artifact, and copy it over `docker-context/bin/arm64/ferrum-edge` before the
  image is built. The **entire `steps:` list** of each Docker publishing job is
  therefore frozen as well, in both workflows and against both the pinned
  contract and the merge base, so no later step — including one that assembles
  the context path out of shell variables, or repoints the build's `context:`
  input — can touch the prepared per-arch binaries. Editing a Docker publishing
  job requires updating `PUBLISH_CONTROL_CONTRACTS` in the same commit; the
  remaining publishing jobs stay editable.
- The manifest jobs that assemble the published tags select their inputs by
  **wildcard**, not by name: `docker-manifest` and `docker-ebpf-manifest`
  download `docker-digest-*`/`docker-ebpf-digest-*` into `/tmp/digests` and
  hand every file in that directory to `docker buildx imagetools create`.
  Freezing the per-platform producers alone therefore left the published
  `latest` and release tags reachable, because artifacts are scoped to the
  **workflow run** rather than to `needs`: a pull request could add an unrelated
  push-only job that uploads one more matching digest and have it collected with
  no edge in the job graph at all. Each manifest job's `needs`, its gating
  condition, its `Download digests` step, and the `imagetools create` commands
  are frozen, `docker-ebpf`'s `needs`, `strategy`, and `Upload digest` step are
  frozen alongside the other producers, and — because freezing the job graph
  cannot stop an *added* job — the digest artifact **name space itself is
  owned**: only `docker` may produce a `docker-digest-*` name and only
  `docker-ebpf` may produce a `docker-ebpf-digest-*` one. A name assembled by an
  expression is ruled out only when its literal prefix already disagrees with
  the wildcard, so `docker-digest-${{ github.actor }}` from any other job is
  rejected while `binary-${{ matrix.target }}` and unrelated artifact names stay
  editable. This is checked against both the pinned contract and the proposed
  tree, so an added job is caught even though it changes no frozen field.
  Ownership does not depend on how the uploading step is written: every
  `actions/upload-artifact` reference is checked whatever its ref (tag, branch,
  SHA, or none), and a repo-local composite action may not produce a digest
  artifact at all, because the job that calls it — and therefore whether it is
  the frozen owner — is not knowable from the action file.
- Every job that publishes by **wildcard** freezes its whole `steps:` list, not
  only the download that feeds it. `latest-release` and `create-release` publish
  whatever is left in `release-assets/` (`files: release-assets/*` and
  `gh release create ... release-assets/*`), and the manifest jobs publish
  whatever digests the download produced. Freezing only the download list or the
  `needs` graph therefore left every other step of those jobs — including one
  whose stated purpose is release notes — free to add a wildcard download, copy
  an extra file into `release-assets`, or hard-code an additional digest into a
  published tag. The frozen step lists are `latest-release` and `docker-manifest`
  in CI and `create-release`, `docker-manifest`, and `docker-ebpf-manifest` in
  the release workflow. Changing one is a trusted-base change on `main`, exactly
  like the protected ARM64 build job; the published outputs themselves are
  unchanged.
- Flow-spelled YAML is normalized before scanning. `- {uses: ./evil-action}`,
  `- {run: ./evil.sh}`, `with: {name: docker-digest-evil}`, and
  `defaults: {run: {shell: python}}` are the same documents to the runner as
  their block spellings, but every line-oriented scan — local-action roots,
  repository-script following, artifact-name ownership, and workflow shell
  selection — independently loses sight of them. Rather than teach each scan a
  second syntax, one shared layer renders the flow spellings into the block lines
  they stand for and the existing scans are repeated over that rendering, with
  reported line numbers mapped back to the physical source line. The raw pass is
  unchanged, so the normalized pass can only add findings: no anchor, alias,
  merge-key, expression, literal-value-set, shell, local-action, artifact
  ownership, generated-command, or frozen-contract protection is replaced by it.
  Block-scalar bodies are left alone — `- {a: b}` inside a `run: |` script is a
  shell argument, not a step — and a malformed flow collection is reported rather
  than read as an absent one.
- The two protected workflows reach the trusted pull-request gate only through
  their own comparison, because `ci.yml` and `release.yml` are excluded from the
  generic workflow collection. That comparison read only the raw rendering, so a
  flow-spelled step outside the protected ARM64 job produced no surface on either
  side and compared equal. The proposed and merge-base copies of both workflows
  are now scanned through the same flow-normalized second pass the absolute
  contract uses, and the digest-ownership scan the comparison already ran against
  the proposed tree is repeated over that rendering. **Deliberate boundary:** the
  hash-frozen protected job, top-level `env`, and trigger stay *comparisons*
  against the live trusted base rather than absolute re-validations of the
  proposed file, so a base that predates the contract — or the bootstrap commit
  that introduces it — is not retroactively frozen. Everything that is a policy
  rule rather than a base-relative digest is enforced against the proposed tree
  directly.
- A repo-local composite action is checked for digest uploads on the **proposed**
  side of a pull request, not only in the trusted baseline. Adding an
  `actions/upload-artifact` step named `docker-digest-*` to an existing action
  such as `setup-sccache` introduces no Cross token, so the Cross-surface
  comparison sees no change; the action would pass the gate and then contribute
  an extra digest to the wildcard manifest job on the next `main` or tag run. The
  guard is absolute rather than compared, because a local action may never own a
  digest name at all, and it runs over the flow rendering as well.
- Committed Python bytecode is rejected instead of being skipped by suffix. A
  `.pyc` under a scanned automation root is executable automation that no reader
  here can inspect, and `cd scripts && python evil.pyc` is a spelling the command
  scanner did not even recognize, so Cross or publishing code inside the bytecode
  was never examined. Bytecode operands are now recognized and rejected wherever
  they are invoked, committed `.pyc`/`.pyo` paths are rejected from the proposed
  tree listing and from every git-reconstructed automation tree — including
  nested `__pycache__` directories — and the live working copy still ignores the
  interpreter's own untracked cache, which `git ls-tree` never reports, so a
  generated file cannot produce a false positive.
- A relative command operand is resolved from the directory the shell is
  actually in. `cd docs; bash scripts/coverage.sh` runs `docs/scripts/coverage.sh`,
  but the tracked directory was previously applied only to slashless names, so
  the policy recorded and scanned the approved-root `scripts/coverage.sh` while
  the runner executed an unscanned same-name path. Every relative repository
  command now inherits the tracked directory, `..` is normalized across nested
  and repeated `cd`s instead of discarding the directory state, and anything that
  leaves the tree — an absolute path, `~`, `cd -`, an expansion, a conditional
  `cd`, or a traversal above the repository root — fails closed. Absolute
  handling and correct root-relative resolution are unchanged.
- `python -m <module>` is an executable repository dispatch. Only inline `-c`
  programs were extracted, so `python -m cross build --target
  aarch64-unknown-linux-gnu` read as a benign Python invocation even though
  Python loads a module from the checkout. Interpreter options are now parsed
  through `-m` — including bundled clusters (`-Im`), attached modules (`-mpkg`),
  and operand-taking options (`-W`, `-X`) — and a literal module is resolved
  against the tracked directory to `<module>.py` or `<module>/__main__.py`, which
  must be a scanned automation file. A computed module name, an unmodeled option
  that could move the module slot, an unknown working directory, or a module that
  resolves outside the approved roots all fail closed. Modules that ship with the
  interpreter or an installed tool (`py_compile`, `pip`, `venv`, `unittest`,
  `json.tool`, and the rest of the allowlist) stay usable, and `-c`, `-`, and
  ordinary script-path invocations are untouched.
- `rustup run <toolchain> <command>` executes its command operand like `nice` or
  `timeout`, with a mandatory toolchain operand in between, so executable
  dispatch follows it: `rustup run stable ./cross build --target ...` is read as
  the `./cross` invocation it is. Subcommands that only manage toolchains and
  components (`component`, `toolchain`, `target`, `update`, and the rest) execute
  nothing the caller named and are not followed, so ordinary
  `rustup component add clippy` stays editable and no trust is extended to
  repository executables outside the approved automation roots.
- `latest-release` and `create-release` download the five build artifacts by
  exact name instead of by a `binary-*`/`release-binaries-*` wildcard, so an
  unrelated job cannot contribute a colliding upload to a published release.
  Each then copies a closed, auditable list of exact trusted files, asserts
  that the published set equals that list exactly, and verifies every `.sha256`
  sidecar before publishing. Native and protected ARM64 publishing are both
  preserved: the ARM64 artifact is downloaded under its own exact name.
- The Cross process starts through `env -i` with an explicit minimal host
  environment and fixed compiler variables. This removes `CROSS_CONFIG`, every
  `CROSS_BUILD_*`/`CROSS_TARGET_*` alias, image/Dockerfile/pre-build/runner
  overrides, custom-toolchain and compatibility flags, Docker/Podman engine and
  option overrides, remote mode, Cargo default-target overrides, and arbitrary
  inherited `CARGO_*` passthrough values before Cross reads configuration.

The trusted `pull_request_target` job checks out only the base SHA with
read-only contents permission, and verifies that the checkout is exactly the
triggering base SHA because it is the only code the job executes. Because
`main` can advance after the event is created, the job then fetches the live
base branch tip into a fixed local ref, requires it to descend from the
triggering base SHA, and pins it to one immutable commit SHA that every
baseline extraction and comparison reads; a live tip that does not descend from
the triggering base is a rewritten or confused ref and fails closed. It fetches
the PR head without checking it out,
requires the fetched object to equal the immutable head SHA from the triggering
event, then extracts `Cross.toml`, `Cargo.toml`, `.cargo/config.toml`, the
complete proposed and live-base workflow and repo-local action directories,
and the approved automation roots plus the root build-dispatcher manifests as
hostile data. The verifier it executes, and every trusted contract that
verifier reads — `ci.yml`, `release.yml`, the workflow, local-action, and
automation baselines, and the trusted policy workflow itself — are all
extracted from that one pinned live trusted tip, never from the possibly stale
event-base checkout, so a Cross surface that only the newer live-base verifier
recognizes is still enforced. GitHub loads the policy workflow file itself from
the event base and it therefore cannot be re-executed from the live tip; that
extraction contract is instead authenticated by comparison and fails closed
when the trusted tip has moved it, which self-heals as soon as the pull
request's base is updated. Each NUL-delimited
`git ls-tree` result is materialized and its status checked before consumption;
regular blobs may use letters, digits, `.`, `_`, `+`, `@`, `~`, spaces, and
`-`, while dot-dot components, symlinks, gitlinks, and NULs fail closed. A
proposed legacy `.cargo/config` is surfaced and rejected. Proposed executable
and configuration surfaces are compared with the live trusted base tip,
preventing both a stale branch and a stale event base from restoring a surface
removed from main. The verifier and trusted workflow themselves are compared
with `<live base>...<PR head>`, preserving merge-base behavior only for the
question of whether the PR authored a protected-file modification, mode change,
rename, or deletion. The verifier enforces this shape on the trusted workflow
itself, rejecting a baseline read from the stale event-base checkout as well as
an unfetched, unpinned, or unauthenticated live base. On pull
requests, the ordinary `CI Plan` executes the base branch's
trusted verifier when it exists and never imports or runs the proposed script.
For this one bootstrap PR, where no base verifier or base-loaded trusted
workflow can exist yet, CI syntax-compiles and executes the reviewed proposed
verifier; all later PRs necessarily execute the protected base copy. Every
verifier invocation uses Python isolated mode so the script directory,
`PYTHONPATH`, and user site cannot redirect its standard-library imports. This
policy step runs before every other repository Python entry point in the plan
job, and the subsequent planner self-test and its imported live-suite path
filter are also extracted from the base branch on pull requests. The planner
example consumes the exact `origin/${BASE_REF}` fetched by the immediately
preceding policy step, so those adjacent steps have an intentional ordering
dependency.

#### 8. Latest Release and Docker Jobs

**Runs**: `ubuntu-latest`

On pushes to `main`, the `main-publish-gate` job runs after the native build matrix and the `Tests` aggregate, then waits for successful same-commit push runs of the dedicated Coverage, Gateway API Conformance, and Mesh E2E Sidecar Live Datapath workflows. Each requirement is queried through its canonical workflow-file endpoint and accepted only when the server-reported workflow path, display name, commit SHA, `push` event, and `main` branch all match. A different workflow that reuses the display name therefore cannot satisfy a missing canonical run, and every matching canonical run must conclude `success`, so one passing duplicate cannot mask a failed run of the same workflow for the same commit. A missing, still-running, failed, cancelled, stale, malformed, identity-mismatched, or timed-out dedicated run fails the gate closed. Each Actions API query receives up to three bounded attempts with short backoff; exhausting those attempts also fails closed. The gate polls for at most 60 minutes inside a 75-minute job timeout, runs only on `main` pushes so it never holds a runner on a pull request, and grants only `actions: read` because it checks out no code. The protected Cross verifier freezes the complete gate job and rejects workflow-wide run defaults that could alter a protected publishing shell's failure semantics, while the required-CI verifier independently pins the gate's exact digest, checks the three workflow file/name bindings and their unconditional `main` push triggers, and validates the publisher dependencies. Comments cannot stand in for executable gate fields, and changing the gate or either publishing dependency requires a trusted-base update. The `latest-release` job and the per-architecture Linux Docker publishing job keep their direct dependencies on the `Tests` aggregate, the native build matrix, and the protected `build-arm64-cross` job, and additionally require a successful `main-publish-gate`; they can run in parallel only once all four succeed. The `docker-manifest` job runs after the Docker digests are pushed. A Docker failure on `main` does not block replacing the `latest` prerelease, but neither publish path can start until every release check passes. Version-tag releases are stricter and gate GitHub Release creation on `docker-manifest`. Docker Hub publishing requires the `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` repository secrets. GHCR publishing uses `GITHUB_TOKEN` and the job-level `packages: write` permission. The Docker manifests publish both `latest` and `main-<sha>` tags (where `<sha>` is the full commit SHA from `github.sha`).

## Release Pipeline (release.yml)

The Release pipeline creates official releases when a version tag is pushed. It
first verifies that the tag is exactly `v` followed by the `[package]` version
from `Cargo.toml`. It then resolves the tag to its target commit and waits for
successful `CI` and `Coverage` workflow runs for that exact SHA before any
release binary or image job starts. A version mismatch fails immediately, and
every build and publishing job depends transitively on this guard.

Release runs use `concurrency.group: release-${{ github.ref }}` with `cancel-in-progress: false`, so a versioned release is never canceled by a later tag push.

### Trigger

Push a tag matching the pattern `v*`:

```bash
# Create and push tag
git tag v0.2.0
git push origin v0.2.0
```

### Validate Release Version Job

**Runs**: `ubuntu-latest`

Extracts the `[package]` version from `Cargo.toml` and requires
`GITHUB_REF_NAME` to equal `v${CARGO_VERSION}`. A mismatch produces a clear
workflow error and stops the release before CI polling, builds, registry pushes,
or GitHub Release creation. The guard adds no secrets or elevated permissions.

### Validate Release SHA Job

**Runs**: `ubuntu-latest`

Validates that the tag name matches the release pattern and that the tag target
commit has successful `ci.yml` and `coverage.yml` runs from a `push` event.
Manual workflow dispatches do not satisfy this release gate because they do not
necessarily execute the same required `Tests` aggregate. If either workflow has
not passed for the exact SHA, the release waits for the push run and then fails
before publishing binaries or registry tags if it still has no success.

### Release Build Job

**Runs**: `ubuntu-latest`, `macos-latest`, `windows-latest` (four-target native
matrix plus the isolated Linux ARM64 job)

Depends on `Validate release SHA`, then builds optimized release binaries for all target platforms:

**Targets**:
- `x86_64-unknown-linux-gnu` - Linux x86_64
- `aarch64-unknown-linux-gnu` - Linux ARM64
- `x86_64-apple-darwin` - macOS x86_64
- `aarch64-apple-darwin` - macOS ARM64 (Apple Silicon)
- `x86_64-pc-windows-msvc` - Windows x86_64

**Build Process**:
1. Checkout code at tag commit
2. Install Rust toolchain with target
3. Install protobuf compiler plus platform prerequisites (Linux `libcurl4-openssl-dev`, Windows NASM)
4. Build release binary in `--release` mode with `--features cloud-secrets`
5. Generate SHA256 checksum
6. Upload artifact

**Cross-Compilation**:
- Linux ARM64 uses checksum-verified `cross` 0.2.5 in the isolated protected invocation job; `cross` requires Docker on the build host.
- Other targets use standard `cargo build`; macOS x86_64 builds on the `macos-latest` runner (currently ARM64) with the standard Apple/Rust target tooling — pin to a concrete runner image such as `macos-14` if the host architecture must be guaranteed.

**Output**:
- Binary: `ferrum-edge-{platform}`
- Checksum: `ferrum-edge-{platform}.sha256`

### Create Release Job

**Depends On**: Release Build Job, Docker Manifest Job, and Docker eBPF Manifest Job

Creates a GitHub Release with all binaries and checksums only after the versioned Docker manifests have been pushed. A Docker Hub or GHCR manifest failure blocks GitHub Release creation.

**Release Content**:
1. Release title: Version tag (e.g., `v0.2.0`)
2. Release description: Generated release notes including:
   - List of binary platforms
   - SHA256 checksums for verification
   - Download instructions
3. Attachments: All platform-specific gateway binaries, plus Linux `ferrum-cni` binaries for manual CNI installs

**Release Notes Example**:
````markdown
# Release v0.2.0

## Binaries

Pre-built binaries for all supported platforms:

| Platform | Binary |
|----------|--------|
| Linux x86_64 | `ferrum-edge-linux-x86_64` |
| Linux x86_64 CNI plugin | `ferrum-cni-linux-x86_64` |
| Linux ARM64 | `ferrum-edge-linux-aarch64` |
| Linux ARM64 CNI plugin | `ferrum-cni-linux-aarch64` |
| macOS x86_64 | `ferrum-edge-macos-x86_64` |
| macOS ARM64 (Apple Silicon) | `ferrum-edge-macos-aarch64` |
| Windows x86_64 | `ferrum-edge-windows-x86_64.exe` |

## Docker

```bash
docker pull ferrumedge/ferrum-edge:v0.2.0
docker pull ghcr.io/ferrum-edge/ferrum-edge:v0.2.0
```

## Checksums

Verify the integrity of downloaded binaries:

```
abc123... ferrum-edge-linux-x86_64
def456... ferrum-edge-linux-aarch64
...
```

## Usage

Download the binary for your platform and make it executable:

```bash
chmod +x ferrum-edge-linux-x86_64
FERRUM_MODE=file FERRUM_FILE_CONFIG_PATH=config.yaml ./ferrum-edge-linux-x86_64 run
```
````

## How Releases Work

### Version Management

**Current Version**: Defined in `Cargo.toml`

```toml
[package]
name = "ferrum-edge"
version = "<version>"
```

**Release Process**:
1. Record notable changes in `CHANGELOG.md` under `Unreleased`
2. Update `Cargo.toml` version to the intended release version before tagging
3. Tag: `git tag v<version>` (matching the new version exactly)
4. Release: GitHub Actions automatically builds and publishes

During active build-out, any breaking change to configuration shapes,
environment variables, schema, defaults, or other user-facing behavior must add
an `Unreleased` changelog entry in the same pull request. Release preparation
moves those entries under the new version heading.

### Version Numbering

Follow semantic versioning:

- **MAJOR.MINOR.PATCH** (e.g., `1.2.3`)
- **v** prefix for tags (e.g., `v1.2.3`)
- **Examples**:
  - `v0.1.0` - Initial release
  - `v0.2.0` - Minor feature addition
  - `v0.2.1` - Bug fix
  - `v1.0.0` - Major release

### Git Tag Naming

Always use `v` prefix and match `Cargo.toml` version:

```bash
# Correct
git tag v0.2.0   # matches Cargo.toml version = "0.2.0"

# Incorrect (won't trigger release)
git tag 0.2.0
git tag release-0.2.0

# Incorrect (workflow fails because Cargo.toml still says 0.2.0)
git tag v0.3.0
```

## Creating a New Release

### Prerequisites

- Modify `Cargo.toml` with new version
- Move the relevant `CHANGELOG.md` entries from `Unreleased` to the new version heading
- Successful `CI` and `Coverage` workflow runs for the exact commit that will be tagged
- GitHub repo with Actions enabled
- Write permission to repository

### Step-by-Step

**1. Update Version in Cargo.toml**

```bash
# Edit the existing [package] version line in Cargo.toml.
$EDITOR Cargo.toml
```

**2. Commit Changes**

```bash
git add Cargo.toml
git commit -m "chore: bump version to 0.2.0"
git push origin main
```

**3. Wait for CI to Pass**

- Push to main triggers CI and Coverage
- Wait for both workflows to pass for the exact commit you will tag
- Check GitHub Actions tab for status

**4. Create and Push Version Tag**

```bash
# Create tag pointing to HEAD
git tag -a v0.2.0 -m "Release version 0.2.0"

# Push tag to GitHub
git push origin v0.2.0
```

**5. Release Triggered Automatically**

- GitHub Actions detects tag matching `v*`
- Release pipeline starts automatically
- The tag is checked against the `Cargo.toml` package version before any publishing work
- The tag target SHA is validated against successful CI and Coverage runs before publishing starts
- Binaries built for all platforms
- Release created with checksums

**6. Verify Release**

```bash
# GitHub CLI
gh release view v0.2.0

# Check binaries
gh release download v0.2.0 --dir ./binaries

# Verify checksums
sha256sum -c ferrum-edge-*.sha256
```

### Alternative: Manual Release Creation

If automatic release fails:

```bash
# Build binaries manually with the same release features as CI. Install protoc
# for every host first. Linux hosts also need libcurl4-openssl-dev, Windows
# MSVC builds need NASM in PATH. For Linux ARM64, install the pinned Cross 0.2.5
# binary and copy the exact `env -i` invocation from build-release-arm64-cross;
# do not substitute an unpinned `cargo install cross` or inherited environment.
# On a Linux host:
cargo build --features cloud-secrets --release --target x86_64-unknown-linux-gnu
# Then run the complete pinned ARM64 command from build-release-arm64-cross in
# .github/workflows/release.yml (including its revalidation and `env -i` block).

# On a macOS host:
cargo build --features cloud-secrets --release --target x86_64-apple-darwin
cargo build --features cloud-secrets --release --target aarch64-apple-darwin

# On a Windows host:
cargo build --features cloud-secrets --release --target x86_64-pc-windows-msvc

# Stage platform-suffixed assets before checksums/upload, matching CI asset names.
# Run these POSIX staging commands from one checkout after copying in the built
# artifacts from the Linux, macOS, and Windows hosts. On Windows-only recovery,
# use equivalent PowerShell commands or copy the .exe back to a POSIX shell.
mkdir -p dist
cp target/x86_64-unknown-linux-gnu/release/ferrum-edge dist/ferrum-edge-linux-x86_64
cp target/aarch64-unknown-linux-gnu/release/ferrum-edge dist/ferrum-edge-linux-aarch64
cp target/x86_64-apple-darwin/release/ferrum-edge dist/ferrum-edge-macos-x86_64
cp target/aarch64-apple-darwin/release/ferrum-edge dist/ferrum-edge-macos-aarch64
cp target/x86_64-pc-windows-msvc/release/ferrum-edge.exe dist/ferrum-edge-windows-x86_64.exe

# Generate per-asset checksums, matching CI release assets.
(cd dist && for asset in \
  ferrum-edge-linux-x86_64 \
  ferrum-edge-linux-aarch64 \
  ferrum-edge-macos-x86_64 \
  ferrum-edge-macos-aarch64 \
  ferrum-edge-windows-x86_64.exe
do
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$asset" > "$asset.sha256"
  else
    shasum -a 256 "$asset" > "$asset.sha256"
  fi
done)

# Create release in GitHub UI or via gh:
# The glob matches both binaries and their .sha256 sidecars.
gh release create v0.2.0 \
  dist/ferrum-edge-* \
  --title "Release v0.2.0" \
  --generate-notes
```

This manual GitHub Release fallback only recreates release assets. If the tag workflow also failed before Docker publishing completed, rerun/fix the release workflow or manually publish the Docker Hub and GHCR images before treating the version release as complete.
Generated notes are acceptable for this fallback, but they do not include the workflow's curated Docker pull and checksum sections.

## Binaries and Downloads

### GitHub Releases Page

All released binaries available at:
```
https://github.com/ferrum-edge/ferrum-edge/releases
```

### Download Latest Release

```bash
# Using GitHub CLI
gh release download --repo ferrum-edge/ferrum-edge -p "*linux-x86_64"

# Using curl
RELEASE_URL=$(curl -s https://api.github.com/repos/ferrum-edge/ferrum-edge/releases/latest | \
  jq -r '.assets[] | select(.name == "ferrum-edge-linux-x86_64") | .browser_download_url')
curl -L -o ferrum-edge $RELEASE_URL
chmod +x ferrum-edge
```

### Platform-Specific Binaries

**Linux x86_64** (Intel/AMD 64-bit)
```bash
gh release download v0.2.0 -p "ferrum-edge-linux-x86_64"
chmod +x ferrum-edge-linux-x86_64
./ferrum-edge-linux-x86_64 run
```

**Linux ARM64** (ARM 64-bit, Graviton, etc.)
```bash
gh release download v0.2.0 -p "ferrum-edge-linux-aarch64"
chmod +x ferrum-edge-linux-aarch64
./ferrum-edge-linux-aarch64 run
```

**macOS x86_64** (Intel Macs)
```bash
gh release download v0.2.0 -p "ferrum-edge-macos-x86_64"
chmod +x ferrum-edge-macos-x86_64
./ferrum-edge-macos-x86_64 run
```

**macOS ARM64** (Apple Silicon M1/M2/M3)
```bash
gh release download v0.2.0 -p "ferrum-edge-macos-aarch64"
chmod +x ferrum-edge-macos-aarch64
./ferrum-edge-macos-aarch64 run
```

**Windows x86_64** (Intel/AMD 64-bit)
```powershell
gh release download v0.2.0 -p "ferrum-edge-windows-x86_64.exe"
./ferrum-edge-windows-x86_64.exe run
```

### Checksum Verification

Always verify binary integrity using SHA256:

```bash
# Download release files
gh release download v0.2.0

# Verify checksums
sha256sum -c *.sha256

# Expected output:
# ferrum-edge-linux-x86_64: OK
# ferrum-edge-linux-aarch64: OK
# ferrum-edge-macos-x86_64: OK
# ferrum-edge-macos-aarch64: OK
# ferrum-edge-windows-x86_64.exe: OK
```

### Docker Images

Pre-built Docker images are published to Docker Hub and GitHub Container Registry by the main-push and version-tag workflows. Docker Hub credentials must be configured before those publish workflows run:

```bash
docker pull ferrumedge/ferrum-edge:latest
docker pull ferrumedge/ferrum-edge:main-<sha>
docker pull ferrumedge/ferrum-edge:v1.2.3
docker pull ferrumedge/ferrum-edge:1.2.3
docker pull ferrumedge/ferrum-edge:1.2

docker pull ghcr.io/ferrum-edge/ferrum-edge:latest
docker pull ghcr.io/ferrum-edge/ferrum-edge:main-<sha>
docker pull ghcr.io/ferrum-edge/ferrum-edge:v1.2.3
docker pull ghcr.io/ferrum-edge/ferrum-edge:1.2.3
docker pull ghcr.io/ferrum-edge/ferrum-edge:1.2
```

The Docker `latest` tag tracks the latest successful `main` publish, not necessarily the newest stable version tag. The `main-<sha>` tag uses the full commit SHA from `github.sha`.

The GHCR path is `ghcr.io/${{ github.repository }}` in the workflows, so it auto-tracks the GitHub repository owner/name if the repository is moved or forked. The Docker Hub repo `ferrumedge/ferrum-edge` is hardcoded in both `ci.yml` and `release.yml`; forks must edit that `name=` value (and configure their own `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN`) before Docker Hub pushes will succeed.

## GitHub Actions Secrets

Configure secrets for Docker image publishing and releases.

### Accessing Secrets Settings

1. Go to GitHub repository
2. Settings → Secrets and variables → Actions
3. Create new repository secrets

### Required Secrets

#### Docker Registry

Required for pushing Docker Hub images. The workflows unconditionally run the Docker Hub login step on main-push and version-tag Docker jobs, so missing secrets fail publishing:

- `DOCKERHUB_USERNAME` - Docker Hub username
- `DOCKERHUB_TOKEN` - Docker Hub access token

**Generate Docker Token**:
1. Log in to Docker Hub
2. Account Settings → Security
3. Create new access token
4. Copy token to `DOCKERHUB_TOKEN`

For GHCR publishing, the workflows use `GITHUB_TOKEN`. The workflows declare job-level `permissions: { contents: write }` for release creation and `permissions: { contents: read, packages: write }` for Docker/GHCR publishing. Repository **Settings → Actions → General → Workflow permissions** must allow read/write access (including `packages: write`) for those per-job grants to take effect.

### Secret Usage in Workflows

The Docker Hub login steps use:

```yaml
with:
  username: ${{ secrets.DOCKERHUB_USERNAME }}
  password: ${{ secrets.DOCKERHUB_TOKEN }}
```

### Setting Secrets

```bash
# Using GitHub CLI
gh secret set DOCKERHUB_USERNAME --body "your-username"
gh secret set DOCKERHUB_TOKEN --body "your-token"

# Via web UI
1. Settings → Secrets and variables → Actions → New repository secret
2. Name: DOCKERHUB_USERNAME
3. Value: your-username
4. Click "Add secret"
```

## Customizing CI/CD

### Adding New Targets

For a new native target, edit both `.github/workflows/ci.yml`
(`build-binaries`) and `.github/workflows/release.yml`
(`build-release-binaries`):

```yaml
strategy:
  matrix:
    include:
      # Example: add a Linux musl target
      - os: ubuntu-latest
        target: x86_64-unknown-linux-musl
        artifact_name: ferrum-edge
        asset_name: ferrum-edge-linux-x86_64-musl
```

Musl targets need their own toolchain setup. Add `musl-tools` before a native
`cargo build`. A Cross-backed target requires a separate isolated invocation
job, a complete Cross configuration allowlist, fixed empty environment, and an
updated trusted verifier contract; do not add an unguarded Cross invocation to
the native matrix.

### Skipping Steps

Skip the entire workflow run for a commit:

```bash
# Skip CI for documentation changes
git commit -m "docs: update README [skip ci]"

# Skips the whole GitHub Actions workflow run for this commit
```

### Custom Build Flags

Modify build commands in workflows:

```yaml
- name: Build with custom features
  run: cargo build --release --features "cloud-secrets"
```

### Notification Integration

Add notifications to CI failures:

```yaml
- name: Notify Slack
  if: failure()
  uses: slackapi/slack-github-action@v1
  with:
    webhook-url: ${{ secrets.SLACK_WEBHOOK }}
```

## Troubleshooting

### Release Not Triggering

**Check**:
- Tag format: Must be `v*` (e.g., `v0.2.0`)
- Tag exists: `git tag` lists tags
- Push origin: `git push origin v0.2.0`

```bash
# Verify tag
git tag -l "v*"
git show v0.2.0

# Check GitHub Actions
# Settings → Actions → All workflows
```

### Build Failures

**Check logs**:
1. Go to GitHub Actions tab
2. Click failing workflow
3. Expand job logs for details

**Common Issues**:
- Build prerequisites: CI installs `protoc` on every OS, `libcurl4-openssl-dev` on Linux, and NASM on Windows
- Missing dependencies: Check `Cargo.toml` and the release Build Process prerequisites above
- Rust version: Workflows use `stable` Rust toolchain

### Docker Push Failing

**Verify secrets**:
```bash
gh secret list
# Should show DOCKERHUB_USERNAME and DOCKERHUB_TOKEN
```

**Test credentials**:
```bash
# Local login test
printf '%s' "$PASSWORD" | docker login -u "$USERNAME" --password-stdin

# Update secrets if needed
gh secret set DOCKERHUB_TOKEN --body "new-token"
```

## See Also

- [Docker Deployment](docker.md) - Building and running Docker images
- [Main README](../README.md) - Project overview and configuration
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
