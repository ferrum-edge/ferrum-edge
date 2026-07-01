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
| `coverage.yml` | Coverage | PRs, push to `main`, weekly schedule, manual | Coverage planning/reporting and coverage floor enforcement mirrored by CI. |
| `release.yml` | Release | `v*` tag push | Versioned binary, GitHub Release, and Docker publishing after CI/Coverage validation. |
| `gateway-api-conformance.yml` | Gateway API Conformance | PRs, push to `main`, weekly schedule, manual | Upstream Gateway API conformance lab. |
| `node-waypoint-ebpf-live.yml` | NodeWaypoint eBPF Live Datapath | Path-filtered PRs, manual | Live eBPF datapath validation in kind. |
| `multicluster-federation-live.yml` | Multicluster Federation Live Datapath | Path-filtered PRs, manual | Live multicluster federation datapath validation. |
| `dependency-audit.yml` | Dependency Audit | Weekly schedule, manual | Scheduled supply-chain governance beyond the per-PR audit gate. |
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
    ├─► Format
    ├─► Unit / inline-lib / integration-shard / functional-shard tests
    ├─► Lint, dependency audit, vendored regressions
    ├─► Coverage workflow mirror
    ├─► eBPF/netns live checks when relevant
    ├─► Gateway / mesh / Helm / performance gates
    └─► Five target release builds

Push to main
    ├─► Same required validation gate as PRs
    └─► Five target release builds
            └─► Tests aggregate passes
                    ├─► Replace latest GitHub prerelease
                    └─► Push per-arch Docker images to Docker Hub and GHCR
                            └─► Create multi-arch Docker manifest (`latest`, `main-<sha>`)
```

### Release Pipeline Flow

```
Push tag v* (e.g., v0.2.0)
    └─► Validate tag target has successful CI and Coverage runs for the exact SHA
            └─► Five target release builds (matrix: linux-x86_64 / linux-aarch64 /
                macos-x86_64 / macos-aarch64 / windows-x86_64)
                    └─► Push versioned Docker images to Docker Hub and GHCR
                            └─► Create Docker manifest tags
                                    └─► Create GitHub Release with binaries and checksums
```

## CI Pipeline (ci.yml)

The CI workflow is triggered by every pull request and every push to `main`.
The `Tests` aggregate is the required validation gate for both event types: it
waits for format, test shards, lint, dependency audit, vendored patch
regressions, the Coverage workflow mirror, Gateway/mesh/Helm gates, eBPF/netns
gates, performance, and the cross-platform build matrix. Pushes to `main`
publish the `latest` prerelease and Docker images only after that aggregate and
the build matrix pass.

CI uses `concurrency.group: ci-publish-${{ github.ref }}` with `cancel-in-progress: true`, so a newer push to the same branch cancels the older CI run. On `main`, that can interrupt an in-flight publish job such as Docker manifest creation. If the cancellation left publishing incomplete, re-run the newest workflow attempt (the one for the latest `main` SHA) — re-running the older, canceled run would re-publish stale binaries and images as `latest`.

### Jobs

#### 1. Format Job

**Runs**: `ubuntu-latest`

Checks Rust formatting on pull requests and pushes to `main`:

```bash
cargo fmt --all -- --check
```

**Failures**:
- Indicate formatting drift
- Must be fixed before merging

#### 2. Test Jobs

**Runs**: `ubuntu-latest`

Runs the required test matrix in parallel. The commands below are grouped by job,
not run as one sequential shell script:

```bash
# test-unit
cargo test --test unit_tests

# test-lib
cargo test --lib

# test-integration-{admin-api,admin-config,mesh-routing,mesh-platform,protocols-data-plane}
cargo nextest run --test integration_tests \
  --no-fail-fast \
  <shard filters>

# test-integration-coverage (sanity check job; needs test-integration)
# Diffs `ls tests/integration/*.rs` against the union of shard filters and
# fails the PR if a file is missing from / not declared in any shard.

# build-gateway-binary
cargo build --bin ferrum-edge

# test-functional-{harness,admin-routing,data-plane,plugins,protocols,resilience}
cargo nextest run --test functional_tests \
  --run-ignored=all \
  --no-fail-fast \
  -E 'not test(/test_scale_perf_30k_proxies/) and not test(/test_load_stress_10k_proxies/)'
```

**What it tests**:
- Unit tests in `tests/unit_tests.rs`
- Inline `#[cfg(test)]` modules in `src/`
- Integration tests split across five shards (`admin-api`, `admin-config`, `mesh-routing`, `mesh-platform`, `protocols-data-plane`). Each shard runs `cargo nextest run --test integration_tests` with a per-shard list of `integration::<file_module>` positional filters that nextest ORs together. The shard split balances ~583 in-process tests across 57 files roughly by test count (admin-api ~153, admin-config ~152, mesh-routing ~158, mesh-platform ~60 — lower count offset by heavier k8s/telemetry setup per test, protocols-data-plane ~150). Integration tests are in-process (no gateway binary, no Redis/Mongo services); each shard runs on its own `ubuntu-latest` runner with the standard Rust toolchain and a 30-minute cap.
- `test-integration-coverage` runs after `test-integration` and diffs `ls tests/integration/*.rs` against the union of declared shard filters in `ci.yml`. Adding a new `mod foo_tests` to `tests/integration/mod.rs` without wiring it into a shard fails this guard — silent-skip protection.
- Functional tests split across six shards (harness, admin-routing, data-plane, plugins, protocols, and resilience). CI builds the gateway binary once in `build-gateway-binary`, uploads it as an artifact, and each functional shard downloads it with `FERRUM_SKIP_GATEWAY_BUILD=1`. The data-plane shard runs serialized with `nextest_jobs: 1`, and Redis/MongoDB service containers are attached to every functional shard job for tests that need them.

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

The job runs on PRs and pushes to `main`. On PRs, eBPF validation steps only run when files under `ebpf/` changed relative to the PR base; on `main`, they run without the PR path filter. When eBPF changes are present, CI installs stable and nightly Rust toolchains plus `bpf-linker`, uses nightly to build `ferrum-ebpf`, uses stable to run `cargo test -p ferrum-ebpf-common`, and uploads the compiled `ebpf-programs` artifact with 14-day retention. If this job is edited, preserve the intent that the shared-types test runs on stable Rust. When no eBPF files changed on a PR, the job no-ops and reports success.

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

Runs on PRs, pushes to `main`, and manual dispatches. PRs first apply a
performance-sensitive path filter; unrelated PRs skip the expensive benchmark
and report success. Relevant PRs and all `main` pushes build the gateway in the
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

Builds optimized release binaries for Linux x86_64, Linux ARM64, macOS x86_64, macOS ARM64, and Windows x86_64. These run on PRs and on pushes to `main`. The job installs the same prerequisites as the Release pipeline matrix — `protoc` on every OS, `libcurl4-openssl-dev` on Linux, and NASM on Windows — and builds with `--features cloud-secrets` so Vault/AWS/Azure/GCP secret backends are included. The macOS x86_64 build targets `x86_64-apple-darwin` with the standard Apple/Rust toolchain (no `cross` needed) and runs on whichever host architecture GitHub maps `macos-latest` to today (currently ARM64); pin to a concrete runner image such as `macos-14` if the host architecture must be guaranteed.

#### 8. Latest Release and Docker Jobs

**Runs**: `ubuntu-latest`

On pushes to `main`, the `latest-release` job and the per-architecture Linux Docker publishing job both depend on the completed build matrix and the `Tests` aggregate, which includes a mirror of the separate Coverage workflow for the same SHA. They can run in parallel after validation passes; the `docker-manifest` job runs after the Docker digests are pushed. A Docker failure on `main` does not block replacing the `latest` prerelease, but neither publish path can start until required validation passes. Version-tag releases are stricter and gate GitHub Release creation on `docker-manifest`. Docker Hub publishing requires the `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` repository secrets. GHCR publishing uses `GITHUB_TOKEN` and the job-level `packages: write` permission. The Docker manifests publish both `latest` and `main-<sha>` tags (where `<sha>` is the full commit SHA from `github.sha`).

## Release Pipeline (release.yml)

The Release pipeline creates official releases when a version tag is pushed. It
first resolves the tag to its target commit and waits for successful `CI` and
`Coverage` workflow runs for that exact SHA before any release binary or image
job starts.

Release runs use `concurrency.group: release-${{ github.ref }}` with `cancel-in-progress: false`, so a versioned release is never canceled by a later tag push.

### Trigger

Push a tag matching the pattern `v*`:

```bash
# Create and push tag
git tag v0.2.0
git push origin v0.2.0
```

### Validate Release SHA Job

**Runs**: `ubuntu-latest`

Validates that the tag name matches the release pattern and that the tag target
commit has successful `ci.yml` and `coverage.yml` runs from a `push` event.
Manual workflow dispatches do not satisfy this release gate because they do not
necessarily execute the same required `Tests` aggregate. If either workflow has
not passed for the exact SHA, the release waits for the push run and then fails
before publishing binaries or registry tags if it still has no success.

### Release Build Job

**Runs**: `ubuntu-latest`, `macos-latest`, `windows-latest` (matrix)

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
- Linux ARM64 uses `cross` tool for seamless compilation; `cross` requires Docker or Podman on the build host.
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
1. Update `Cargo.toml` version to the intended release version before tagging
2. Tag: `git tag v<version>` (matching the new version)
3. Release: GitHub Actions automatically builds and publishes

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
```

## Creating a New Release

### Prerequisites

- Modify `Cargo.toml` with new version
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
# MSVC builds need NASM in PATH, and Linux ARM64 uses cross (`cargo install cross`)
# with Docker or Podman running.
# On a Linux host:
cargo build --features cloud-secrets --release --target x86_64-unknown-linux-gnu
cross build --features cloud-secrets --release --target aarch64-unknown-linux-gnu

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

Edit both `.github/workflows/ci.yml` (`build-binaries`) and `.github/workflows/release.yml` (`build-release-binaries`):

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
`cargo build`, or route the target through `cross build` and install `cross`
in the workflow the same way the ARM64 Linux target does.

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
