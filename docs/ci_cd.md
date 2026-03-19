# CI/CD Pipeline Documentation

Ferrum Gateway includes comprehensive CI/CD pipelines for automated testing, building, and releasing.

## Table of Contents

- [Pipeline Overview](#pipeline-overview)
- [CI Pipeline (ci.yml)](#ci-pipeline-ciyml)
- [Release Pipeline (release.yml)](#release-pipeline-releaseyml)
- [How Releases Work](#how-releases-work)
- [Creating a New Release](#creating-a-new-release)
- [Binaries and Downloads](#binaries-and-downloads)
- [GitHub Actions Secrets](#github-actions-secrets)

## Pipeline Overview

Two main workflows handle different aspects of the development lifecycle:

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| **CI** (`ci.yml`) | Push to `main`, Pull Requests | Test and lint |
| **Release** (`release.yml`) | Push tag matching `v*` | Build platform-specific binaries, create GitHub release |

### CI Pipeline Flow

```
Push to main / Pull Request
        │
        ├─► Test (cargo test)
        └─► Lint (clippy, fmt)
```

> **Note**: Build Release and Docker Build jobs are currently disabled (commented out in ci.yml) while the project is in early development. They will be enabled when the project is mature. See the release pipeline for producing binaries on version tags.

### Release Pipeline Flow

```
Push tag v* (e.g., v0.2.0)
        │
        ├─► Build linux-x86_64
        ├─► Build linux-aarch64 (ARM)
        ├─► Build macos-x86_64
        ├─► Build macos-aarch64 (Apple Silicon)
        │
        └─► Create GitHub Release with binaries and checksums
```

## CI Pipeline (ci.yml)

The CI pipeline runs on every push to `main` and all pull requests.

### Jobs

#### 1. Test Job

**Runs**: `ubuntu-latest`

Tests all code changes and dependencies:

```bash
# Executed
cargo test --verbose --all-features
```

**What it tests**:
- All unit tests in `src/`
- All integration tests in `tests/`
- Feature combinations
- Build dependencies

**Output**:
- Test pass/fail status
- Failures block PR merges (if branch protection enabled)

#### 2. Lint Job

**Runs**: `ubuntu-latest`

Enforces code quality standards:

```bash
# Clippy (warnings as errors)
cargo clippy --all-targets --all-features -- -D warnings

# Format check
cargo fmt --all -- --check
```

**What it checks**:
- Code style and idioms (clippy)
- Code formatting (rustfmt)
- Unsafe code warnings
- Performance issues

**Failures**:
- Indicate code quality issues
- Must be fixed before merging

#### 3. Build Release Job (Currently Disabled)

> **Status**: Commented out in ci.yml while the project is in early development. Will be re-enabled when the project is mature.

When enabled, builds optimized release binaries for multiple platforms (Linux x86_64, macOS x86_64, macOS aarch64). Gated on test and lint jobs passing, and only runs on push to `main` (not on PRs).

#### 4. Docker Build Job (Currently Disabled)

> **Status**: Commented out in ci.yml while the project is in early development. Will be re-enabled when the project is mature.

When enabled, builds and optionally pushes a Docker image. Gated on test and lint jobs passing, and only runs on push to `main`. Requires `DOCKER_USERNAME` and `DOCKER_PASSWORD` GitHub Secrets for pushing to a registry.

## Release Pipeline (release.yml)

The Release pipeline creates official releases when a version tag is pushed.

### Trigger

Push a tag matching the pattern `v*`:

```bash
# Create and push tag
git tag v0.2.0
git push origin v0.2.0
```

### Release Build Job

**Runs**: `ubuntu-latest`, `macos-latest` (matrix)

Builds optimized release binaries for all target platforms:

**Targets**:
- `x86_64-unknown-linux-gnu` - Linux x86_64
- `aarch64-unknown-linux-gnu` - Linux ARM64
- `x86_64-apple-darwin` - macOS x86_64
- `aarch64-apple-darwin` - macOS ARM64 (Apple Silicon)

**Build Process**:
1. Checkout code at tag commit
2. Install Rust toolchain with target
3. Install protobuf compiler
4. Build release binary in `--release` mode
5. Generate SHA256 checksum
6. Upload artifact

**Cross-Compilation**:
- Linux ARM64 uses `cross` tool for seamless compilation
- Other targets use standard `cargo build`

**Output**:
- Binary: `ferrum-gateway-{platform}`
- Checksum: `ferrum-gateway-{platform}.sha256`

### Create Release Job

**Depends On**: Release Build Job (all targets)

Creates a GitHub Release with all binaries and checksums:

**Release Content**:
1. Release title: Version tag (e.g., `v0.2.0`)
2. Release description: Generated release notes including:
   - List of binary platforms
   - SHA256 checksums for verification
   - Download instructions
3. Attachments: All platform-specific binaries

**Release Notes Example**:
```markdown
# Release v0.2.0

## Binaries

- ferrum-gateway-linux-x86_64
- ferrum-gateway-linux-aarch64
- ferrum-gateway-macos-x86_64
- ferrum-gateway-macos-aarch64

## Checksums

abc123... ferrum-gateway-linux-x86_64
def456... ferrum-gateway-linux-aarch64
...
```

## How Releases Work

### Version Management

**Current Version**: Defined in `Cargo.toml`

```toml
[package]
name = "ferrum-gateway"
version = "0.1.0"
```

**Release Process**:
1. Update `Cargo.toml` version before tagging
2. Tag: `git tag v0.2.0` (matching new version)
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
- All tests passing on `main` branch
- GitHub repo with Actions enabled
- Write permission to repository

### Step-by-Step

**1. Update Version in Cargo.toml**

```bash
# Edit Cargo.toml
cat > Cargo.toml << EOF
[package]
name = "ferrum-gateway"
version = "0.2.0"
...
EOF
```

**2. Commit Changes**

```bash
git add Cargo.toml
git commit -m "chore: bump version to 0.2.0"
git push origin main
```

**3. Wait for CI to Pass**

- Push to main triggers CI pipeline
- All jobs must pass (test, lint, build)
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
- Binaries built for all platforms
- Release created with checksums

**6. Verify Release**

```bash
# GitHub CLI
gh release view v0.2.0

# Check binaries
gh release download v0.2.0 --dir ./binaries

# Verify checksums
sha256sum -c ferrum-gateway-*.sha256
```

### Alternative: Manual Release Creation

If automatic release fails:

```bash
# Build binaries manually
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin

# Generate checksums
sha256sum target/*/release/ferrum-gateway > checksums.txt

# Create release in GitHub UI or via gh:
gh release create v0.2.0 \
  target/*/release/ferrum-gateway \
  checksums.txt \
  --title "Release v0.2.0" \
  --notes "$(cat release-notes.md)"
```

## Binaries and Downloads

### GitHub Releases Page

All released binaries available at:
```
https://github.com/your-org/ferrum-gateway/releases
```

### Download Latest Release

```bash
# Using GitHub CLI
gh release download --repo your-org/ferrum-gateway -p "*linux-x86_64"

# Using curl
RELEASE_URL=$(curl -s https://api.github.com/repos/your-org/ferrum-gateway/releases/latest | \
  jq -r '.assets[] | select(.name == "ferrum-gateway-linux-x86_64") | .browser_download_url')
curl -L -o ferrum-gateway $RELEASE_URL
chmod +x ferrum-gateway
```

### Platform-Specific Binaries

**Linux x86_64** (Intel/AMD 64-bit)
```bash
gh release download v0.2.0 -p "ferrum-gateway-linux-x86_64"
chmod +x ferrum-gateway-linux-x86_64
./ferrum-gateway-linux-x86_64
```

**Linux ARM64** (ARM 64-bit, Graviton, etc.)
```bash
gh release download v0.2.0 -p "ferrum-gateway-linux-aarch64"
chmod +x ferrum-gateway-linux-aarch64
./ferrum-gateway-linux-aarch64
```

**macOS x86_64** (Intel Macs)
```bash
gh release download v0.2.0 -p "ferrum-gateway-macos-x86_64"
chmod +x ferrum-gateway-macos-x86_64
./ferrum-gateway-macos-x86_64
```

**macOS ARM64** (Apple Silicon M1/M2/M3)
```bash
gh release download v0.2.0 -p "ferrum-gateway-macos-aarch64"
chmod +x ferrum-gateway-macos-aarch64
./ferrum-gateway-macos-aarch64
```

### Checksum Verification

Always verify binary integrity using SHA256:

```bash
# Download release files
gh release download v0.2.0

# Verify checksums
sha256sum -c *.sha256

# Expected output:
# ferrum-gateway-linux-x86_64: OK
# ferrum-gateway-linux-aarch64: OK
# ferrum-gateway-macos-x86_64: OK
# ferrum-gateway-macos-aarch64: OK
```

### Docker Hub Images

Pre-built Docker images also available (if Docker Hub credentials configured):

```bash
docker pull your-registry/ferrum-gateway:v0.2.0
docker pull your-registry/ferrum-gateway:latest
```

## GitHub Actions Secrets

Configure secrets for Docker image publishing and releases.

### Accessing Secrets Settings

1. Go to GitHub repository
2. Settings → Secrets and variables → Actions
3. Create new repository secrets

### Required Secrets

#### Docker Registry (Optional)

For pushing Docker images to registry:

- `DOCKER_USERNAME` - Docker Hub username
- `DOCKER_PASSWORD` - Docker Hub access token or password

**Generate Docker Token**:
1. Log in to Docker Hub
2. Account Settings → Security
3. Create new access token
4. Copy token to `DOCKER_PASSWORD`

### Environment Variables in Workflows

Access secrets in workflows:

```yaml
env:
  DOCKER_USERNAME: ${{ secrets.DOCKER_USERNAME }}
  DOCKER_PASSWORD: ${{ secrets.DOCKER_PASSWORD }}
```

### Setting Secrets

```bash
# Using GitHub CLI
gh secret set DOCKER_USERNAME --body "your-username"
gh secret set DOCKER_PASSWORD --body "your-token"

# Via web UI
1. Settings → Secrets → New repository secret
2. Name: DOCKER_USERNAME
3. Value: your-username
4. Click "Add secret"
```

## Customizing CI/CD

### Adding New Targets

Edit `.github/workflows/release.yml`:

```yaml
strategy:
  matrix:
    include:
      # Add Windows target
      - os: windows-latest
        target: x86_64-pc-windows-gnu
        artifact_name: ferrum-gateway.exe
        asset_name: ferrum-gateway-windows-x86_64.exe
```

### Skipping Steps

Skip specific jobs per commit:

```bash
# Skip CI for documentation changes
git commit -m "docs: update README [skip ci]"

# Automatically skips test/lint/build jobs
```

### Custom Build Flags

Modify build commands in workflows:

```yaml
- name: Build with custom features
  run: cargo build --release --features "vendored-openssl"
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
- `protoc` not installed: Fixed in CI (installs protoc)
- Missing dependencies: Check `Cargo.toml`
- Rust version: Workflows use `stable` Rust toolchain

### Docker Push Failing

**Verify secrets**:
```bash
gh secret list
# Should show DOCKER_USERNAME and DOCKER_PASSWORD
```

**Test credentials**:
```bash
# Local login test
docker login -u $USERNAME -p $PASSWORD

# Update secrets if needed
gh secret set DOCKER_PASSWORD --body "new-token"
```

## See Also

- [Docker Deployment](docker.md) - Building and running Docker images
- [Main README](../README.md) - Project overview and configuration
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
