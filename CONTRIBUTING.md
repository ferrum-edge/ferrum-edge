# Contributing to Ferrum Edge

Thank you for your interest in contributing to Ferrum Edge! This document provides guidelines and instructions for contributing to this high-performance edge proxy built in Rust.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Making Changes](#making-changes)
- [Changelog Policy](#changelog-policy)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Commit Message Guidelines](#commit-message-guidelines)
- [Documentation](#documentation)
- [Questions](#questions)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/ferrum-edge.git
   cd ferrum-edge
   ```
3. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/my-feature-name
   # or
   git checkout -b fix/issue-description
   ```

## Development Environment

### Prerequisites

- **Rust** toolchain (stable 1.85+)
- **protoc** (Protocol Buffers compiler) - required for gRPC code generation
- **Database** (optional): PostgreSQL, MySQL, SQLite, or MongoDB for testing database mode

### One-time local bootstrap

The checked-in [`.cargo/config.toml`](.cargo/config.toml) requires **sccache** for all
targets, **clang + mold** for x86_64/aarch64 GNU/Linux, and **lld** (`ld64.lld` on PATH)
for x86_64/aarch64 macOS. Install these tools before the first build, or use the explicit
fallback below. From the cloned repository, run the bootstrap once per workstation:

```bash
./scripts/install-build-deps.sh
```

The [script](scripts/install-build-deps.sh) supports macOS with Homebrew already installed
and apt-based Linux with `sudo` access and Rust/Cargo on PATH. On macOS it installs
`sccache` and `lld` via Homebrew; on Linux it installs `mold` and `clang` via apt, then
`sccache` via `cargo install --locked` if missing. It does not install Rust, `protoc`, or
all native build dependencies. It detects the OS, not the architecture; package availability
depends on the host's repositories. It does not set up cross-compilation toolchains.

On other Linux distributions, install the same tools through your distribution's package
manager or use the fallback. The script rejects other operating systems, including Windows.
Windows keeps its system linker (`link.exe` for MSVC), but still needs `sccache` installed
manually or the wrapper disabled. Targets outside the four triples above have no fast-linker
override in the checked-in configuration.

CI installs these tools through separate setup actions. Missing tools locally cause a build
failure; there is no automatic local fallback. To relocate the compiler cache, set
`SCCACHE_DIR` in your shell profile.

#### Build without sccache or fast linkers

With the normal native compiler/linker and other build prerequisites installed, use these
POSIX-shell commands for a native GNU/Linux or macOS build:

```bash
# Native GNU/Linux (x86_64 or ARM64): use cc and its system linker.
env -u RUSTC_WRAPPER -u CARGO_ENCODED_RUSTFLAGS \
  CARGO_BUILD_RUSTC_WRAPPER="" RUSTFLAGS="" \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc \
  CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=cc \
  cargo build --release

# Native macOS (Intel or Apple Silicon): use the Apple toolchain linker.
env -u RUSTC_WRAPPER -u CARGO_ENCODED_RUSTFLAGS \
  CARGO_BUILD_RUSTC_WRAPPER="" RUSTFLAGS="" cargo build --release
```

`CARGO_BUILD_RUSTC_WRAPPER=""` overrides `[build] rustc-wrapper` and disables the wrapper.
To disable only sccache, use that setting without changing linker flags (and unset any
separate `RUSTC_WRAPPER`). On Windows PowerShell, use
`$env:RUSTC_WRAPPER = ""; $env:CARGO_BUILD_RUSTC_WRAPPER = ""` before `cargo build --release`.
See Cargo's [environment precedence](https://doc.rust-lang.org/cargo/reference/config.html#environment-variables),
[wrapper configuration](https://doc.rust-lang.org/cargo/reference/config.html#buildrustc-wrapper),
and [empty-wrapper behavior](https://doc.rust-lang.org/cargo/reference/environment-variables.html).

Empty `RUSTFLAGS` bypasses the configured `-fuse-ld` flags; clearing only
`CARGO_TARGET_<TRIPLE>_RUSTFLAGS` does not remove them because those values merge.
The commands unset `CARGO_ENCODED_RUSTFLAGS` because it has higher
[precedence](https://doc.rust-lang.org/cargo/reference/config.html#buildrustflags).
These examples replace custom Rust flags for that invocation. Repeat the environment
overrides for subsequent Cargo commands that compile code, or install the bootstrap tools.

### Building

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release
```

The `build.rs` runs `tonic_build` to compile `proto/ferrum.proto`, so ensure `protoc` is installed.

### Linting

We enforce zero warnings with clippy:

```bash
# Run clippy
cargo clippy --all-targets -- -D warnings

# Format code
cargo fmt

# Check formatting
cargo fmt --check
```

## Making Changes

### Project Structure

- `src/` - Core source code
  - `admin/` - Admin REST API
  - `config/` - Configuration loading & types
  - `modes/` - Operating mode implementations
  - `proxy/` - Reverse proxy core
  - `plugins/` - Plugin system
  - `tls/` - TLS/DTLS handling
- `tests/` - Integration and functional tests
- `docs/` - Documentation
- `proto/` - Protocol Buffer definitions

### Coding Standards

1. **Rust Edition 2024**: Use modern Rust idioms
2. **Lock-free hot path**: All request-path reads use `ArcSwap` or `DashMap` — no mutexes on the proxy path
3. **Zero-allocation patterns**: Avoid allocations on hot paths
4. **Pre-computed indexes**: Cache structures rebuilt on config reload, not per-request
5. **Error handling**: Use `Result` types with descriptive errors; avoid panics in production code

### Adding New Features

For significant features, please open an issue first to discuss the design:

1. Describe the feature and its use case
2. Discuss implementation approach
3. Get feedback from maintainers

For new plugins, see [CUSTOM_PLUGINS.md](CUSTOM_PLUGINS.md) for the plugin development guide.

## Changelog Policy

Ferrum Edge is in active build-out, so breaking changes are permitted without
legacy compatibility shims. Any breaking change to configuration shapes,
environment variables, schema, defaults, or other user-facing behavior **must**
add an entry under the appropriate heading in `CHANGELOG.md`'s `Unreleased`
section in the same pull request.

## Testing

### Running Tests

```bash
# Unit tests (fast, no I/O)
cargo test --test unit_tests

# Integration tests (component interaction)
cargo test --test integration_tests

# Functional / end-to-end tests (requires binary build first)
cargo build --bin ferrum-edge
cargo test --test functional_tests -- --ignored

# All tests together
cargo test
cargo test -- --ignored  # includes E2E tests
```

### Test Coverage

- Write tests for new functionality
- Unit tests for pure functions and logic
- Integration tests for component interactions
- Functional tests for end-to-end scenarios

### Performance Testing

For performance-sensitive changes:

```bash
cd tests/performance/multi_protocol
./run_benchmarks.sh
```

## Pull Request Process

1. **Update documentation** for any changed functionality
2. **Add tests** for new code
3. **Ensure all tests pass**:
   ```bash
   cargo test
   cargo test -- --ignored
   ```
4. **Run linting**:
   ```bash
   cargo clippy --all-targets -- -D warnings
   cargo fmt --check
   ```
5. **Update relevant docs** if changing user-facing features
6. **Submit your PR** with a clear description of the changes

### PR Title Format

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation only changes
- `style:` - Formatting, no code changes
- `refactor:` - Code restructuring
- `perf:` - Performance improvements
- `test:` - Adding or correcting tests
- `chore:` - Maintenance tasks

Examples:
- `feat: add WebSocket message compression plugin`
- `fix: resolve connection pool leak under high load`
- `docs: update TLS configuration examples`

## Commit Message Guidelines

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`

Examples:
```
feat(proxy): add HTTP/3 server push support

Implement server push for HTTP/3 connections to reduce
latency for critical resources. Adds configuration
option `enable_http3_push`.

Closes #123
```

## Documentation

- Update `docs/` for feature changes
- Add doc comments to public APIs (`///`)
- Update `README.md` for major features
- Follow the [changelog policy](#changelog-policy)

## Questions?

- **General questions**: Open a [GitHub Discussion](https://github.com/ferrum-edge/ferrum-edge/discussions)
- **Bug reports**: Open an issue with the bug template
- **Feature requests**: Open an issue with the feature request template

## License

By contributing, you agree that your contributions will be licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE).
