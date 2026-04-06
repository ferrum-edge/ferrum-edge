# Contributing to Ferrum Edge

Thank you for your interest in contributing to Ferrum Edge! This document provides guidelines and instructions for contributing to this high-performance edge proxy built in Rust.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Making Changes](#making-changes)
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
- Keep `CHANGELOG.md` updated if maintained

## Questions?

- **General questions**: Open a [GitHub Discussion](https://github.com/QuickLaunchWeb/ferrum-edge/discussions)
- **Bug reports**: Open an issue with the bug template
- **Feature requests**: Open an issue with the feature request template

## License

By contributing, you agree that your contributions will be licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE).
