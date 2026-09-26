# Functional Testing for File Mode

This document describes the functional testing strategy for Ferrum Edge when running in file mode (`FERRUM_MODE=file`).

## Overview

File mode allows Ferrum Edge to load and manage configurations from static YAML/JSON files rather than a database. The functional tests verify that the gateway correctly:

1. Loads configuration files
2. Routes requests to configured backends
3. Reloads configuration on SIGHUP signal
4. Handles multiple proxies and backends
5. Manages empty configurations gracefully

## Test Files

### Unit Tests: `tests/unit/config/config_file_loader_tests.rs`

Unit tests for configuration file loading (part of the `unit_tests` target), covering:

- **Basic Loading**
  - YAML configuration loading
  - JSON configuration loading
  - Duplicate listen_path validation

- **Full Configuration**
  - Loading complete configs with proxies, consumers, and plugins
  - Field parsing validation

- **Backend Schemes**
  - `http` and `https` parsing, `https` default for HTTP-family proxies
  - `h3` rejected as a `backend_scheme`

- **Authentication Modes**
  - Single auth mode
  - Multi auth mode
  - Default auth mode behavior

- **Consumer Credentials**
  - Key authentication credentials
  - JWT authentication credentials
  - Basic authentication credentials
  - Multiple credentials per consumer

- **Plugin Configuration**
  - Global scope plugins
  - Proxy-specific scope plugins
  - Complex plugin configurations with nested fields

- **Proxy Optional Fields**
  - All optional timeout settings
  - TLS configuration options
  - DNS override and caching settings
  - Connection pool configuration
  - Multiple plugin associations

- **Configuration Reload**
  - Dynamic reloading of configurations
  - Preservation of configuration state during reload

- **Error Handling**
  - Missing configuration files and missing `version`
  - Malformed YAML
  - Malformed JSON
  - Empty configurations
  - Unknown fields, oversized files, non-regular files, and torn (partially written) files

- **Format Fallback**
  - Unknown extensions are parsed as YAML (which also accepts JSON)

### Functional Tests: `tests/functional/functional_file_mode_test.rs`

End-to-end tests against a running gateway, started through the shared `TestGateway` harness (reserved ports, per-spawn credentials, automatic cleanup). They are marked `#[ignore]` because they build and run the `ferrum-edge` binary. Hosted CI runs them in the `Functional Tests (application)` shard.

#### Test: `test_file_mode_basic_request_routing`

Verifies basic request routing through the gateway:

1. Creates a temporary config file with one proxy
2. Starts a local echo HTTP server on a reserved port
3. Starts the gateway binary with `FERRUM_MODE=file`
4. Sends a test request through the proxy at `/echo/test-path`
5. Verifies the request is routed correctly and returns 200 OK

**What it tests:**
- Gateway startup in file mode
- Configuration loading from file
- HTTP request routing to backend
- Path stripping behavior
- Basic proxy functionality

#### Test: `test_file_mode_config_reload_on_sighup`

Verifies configuration reload on SIGHUP signal:

1. Creates a temporary config with one proxy
2. Starts echo server and gateway
3. Verifies initial proxy is accessible
4. Updates the config file to add a second proxy
5. Sends SIGHUP signal to the gateway process (Unix only)
6. Verifies the new proxy is accessible after reload

**What it tests:**
- SIGHUP signal handling
- Live configuration reloading

#### Test: `test_file_mode_empty_config`

Verifies graceful handling of empty configurations:

1. Creates a config file with no proxies, consumers, or plugins
2. Starts the gateway in file mode
3. Verifies startup succeeds

**What it tests:**
- Handling of minimal/empty configurations
- Gateway stability with no active proxies
- Configuration validation for empty configs

#### Test: `test_file_mode_multiple_backends`

Verifies routing to multiple backend services:

1. Creates a config with two proxies on different paths
2. Starts two echo servers on different ports
3. Starts the gateway
4. Sends requests to both backend paths
5. Verifies both requests are routed correctly

**What it tests:**
- Multiple proxy configurations
- Routing to different backends
- Path isolation between proxies

#### Test: `test_file_mode_consumer_identity_headers_forwarded`

Verifies that when `key_auth` authenticates a consumer, the consumer identity headers reach the backend (checked with a header-echo server).

#### Test: `test_file_mode_namespace_filtering`

Verifies `FERRUM_NAMESPACE` filtering: with proxies in two namespaces, only the proxies in the gateway's namespace are routable.

## Running the Tests

### Run Unit Tests

```bash
cargo test --test unit_tests config_file_loader
```

These don't require the gateway binary or live processes.

### Run Functional Tests

The harness runs `cargo build --bin ferrum-edge` once per test process (set `FERRUM_SKIP_GATEWAY_BUILD=1` to use an existing binary):

```bash
# Run a specific functional test
cargo test --test functional_tests test_file_mode_basic_request_routing -- --ignored --nocapture

# Run all file-mode functional tests
cargo test --test functional_tests functional_file_mode -- --ignored --nocapture
```

## Configuration File Format

See [File Mode Configuration Format](configuration.md#file-mode-configuration-format) for the canonical reference. The loader requires `version`, `proxies`, and `plugin_configs`; `consumers` and `upstreams` are optional.

### Basic YAML Structure

```yaml
version: "1"
proxies:
  - id: "proxy-id"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "backend.example.com"
    backend_port: 3000
    # Optional fields
    name: "Friendly Name"
    backend_path: "/v1"
    strip_listen_path: true
    preserve_host_header: false
    auth_mode: single
    plugins:
      - plugin_config_id: "plugin-id"

consumers:
  - id: "consumer-id"
    username: "alice"
    custom_id: "alice-001"
    credentials:
      keyauth:
        - key: "api-key-value"
      jwt:
        - secret: "jwt-secret-at-least-32-characters"
      basicauth:
        - password_hash: "hmac_sha256:0000000000000000000000000000000000000000000000000000000000000000"

plugin_configs:
  - id: "plugin-id"
    plugin_name: "stdout_logging"
    config:
      key: value
    scope: global
    enabled: true
```

## Environment Variables for File Mode

```bash
# Required: Path to the configuration file
FERRUM_FILE_CONFIG_PATH=/path/to/config.yaml

# Operating mode
FERRUM_MODE=file

# Optional: Logging level (default: warn). RUST_LOG, if set, takes precedence.
FERRUM_LOG_LEVEL=debug

# Optional: Proxy ports (defaults: 8000 for HTTP, 8443 for HTTPS)
FERRUM_PROXY_HTTP_PORT=8000
FERRUM_PROXY_HTTPS_PORT=8443

# Optional: Admin API ports (defaults: 9000 for HTTP, 9443 for HTTPS)
FERRUM_ADMIN_HTTP_PORT=9000
FERRUM_ADMIN_HTTPS_PORT=9443
```

## Test Coverage

The tests cover:

- **Configuration Loading**: ~80 unit tests for various config scenarios
- **Backend Schemes**: `http`/`https` parsing and `h3` rejection
- **Authentication**: 2 auth modes (single, multi) with 3 credential types
- **Scoping**: Global, proxy-specific, and proxy-group plugin scoping
- **Timeouts**: Backend connection, read, and write timeouts
- **TLS**: Client certificates, server verification, CA bundles
- **DNS**: Override and caching configuration
- **Connection Pooling**: Max idle connections, timeouts, keep-alive settings
- **Error Scenarios**: File not found, malformed content, invalid configurations
- **Reload Behavior**: SIGHUP signal handling and live config updates

## Debugging Failed Tests

### Unit Test Failures

Enable verbose logging:

```bash
cargo test --test unit_tests config_file_loader -- --nocapture
```

Check the test output for specific assertion failures, especially around field parsing and type conversion.

### Functional Test Failures

Run with `--nocapture`; a failed gateway spawn prints the child's exit status, ports, and stdout/stderr tails.

```bash
cargo test --test functional_tests functional_file_mode -- --ignored --nocapture
```

Common issues:

1. **Build failures or stale binary**: The harness builds `target/debug/ferrum-edge` unless `FERRUM_SKIP_GATEWAY_BUILD=1` is set, in which case it uses whatever binary exists
   ```bash
   cargo build --bin ferrum-edge
   ```

2. **Leftover gateway processes**: Ports come from the shared test port registry and spawns retry on fresh ports, but orphaned gateways from an aborted run can still hold ports
   ```bash
   pkill -f ferrum-edge
   ```

## Adding New Tests

### New Unit Test Template

```rust
#[test]
fn test_new_feature() {
    let yaml = r#"
version: "1"
proxies:
  - id: "proxy-1"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: 8080
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(
        file.path().to_str().unwrap(),
        30,
        &ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        "ferrum",
    )
    .unwrap();

    // Add assertions
    assert_eq!(config.proxies.len(), 1);
}
```

### New Functional Test Template

```rust
#[ignore]
#[tokio::test]
async fn test_new_functionality() {
    let backend = spawn_http_echo().await.expect("spawn echo");
    let config = format!(
        r#"
version: "1"
proxies:
  - id: "proxy-1"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {port}
plugin_configs: []
"#,
        port = backend.port
    );

    // Reserves ports, retries on collisions, and kills the child on drop.
    let gateway = TestGateway::builder()
        .mode_file(config)
        .spawn()
        .await
        .expect("start gateway");

    let response = reqwest::get(gateway.proxy_url("/api/test")).await.unwrap();
    assert!(response.status().is_success());
}
```

## Continuous Integration

Hosted CI runs the unit tests in the `Unit Tests` jobs and the file-mode functional tests in the `Functional Tests (application)` shard (`.github/workflows/ci.yml`). The shared port registry makes `--test-threads=1` unnecessary.

## Known Limitations

1. **SIGHUP Reload is Unix-only**: File mode config reload via SIGHUP is only available on Unix platforms. On non-Unix platforms (e.g., Windows), a warning is logged at startup and a process restart is required to apply config changes.

2. **Functional Tests on Windows**: File mode tests use Unix signal handling (SIGHUP). Windows versions need process management alternatives.

3. **Timeout Sensitivity**: The SIGHUP reload test waits a fixed 2 seconds after signalling; slow systems may need a longer wait.

## Security Notes

- **Config file permissions**: The gateway warns at startup if the config file is world-readable (Unix only). Since config files may contain consumer credentials (API keys, passwords, JWT secrets), restrict file permissions (e.g., `chmod 600`).

- **Admin API JWT in file mode**: When `FERRUM_ADMIN_JWT_SECRET` is not configured, the admin API uses a randomly generated secret per process start. This means the admin API is effectively inaccessible (no one can forge valid tokens), but it is still recommended to either set an explicit JWT secret or restrict network access to the admin port. If the secret or a related setting such as `FERRUM_ADMIN_JWT_MAX_TTL` is explicitly present but invalid, file-mode startup fails closed instead of silently generating a random secret.

- **ferrum.conf precedence**: Environment variables take precedence over values in `ferrum.conf`. The conf file provides defaults; if both are set for the same key with different values, an info-level message is logged. A stale `ferrum.conf` in the working directory will not override explicit env vars.

## Future Improvements

Generic "add TLS/WebSocket/rate-limit/auth/stress" items are already covered
by other functional suites (most of which run file-mode gateways).

### Covered elsewhere

- TLS-enabled proxies / frontend TLS — TLS functional suites and protocol tests (not a file-mode-only gap)
- WebSocket upgrade — `functional_websocket_*` / `functional_ws_*`
- Rate limiting plugins — `functional_redis_rate_limiting_test` + plugin network suites
- Authentication plugin integration — `functional_file_mode_test` key_auth path + [Auth & ACL Functional Testing](functional_testing_auth_acl.md)
- High proxy-count stress — scheduled `.github/workflows/scaling-regression.yml` (and `functional_load_stress_test` / `functional_scale_perf_test`)
- Live OIDC / OAuth2 introspection integration coverage — service-integration suite ([#3333](https://github.com/ferrum-edge/ferrum-edge/issues/3333))

### Explicit non-goal

- No dedicated SIGHUP / file-mode reload performance benchmark is currently
  owed. Functional reload correctness and the scheduled large-configuration
  scale suites cover the supported contract; open a scoped tracker only if the
  project adopts a measurable reload-latency budget.
