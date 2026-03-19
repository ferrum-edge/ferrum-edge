# Functional Testing for File Mode

This document describes the functional testing strategy for Ferrum Gateway when running in file mode (`FERRUM_MODE=file`).

## Overview

File mode allows Ferrum Gateway to load and manage configurations from static YAML/JSON files rather than a database. The functional tests verify that the gateway correctly:

1. Loads configuration files
2. Routes requests to configured backends
3. Reloads configuration on SIGHUP signal
4. Handles multiple proxies and backends
5. Manages empty configurations gracefully

## Test Files

### Unit Tests: `tests/config_file_loader_tests.rs`

Comprehensive unit tests for configuration file loading, covering:

- **Basic Loading**
  - YAML configuration loading
  - JSON configuration loading
  - Duplicate listen_path validation

- **Full Configuration**
  - Loading complete configs with proxies, consumers, and plugins
  - Field parsing validation

- **Backend Protocols**
  - All supported protocols: `http`, `https`, `ws`, `wss`, `grpc`, `h3`

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
  - Missing configuration files
  - Malformed YAML
  - Malformed JSON
  - Empty configurations

- **Format Fallback**
  - Unknown extension handling
  - YAML fallback behavior
  - JSON fallback behavior

### Functional Tests: `tests/functional_file_mode_test.rs`

End-to-end functional tests for the running gateway. These tests are marked with `#[ignore]` as they require building the binary and managing live processes.

#### Test: `test_file_mode_basic_request_routing`

Verifies basic request routing through the gateway:

1. Creates a temporary config file with one proxy
2. Starts a local echo HTTP server on port 9999
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
5. Sends SIGHUP signal to the gateway process
6. Verifies the new proxy is accessible after reload
7. Confirms old proxy still works

**What it tests:**
- SIGHUP signal handling
- Live configuration reloading
- No downtime during reload
- Multiple proxies after reload
- Configuration file watching and refresh logic

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
- Concurrent requests to different backends

## Running the Tests

### Run All Unit Tests (Default)

```bash
cargo test --test config_file_loader_tests
```

This runs all unit tests which don't require building the binary or managing processes.

### Run Functional Tests

Functional tests require the gateway binary to be built:

```bash
# Run a specific functional test
cargo test --test functional_file_mode_test -- --ignored --nocapture test_file_mode_basic_request_routing

# Run all functional tests
cargo test --test functional_file_mode_test -- --ignored --nocapture

# Run with verbose output to see gateway logs
RUST_LOG=debug cargo test --test functional_file_mode_test -- --ignored --nocapture
```

### Run All Tests (Both Unit and Functional)

```bash
cargo test --lib --test config_file_loader_tests
cargo test --test functional_file_mode_test -- --ignored --nocapture
```

## Configuration File Format

### Basic YAML Structure

```yaml
proxies:
  - id: "proxy-id"
    listen_path: "/api"
    backend_protocol: http
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
        key: "api-key-value"
      jwt:
        secret: "jwt-secret"
      basicauth:
        password_hash: "$2b$12$hash"

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

# Optional: Logging level (default: info)
RUST_LOG=ferrum_gateway=debug

# Optional: Proxy ports (defaults: 8000 for HTTP, 8443 for HTTPS)
FERRUM_PROXY_HTTP_PORT=8000
FERRUM_PROXY_HTTPS_PORT=8443

# Optional: Admin API ports (defaults: 9000 for HTTP, 9443 for HTTPS)
FERRUM_ADMIN_HTTP_PORT=9000
FERRUM_ADMIN_HTTPS_PORT=9443
```

## Test Coverage

The tests cover:

- **Configuration Loading**: 25+ unit tests for various config scenarios
- **Supported Protocols**: 6 backend protocols (http, https, ws, wss, grpc, h3)
- **Authentication**: 2 auth modes (single, multi) with 3 credential types
- **Scoping**: Global and proxy-specific plugin scoping
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
RUST_LOG=debug cargo test --test config_file_loader_tests -- --nocapture
```

Check the test output for specific assertion failures, especially around field parsing and type conversion.

### Functional Test Failures

Enable detailed output:

```bash
RUST_LOG=debug cargo test --test functional_file_mode_test -- --ignored --nocapture
```

Common issues:

1. **Port Already in Use**: Kill existing gateway processes
   ```bash
   pkill -f ferrum-gateway
   ```

2. **Build Failures**: Clean and rebuild
   ```bash
   cargo clean
   cargo build --release
   ```

3. **Network Issues**: Verify localhost connectivity
   ```bash
   netstat -tulpn | grep 8080
   ```

4. **Permission Denied**: Ensure executable permissions on the binary
   ```bash
   chmod +x target/release/ferrum-gateway
   ```

## Adding New Tests

### New Unit Test Template

```rust
#[test]
fn test_new_feature() {
    let yaml = r#"
proxies:
  - id: "proxy-1"
    listen_path: "/api"
    backend_protocol: http
    backend_host: "localhost"
    backend_port: 8080
consumers: []
plugin_configs: []
"#;
    let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
    write!(file, "{}", yaml).unwrap();
    let config = load_config_from_file(file.path().to_str().unwrap()).unwrap();

    // Add assertions
    assert_eq!(config.proxies.len(), 1);
}
```

### New Functional Test Template

```rust
#[ignore]
#[tokio::test]
async fn test_new_functionality() {
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");

    // Create config
    let mut config_file = File::create(&config_path).unwrap();
    config_file.write_all(b"...").unwrap();
    drop(config_file);

    // Start services
    let gateway_process = start_gateway_in_file_mode(config_path.to_str().unwrap());

    // Run test assertions

    // Cleanup
    if let Ok(mut proc) = gateway_process {
        let _ = proc.kill();
    }
}
```

## Continuous Integration

For CI/CD pipelines, run tests in this order:

1. Unit tests (fast, no dependencies):
   ```bash
   cargo test --test config_file_loader_tests
   ```

2. Functional tests (slower, requires binary build):
   ```bash
   cargo test --test functional_file_mode_test -- --ignored --test-threads=1
   ```

Using `--test-threads=1` prevents port conflicts when multiple functional tests run simultaneously.

## Known Limitations

1. **Functional Tests on Windows**: File mode tests use Unix signal handling (SIGHUP). Windows versions need process management alternatives.

2. **Port Conflicts**: Tests use fixed ports (8080, 8443, 9999, etc.). Ensure these are available during testing.

3. **Binary Caching**: Tests rebuild the binary each run. Use `--release` mode for faster builds in CI.

4. **Timeout Sensitivity**: SIGHUP reload tests rely on timing. On slow systems, may need to increase wait times.

## Future Improvements

- Add tests for TLS-enabled proxies
- Add WebSocket upgrade testing
- Add rate limiting plugin functional tests
- Add authentication plugin integration tests
- Add benchmarking for configuration reload performance
- Add stress testing with high proxy counts
