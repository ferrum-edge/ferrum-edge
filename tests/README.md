# Ferrum Gateway Test Suite

Comprehensive test suite for Ferrum Gateway, organized by test type and component.

## Directory Structure

```
tests/
├── README.md                           # This file
├── config.yaml                         # Test configuration fixture
├── certs/                              # TLS certificates for testing
│
├── unit_tests.rs                       # Entry point: unit test crate
├── unit/
│   ├── mod.rs
│   ├── plugins/                        # Plugin unit tests
│   │   ├── mod.rs
│   │   ├── plugin_utils.rs             # Shared plugin test helpers
│   │   ├── access_control_tests.rs     # IP/CIDR + consumer access control
│   │   ├── basic_auth_tests.rs         # Basic auth plugin
│   │   ├── http_logging_tests.rs       # HTTP logging plugin
│   │   ├── jwt_auth_plugin_tests.rs    # JWT auth plugin
│   │   ├── key_auth_tests.rs           # Key auth plugin
│   │   ├── oauth2_auth_tests.rs        # OAuth2 auth plugin
│   │   ├── plugin_cache_tests.rs       # Plugin cache logic
│   │   ├── plugin_integration_tests.rs # Plugin creation and scope
│   │   ├── rate_limiting_tests.rs      # Rate limiting plugin
│   │   ├── request_transformer_tests.rs
│   │   ├── response_transformer_tests.rs
│   │   ├── stdout_logging_tests.rs     # Stdout logging plugin
│   │   └── transaction_debugger_tests.rs
│   ├── config/                         # Configuration parsing tests
│   │   ├── mod.rs
│   │   ├── admin_enhanced_tls_tests.rs # Admin TLS/mTLS config
│   │   ├── admin_listeners_tests.rs    # Listener config parsing
│   │   ├── config_file_loader_tests.rs # YAML/JSON file loading (26 tests)
│   │   ├── config_types_tests.rs       # Config struct validation
│   │   ├── env_config_tests.rs         # Env var parsing (40+ tests)
│   │   ├── frontend_tls_tests.rs       # Frontend TLS config
│   │   ├── pool_config_tests.rs        # Pool config defaults/overrides
│   │   └── separate_listeners_tests.rs # HTTP/HTTPS listener config
│   ├── admin/                          # Admin API tests
│   │   ├── mod.rs
│   │   ├── admin_jwt_auth_tests.rs     # JWT verification, expiry
│   │   ├── admin_read_only_tests.rs    # Read-only mode
│   │   └── admin_tests.rs             # Admin API handlers
│   └── gateway_core/                   # Core data structure tests
│       ├── mod.rs
│       ├── consumer_index_tests.rs     # Consumer lookup index
│       ├── dns_tests.rs               # DNS cache and resolution
│       ├── proxy_tests.rs             # Proxy routing and URL building
│       ├── router_cache_tests.rs       # Router cache matching (29 tests)
│       └── websocket_auth_tests.rs     # WebSocket auth config
│
├── integration_tests.rs                # Entry point: integration test crate
├── integration/
│   ├── mod.rs
│   ├── backend_mtls_tests.rs           # Backend mutual TLS
│   ├── connection_pool_tests.rs        # Connection pool with real connections
│   ├── cp_dp_grpc_tests.rs            # CP/DP gRPC communication
│   ├── grpc_proxy_tests.rs            # gRPC reverse proxy (in-process)
│   └── http3_integration_tests.rs      # HTTP/3 flow tests
│
├── functional_tests.rs                 # Entry point: functional test crate
├── functional/
│   ├── mod.rs
│   ├── functional_cp_dp_test.rs        # CP/DP mode: gRPC + DB TLS
│   ├── functional_database_test.rs     # Database mode: SQLite + Admin API + proxy
│   ├── functional_file_mode_test.rs    # File mode: YAML config + SIGHUP reload
│   ├── functional_grpc_test.rs         # gRPC proxying: h2c echo, errors, metadata
│   └── functional_websocket_test.rs    # WebSocket proxying: ws/wss echo
│
├── helpers/
│   └── bin/                            # Standalone test server binaries
│       ├── websocket_echo_server.rs    # WS echo server (port 8080)
│       ├── secure_echo_server_simple.rs # Secure echo server (port 8443)
│       └── websocket_gateway_test.rs   # WS gateway integration binary
│
└── performance/                        # Performance/load testing (separate crate)
    ├── Cargo.toml
    ├── README.md
    ├── backend_server.rs
    ├── run_perf_test.sh
    ├── quick_test.sh
    └── *.lua                           # wrk test scripts
```

## Running Tests

### All Unit + Integration Tests (fast, no external services)
```bash
cargo test
```

### By Category
```bash
# Unit tests only (~280 tests, runs in seconds)
cargo test --test unit_tests

# Integration tests only (in-process servers, mock certs)
cargo test --test integration_tests

# Functional tests (spawn real binary, require build first)
cargo test --test functional_tests -- --ignored --nocapture
```

### By Test Name Pattern
```bash
cargo test plugin           # All plugin-related tests
cargo test config           # All configuration tests
cargo test admin            # All admin API tests
cargo test router_cache     # Router cache tests
cargo test dns              # DNS tests
```

### Functional Tests (individually)
Functional tests are marked `#[ignore]` since they spawn the gateway binary.
They require `cargo build` first (debug profile).

```bash
# Database mode: full CRUD + proxy routing + plugin configs
cargo test --test functional_tests functional_database -- --ignored --nocapture

# File mode: YAML config loading + SIGHUP reload
cargo test --test functional_tests functional_file_mode -- --ignored --nocapture

# CP/DP mode: gRPC sync + database TLS config
cargo test --test functional_tests functional_cp_dp -- --ignored --nocapture

# gRPC proxying: client → gateway → gRPC backend echo
cargo test --test functional_tests functional_grpc -- --ignored --nocapture

# WebSocket proxying: client → gateway → WebSocket backend echo
cargo test --test functional_tests functional_websocket -- --ignored --nocapture
```

### Performance Tests
```bash
cd tests/performance
cargo build --release
./run_perf_test.sh          # Full benchmark suite
./quick_test.sh             # Quick smoke test
```

## Test Categories Explained

**Unit tests** test individual modules in isolation with no I/O, no servers, no
network. They validate config parsing, data structures, plugin logic, routing
algorithms, and auth flows using mock data.

**Integration tests** verify interactions between multiple modules. They may spin
up in-process TCP/gRPC servers, create mock TLS certificates, or connect to
databases, but they do not spawn the gateway binary.

**Functional tests** are end-to-end: they compile and launch the actual
`ferrum-gateway` binary, send real HTTP requests through the proxy, and verify
the full request lifecycle. They are gated behind `#[ignore]` to keep the
default `cargo test` fast.

**Performance tests** use wrk and lua scripts to measure throughput and latency
under load. They live in a separate Cargo workspace.
