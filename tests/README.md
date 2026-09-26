# Ferrum Edge Test Suite

Test suite for Ferrum Edge, organized by test type and component.

## Directory Structure

Each top-level `tests/*.rs` file (or `[[test]]` entry in the root `Cargo.toml`)
is its own test target. Directories hold the modules those targets compile.

```
tests/
├── README.md                     # This file
├── config.yaml                   # Test configuration fixture
├── certs/, fixtures/             # TLS certificates, keys, MaxMind and k8s fixtures
│
├── unit_tests.rs                 # Unit target: config, admin, tls, identity, secrets,
│                                 #   cli, notifications, util, build, logging, openapi
├── unit_plugins_a_tests.rs       # Unit target: plugin test files a–j
├── unit_plugins_b_tests.rs       # Unit target: plugin test files k–z
├── unit_gateway_core_tests.rs    # Unit target: core runtime (router, proxy, DNS, ...)
├── unit/                         # Modules for the four unit targets, one directory
│                                 #   per area (plugins/, config/, gateway_core/, ...)
│
├── integration_tests.rs          # Integration target
├── integration/                  # In-process servers; no gateway binary
│
├── functional_tests.rs           # Functional target (#[ignore], spawns the binary)
├── functional/                   # End-to-end tests; see SCALE_PERF_TEST.md
│
├── conformance_tests.rs          # Mesh/Istio/xDS conformance target
├── conformance/                  # ga_contract.yaml + per-category modules
│
├── secrets_functional/           # [[test]]: secret backends (Vault/AWS containers,
│                                 #   GCP/Azure wiremock fakes)
├── service_integration/          # [[test]]: external middleware via OSS containers
├── acme_dns01/                   # [[test]]: ACME DNS-01 hook tests (feature `acme`)
├── k8s_istio_status_cas_live.rs  # Hosted kind test (istio-status-cas-live.yml)
│
├── common/                       # Shared helpers (gateway harness, echo servers, ...)
├── scaffolding/                  # Protocol backends/clients, port registry, harness
├── scenarios/                    # Catalog of scripted failure modes
├── support/                      # Tracing/diagnostic capture helpers
├── helpers/bin/                  # Standalone test server binaries
├── scripts/                      # Setup scripts (e.g. setup_db_tls.sh)
│
├── k8s/                          # Kubernetes live suites (kind), shared lib/
└── performance/                  # Benchmark harnesses (separate Cargo workspaces)
```

## Running Tests

### All Default Tests
```bash
cargo test
```

Runs every test target except `#[ignore]` tests (functional and live suites).
Most container-backed tests in `service_integration` and `secrets_functional`
self-skip when Docker is unavailable; the Kafka TLS acceptance tests do not.

### By Category
```bash
# Unit tests (four targets; each runs in seconds once built)
cargo test --test unit_tests
cargo test --test unit_plugins_a_tests
cargo test --test unit_plugins_b_tests
cargo test --test unit_gateway_core_tests

# Integration tests only (in-process servers, mock certs)
cargo test --test integration_tests

# Functional tests (spawn the real binary; build it first)
cargo build --bin ferrum-edge
cargo test --test functional_tests -- --ignored --nocapture
```

### Mesh Conformance and Live Evidence

`tests/conformance/ga_contract.yaml` is the machine-readable GA product
contract for mesh semantic coverage. `cargo test --test conformance_tests`
validates the manifest and emits `target/conformance/coverage.json` plus
`target/conformance/coverage.md`.

Kubernetes live suites should source helpers from `tests/k8s/lib/`:

- `kind.sh` for disposable kind clusters and shared diagnostics.
- `spire.sh` for the common SPIRE install/readiness/diagnostics flow.
- `live_assertions.sh` for `live-assertions.json` files keyed by stable
  assertion IDs from the GA contract.

### By Test Name Pattern
```bash
cargo test unit::plugins::cors_tests  # One module, searched across every target
cargo test plugin           # All plugin-related tests
cargo test config           # All configuration tests
cargo test admin            # All admin API tests
cargo test router_cache     # Router cache tests
cargo test dns              # DNS tests
```

### Functional Tests (individually)
Functional tests are marked `#[ignore]` because they spawn the gateway binary.
Build it first with `cargo build --bin ferrum-edge`; the harness uses
`target/debug/ferrum-edge` (or `FERRUM_EDGE_TEST_BIN` when set).

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

# Load balancing: algorithms, health checks, target failover, observability headers
cargo test --test functional_tests functional_load_balancer -- --ignored --nocapture
```

### Service Integration Tests (external middleware via OSS containers)
These validate the real integration code against live third-party software run
as local containers (`testcontainers`/Docker). With Docker available they run;
without it most of them self-skip (and hard-fail in CI). See
[`service_integration/README.md`](service_integration/README.md).

```bash
# Consul service discovery (ConsulDiscoverer::discover health-API parsing)
cargo test --test service_integration consul

# LDAP auth (bind / search-then-bind / group membership against OpenLDAP)
cargo test --test service_integration ldap

# OIDC relying party + OAuth2 introspection against Ory Hydra (#3333)
cargo test --test service_integration oidc
cargo test --test service_integration oauth2_introspection

# ClickHouse JSONEachRow chargeback insert (issue #4441)
cargo test --test service_integration clickhouse

# Kafka (Redpanda), MySQL, and PostgreSQL/MySQL database TLS
cargo test --test service_integration kafka
cargo test --test service_integration mysql
cargo test --test service_integration db_tls
```

### Performance Tests
```bash
cd tests/performance
./run_perf_test.sh          # Local HTTP/1.1 wrk smoke test
```

See [`performance/README.md`](performance/README.md) for the full suite index
(multi-protocol, payload-size, mesh Criterion, mesh DNS/HBONE E2E).

## Test Categories Explained

**Unit tests** test individual modules in isolation with no I/O, no servers, no
network. They validate config parsing, data structures, plugin logic, routing
algorithms, and auth flows using mock data.

**Integration tests** verify interactions between multiple modules. They may spin
up in-process TCP/gRPC servers, create mock TLS certificates, or connect to
databases, but they do not spawn the gateway binary.

**Functional tests** are end-to-end: they compile and launch the actual
`ferrum-edge` binary, send real HTTP requests through the proxy, and verify
the full request lifecycle. They are gated behind `#[ignore]` to keep the
default `cargo test` fast.

**Performance tests** measure throughput and latency under load with wrk,
Criterion, and custom load generators. Each harness under `tests/performance/`
is its own Cargo workspace.
