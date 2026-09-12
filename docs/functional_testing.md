# Functional Testing Guide

This document describes the functional testing strategy for the Ferrum Edge, particularly for Control Plane (CP) and Data Plane (DP) mode integration.

## Test Files

### cp_dp_grpc_tests.rs

Located in `tests/integration/cp_dp_grpc_tests.rs`, this file contains integration tests for gRPC communication between CP and DP.

**Tests:**
- `test_dp_receives_initial_config_from_cp` - Verifies DP receives initial config snapshot from CP
- `test_dp_receives_config_updates` - Verifies DP receives streaming config updates
- `test_dp_rejects_invalid_token` - Verifies authentication is enforced
- `test_dp_handles_malformed_config` - Verifies DP handles invalid updates gracefully
- `test_dp_preserves_config_after_cp_shutdown` - Verifies DP caches config when CP goes down

**Running:**
```bash
cargo test --test cp_dp_grpc_tests
```

### functional_cp_dp_test.rs

Located in `tests/functional/functional_cp_dp_test.rs`, this file contains higher-level functional tests for CP/DP integration and database TLS support.

**Test Coverage:**
1. **test_cp_dp_grpc_config_sync** - Tests complete gRPC config sync flow
   - Starts a CP gRPC server
   - Connects a DP client
   - Verifies initial config reception
   - Broadcasts config updates and verifies DP receives them

2. **test_database_connection_with_sqlite_config** - Tests SQLite database connection behavior
   - Tests plaintext SQLite connection
   - Creates and loads proxies from database

3. **test_env_config_tls_fields** - Verifies all TLS fields are present in EnvConfig
   - Checks db_tls_mode
   - Checks db_tls_ca_cert_path
   - Checks db_tls_client_cert_path
   - Checks db_tls_client_key_path

**Running (Ignored by Default):**
```bash
# Run all functional tests
cargo test --test functional_tests functional_cp_dp -- --ignored

# Run specific test
cargo test --test functional_tests functional_cp_dp -- test_database_connection_with_sqlite_config -- --ignored

# Run with output
cargo test --test functional_tests functional_cp_dp -- --ignored --nocapture
```

## Database TLS Support

The database layer supports TLS configuration for PostgreSQL, MySQL, and MongoDB connections. SQLite has no network TLS; `FERRUM_DB_TLS_MODE=disable` is accepted as a no-op, while certificate paths and other database TLS modes are rejected.

### Configuration

Set these environment variables to enable database TLS:

```bash
# Enable TLS for database connection
FERRUM_DB_TLS_MODE=verify-full

# Path to CA certificate (for server verification)
FERRUM_DB_TLS_CA_CERT_PATH=/path/to/ca.pem

# Path to client certificate (for mTLS)
FERRUM_DB_TLS_CLIENT_CERT_PATH=/path/to/client.pem

# Path to client private key (for mTLS)
FERRUM_DB_TLS_CLIENT_KEY_PATH=/path/to/client-key.pem

# Encrypted but without certificate verification (testing only)
FERRUM_DB_TLS_MODE=require
```

### Implementation Details

#### EnvConfig Changes

Added to `src/config/env_config.rs`:
```rust
pub db_tls_mode: Option<DbTlsMode>,
pub db_tls_ca_cert_path: Option<String>,
pub db_tls_client_cert_path: Option<String>,
pub db_tls_client_key_path: Option<String>,
```

#### Database URL Handling

SQL URLs are built by `EnvConfig::effective_db_url()`,
`effective_db_failover_urls()`, and `effective_db_read_replica_url()` from the
canonical `FERRUM_DB_TLS_MODE` and certificate path fields. `DatabaseStore`
consumes those already-effective URLs and only appends pool-level driver options
such as `connect_timeout`.

**For PostgreSQL:**
- Uses the `sslmode` parameter (`require`, `verify-ca`, `verify-full`, etc.)
- Supports `sslrootcert`, `sslcert`, `sslkey` parameters

**For MySQL:**
- Uses the `ssl-mode` parameter (`REQUIRED`, `VERIFY_CA`, `VERIFY_IDENTITY`, etc.)
- Supports `ssl-ca`, `ssl-cert`, `ssl-key` parameters

**For SQLite:**
- `FERRUM_DB_TLS_MODE=disable` is accepted as a no-op for shared templates
- Certificate paths and other TLS modes are rejected because SQLite doesn't use network TLS

#### Mode Changes

Updated `src/modes/control_plane.rs` and `src/modes/database.rs` to apply canonical database TLS settings for SQL URLs and MongoDB driver options.

## CP/DP Mode Integration

### Control Plane (CP)

When FERRUM_MODE=cp:

1. Connects to database (with optional TLS)
2. Loads initial gateway configuration
3. Starts gRPC server on FERRUM_CP_GRPC_LISTEN_ADDR (default: 0.0.0.0:50051)
2. Starts Admin HTTP listener on port FERRUM_ADMIN_HTTP_PORT (default: 9000)
4. Polls database for updates at FERRUM_DB_POLL_INTERVAL (default: 30s)
5. Broadcasts config updates to connected DPs via gRPC

**Required Environment Variables:**
```bash
FERRUM_MODE=cp
FERRUM_ADMIN_JWT_SECRET=<change-me-to-a-32-character-admin-secret>
FERRUM_DB_TYPE=sqlite  # or postgres, mysql
FERRUM_DB_URL=sqlite://ferrum.db
FERRUM_CP_GRPC_LISTEN_ADDR=0.0.0.0:50051
FERRUM_CP_DP_GRPC_JWT_SECRET=<change-me-to-a-32-character-grpc-secret>
```

### Data Plane (DP)

When FERRUM_MODE=dp:

1. Connects to Control Plane via gRPC
2. Receives initial gateway configuration
3. Subscribes to streaming config updates
4. Starts proxy HTTP listener on FERRUM_PROXY_HTTP_PORT (default: 8000)
5. Routes traffic according to configuration

**Required Environment Variables:**
```bash
FERRUM_MODE=dp
FERRUM_DP_CP_GRPC_URLS=http://cp-host:50051
FERRUM_CP_DP_GRPC_JWT_SECRET=<change-me-to-a-32-character-grpc-secret>
FERRUM_ADMIN_JWT_SECRET=<change-me-to-a-32-character-admin-secret>
```

## Admin API

The CP mode exposes an Admin API on HTTP port (default: 9000) for managing configuration.

### Create Proxy
```bash
curl -X POST http://localhost:9000/proxies \
  -H "Authorization: Bearer <jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "proxy-1",
    "name": "Example Proxy",
    "listen_path": "/api/v1",
    "backend_scheme": "http",
    "backend_host": "example.com",
    "backend_port": 80,
    "strip_listen_path": true,
    "preserve_host_header": false,
    "backend_connect_timeout_ms": 5000,
    "backend_read_timeout_ms": 30000,
    "backend_write_timeout_ms": 30000,
    "auth_mode": "single"
  }'
```

### Create Consumer
```bash
curl -X POST http://localhost:9000/consumers \
  -H "Authorization: Bearer <jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "test-user",
    "custom_id": "custom-123"
  }'
```

## Testing Workflow

### Local Testing with CP/DP

1. Create database:
```bash
# Using in-memory or file SQLite
export FERRUM_DB_URL="sqlite://./test-ferrum.db"
```

2. Start CP in one terminal:
```bash
FERRUM_MODE=cp \
FERRUM_ADMIN_JWT_SECRET=change-me-to-a-32-character-admin-secret \
FERRUM_DB_TYPE=sqlite \
FERRUM_DB_URL=sqlite://./test-ferrum.db \
FERRUM_CP_GRPC_LISTEN_ADDR=127.0.0.1:50051 \
FERRUM_CP_DP_GRPC_JWT_SECRET=change-me-to-a-32-character-grpc-secret \
FERRUM_ADMIN_HTTP_PORT=9000 \
FERRUM_LOG_LEVEL=debug \
cargo run --bin ferrum-edge -- run
```

3. Create a JWT token for Admin API:
```bash
# Use a tool like jwt.io or write a simple script
# Example payload:
{
  "sub": "admin",
  "role": "admin",
  "iat": 1704067200
}
# Sign with FERRUM_ADMIN_JWT_SECRET: "change-me-to-a-32-character-admin-secret"
```

4. Create a proxy via Admin API:
```bash
curl -X POST http://localhost:9000/proxies \
  -H "Authorization: Bearer <jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "my-proxy",
    "listen_path": "/test",
    "backend_host": "httpbin.org",
    "backend_port": 80,
    "backend_scheme": "http",
    "strip_listen_path": true,
    "auth_mode": "single",
    "backend_connect_timeout_ms": 5000,
    "backend_read_timeout_ms": 30000,
    "backend_write_timeout_ms": 30000
  }'
```

5. Start DP in another terminal (the DP automatically generates short-lived JWTs from the shared secret):
```bash
FERRUM_MODE=dp \
FERRUM_DP_CP_GRPC_URLS=http://127.0.0.1:50051 \
FERRUM_CP_DP_GRPC_JWT_SECRET=change-me-to-a-32-character-grpc-secret \
FERRUM_ADMIN_JWT_SECRET=change-me-to-a-32-character-admin-secret \
FERRUM_PROXY_HTTP_PORT=8000 \
FERRUM_LOG_LEVEL=debug \
cargo run --bin ferrum-edge -- run
```

6. Test proxy traffic:
```bash
curl http://localhost:8000/test/get
```

### Testing with TLS Database Connection

For PostgreSQL or MySQL with TLS, set:
```bash
FERRUM_DB_TLS_MODE=verify-full
FERRUM_DB_TLS_CA_CERT_PATH=/path/to/ca.pem
FERRUM_DB_TLS_CLIENT_CERT_PATH=/path/to/client.pem
FERRUM_DB_TLS_CLIENT_KEY_PATH=/path/to/client-key.pem
# For testing only, use require to encrypt without certificate verification.
# FERRUM_DB_TLS_MODE=require
```

Then start CP/DP modes normally. The database connection will use TLS.

## Troubleshooting

### DP Not Receiving Config
- Verify CP is running and gRPC server is listening on FERRUM_CP_GRPC_LISTEN_ADDR
- Check that FERRUM_CP_DP_GRPC_JWT_SECRET matches on both CP and DP
- Check logs for JWT validation errors

### Admin API Endpoints Failing
- Verify JWT token is properly signed with FERRUM_ADMIN_JWT_SECRET
- Check that token has not expired
- Verify token format: `Authorization: Bearer <token>`

### Database Connection Failures
- For TLS: Ensure certificate paths exist and are readable
- For SQLite: Check file path and permissions
- For PostgreSQL/MySQL: Verify FERRUM_DB_TLS_MODE and certificate validity

### Proxy Traffic Not Working
- Verify proxy exists in CP database via Admin API
- Check DP has received config (look for "proxies loaded" in logs)
- Verify backend is reachable from DP
- Check proxy listen_path matches request path

## Performance Considerations

- **Database polling**: Adjust FERRUM_DB_POLL_INTERVAL based on how frequently config changes
- **Config update delay**: DP receives updates via gRPC stream, typically within 100ms
- **Admin API**: Limited by database query performance
- **Proxy throughput**: DP performance scales with number of concurrent connections

## Subprocess Harness Process Identity

`tests/common/gateway_harness.rs` reserves the admin and proxy ports by
binding `127.0.0.1:0` and dropping the listener, so between reservation
and the child's own bind another gateway running in a parallel test can
claim either port. Neither readiness nor a bare TCP accept can tell them
apart — every gateway serves the same unauthenticated `/health` body.

`TestGatewayBuilder::spawn` therefore mints per-spawn-attempt credentials
(admin JWT secret/issuer plus `FERRUM_METRICS_BEARER_TOKEN`) and treats
startup as complete only once the admin port answers `/health` in the
**authenticated detail tier** for that instance's token *and* reports
`ready: true`:

- The detail tier requires the instance credential, so a foreign gateway
  is rejected instead of impersonating the child.
- `ready` flips only after every listener bind succeeded, including the
  proxy HTTP listener, so an identified ready child is also proof that it
  — not a squatter — owns the proxy port for its whole lifetime.

That last claim requires an exclusive proxy bind. Production binds one
exclusive listen socket and duplicates it for `FERRUM_ACCEPT_THREADS`
accept workers — it never sets `SO_REUSEPORT` — so a second process
cannot join the same TCP proxy port. The harness still pins
`FERRUM_ACCEPT_THREADS=1` unless the caller overrides it, so a colliding
bind is a single-socket `EADDRINUSE` and the spawn retry picks a fresh port.

`wait_for_proxy_port` re-proves that ownership before trusting a TCP
accept, and the spawn wait polls the child so a process that dies after a
partial bind fails fast instead of burning the health timeout against
whatever claims the released port next.

Tests that pin `FERRUM_ADMIN_JWT_SECRET` or `FERRUM_METRICS_BEARER_TOKEN`
(or open `FERRUM_METRICS_ALLOWED_CIDRS`) keep their explicit value; their
identity is then only as unique as the value they chose. The contract is
covered by `functional_shared_harness_smoke_test`.

The same barrier is mandatory for suites that keep a bespoke spawner
instead of `TestGatewayBuilder`. `functional_websocket_test.rs` reuses the
exported `probe_gateway_identity` in `wait_for_owned_gateway`, because a
bare TCP accept let an unrelated H2 fixture that had claimed the released
proxy port answer the RFC 8441 Extended CONNECT handshake and reset it
with `PROTOCOL_ERROR` (issue #3435).

## Spawned Gateway Teardown

A `std::process::Child` does **not** kill its process when it is dropped. A
bespoke spawner that only calls `shutdown_gateway(...)` on the happy path
therefore leaks a live gateway on every early exit — an assertion panic, an
early `return`, a `?` — and that orphan keeps its listen ports, reparented to
init, contaminating every later run on a fixture with fixed ports (issue #4991).

`tests/common/gateway_harness.rs` exports `GatewayChildGuard` for those
spawners: wrap the child at the instant it is spawned, borrow it through
`child_mut()` for `try_wait` readiness probes, and call `shutdown()` where the
test wants a graceful teardown. `shutdown()` is idempotent and `Drop` runs it,
so teardown is a property of scope rather than of reaching the last line.
`TestGateway` already has the equivalent `Drop`. The contract is covered by
`functional_tcp_proxy_test::test_gateway_guard_reaps_the_child_on_a_panicking_fixture`,
which starts a real gateway, proves it relays, then panics inside
`catch_unwind` and asserts both that the child is reaped and that its ports are
bindable again.

## Host-Dependent Socket Fixtures

Three socket behaviours that Linux fixtures routinely assume are not portable
to the macOS hosts developers build on (issue #4983). Fixtures must either
avoid them or report the missing prerequisite explicitly — never fail as though
the gateway were at fault:

- **Secondary loopback addresses.** Linux assigns all of `127.0.0.0/8` to `lo`,
  so `127.0.0.2` always binds. macOS assigns only `127.0.0.1` to `lo0`, and
  binding an alias fails with `EADDRNOTAVAIL`. Where the fixture needs two
  distinct *listen* identities, IPv6 loopback (`::1`) is the portable stand-in;
  where it needs two IPv4 *source* addresses or two A records on one port
  (`http2_pool_tests`, the per-source TCP cap, the UDP hook-concurrency gate),
  probe for an alias and skip with a message naming the prerequisite. Note that
  UDP sessions are keyed by the full client `SocketAddr`, so per-session
  isolation only needs a second ephemeral **port**, not a second address.
- **Refused connects.** A bound-but-unlistened TCP socket answers a SYN with
  RST on Linux; Darwin drops it, so the connect hangs until the caller's own
  timeout. `tests/scaffolding/ports.rs` states this as
  `REFUSED_TCP_PORT_REFUSES_CONNECT_IMMEDIATELY`; the reservation's *ownership*
  guarantee is unconditional, its observable failure category is not.
- **Datagram ceilings.** macOS defaults `net.inet.udp.maxdgram` to 9216, so a
  ~16 KiB datagram — including the record a max-size DTLS plaintext produces —
  fails with `EMSGSIZE` before it leaves the socket. Size in-limit transport
  probes under that ceiling and assert local size gates separately from
  transport.

Also beware `SO_REUSEADDR`: on Darwin a `127.0.0.1` listener and a `0.0.0.0`
listener can hold one port at the same time. A fixture whose precondition is
"the gateway cannot bind" must contest the *same* address the gateway uses.

## In-Process Test Harness

The scripted-backend test harness (`tests/scaffolding/harness.rs`) ships
two modes:

- **`HarnessMode::Binary`** (default): spawns the built `ferrum-edge`
  subprocess with `Stdio::null()`. Exercises the full CLI / signal /
  process-bootstrap path. Required for tests that assert on captured
  stdout/stderr or rely on kernel-level features that depend on the
  process having its own runtime (kTLS extraction, io_uring submission
  queues).

- **`HarnessMode::InProcess`**: runs the gateway as a tokio task in the
  test process via `ferrum_edge::modes::file::serve()`. Reserves
  ephemeral ports via `tests/scaffolding/ports.rs`, hands the live
  `TcpListener`s to `serve()`, and skips subprocess overhead entirely.
  End-to-end harness setup runs in well under 100 ms versus 2-3 s for
  binary mode.

### When to prefer which

Default to `mode_in_process()` for unit-of-routing-or-plugin-behaviour
tests — the whole `ProxyState` is real, the listener is real, and the
backend (scripted or otherwise) is real. Switch to `mode_binary()` when
the test must verify:

- Subprocess CLI flag parsing (`ferrum-edge run --settings ...`).
- SIGHUP-driven config reload.
- Captured stdout/stderr (in-process mode shares the test process's
  tracing subscriber).
- kTLS / io_uring kernel features.

### Caveats specific to in-process mode

- `pool_warmup_enabled` defaults to `false` in both modes (matches
  `TestGateway`'s pre-existing default). Tests that exercise the
  capability registry's first probe must opt in via
  `pool_warmup_enabled(true)`.
- Binary file-mode startups with warmup off still run the initial
  backend-capability refresh, but only after every required listener has
  bound and `/health` is `ready`. An abandoned `EADDRINUSE` child is
  shut down before that refresh starts, so TestGateway's fresh-port retry
  cannot consume a caller-owned scripted backend (issue #4080). In-process
  `serve()` uses the same bind barrier; the in-process harness additionally
  sets `skip_initial_capability_refresh` when warmup is off.
  Warmup-enabled starts likewise defer synchronous pool warmup until required
  listeners bind, while still completing warmup before `/health` becomes
  ready.
- The file-mode YAML loader's strict-loading rules apply identically —
  every top-level collection (`consumers`, `upstreams`,
  `plugin_configs`) must be present in the YAML even if empty.
  The helpers in `tests/scaffolding/mod.rs`
  (`file_mode_yaml_for_backend` and friends) include the empty-
  collection boilerplate.
- Logs go to whatever `tracing` subscriber the test process has
  installed. `captured_combined()` returns `Err` in in-process mode —
  tests that depend on log assertions stay on binary mode.

## Security Best Practices

1. **JWT Secrets**: Use strong, random secrets for FERRUM_ADMIN_JWT_SECRET and FERRUM_CP_DP_GRPC_JWT_SECRET
2. **TLS Database**: Always use TLS in production for remote databases
3. **Admin API**: Restrict network access to CP Admin API port
4. **Certificate Validation**: Avoid FERRUM_DB_TLS_MODE=require in production
5. **DP gRPC**: Ensure DP is only accessible from authorized locations
