# Ferrum Gateway Architecture

This document provides a comprehensive overview of the Ferrum Gateway codebase architecture to help new developers understand the project structure and contribute effectively.

## 🏗️ High-Level Architecture

Ferrum Gateway is a high-performance API Gateway built in Rust that follows a modular, plugin-based architecture. It supports multiple operating modes and provides dynamic routing, authentication, authorization, and protocol translation capabilities.

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client Apps   │───▶│  Ferrum Gateway │───▶│  Backend Services│
└─────────────────┘    └─────────────────┘    └─────────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │   Admin API     │
              │   (Management)  │
              └─────────────────┘
```

## 📁 Project Structure

### **Core Application (`src/`)**

```
src/
├── main.rs                 # Application entry point and CLI argument parsing
├── lib.rs                  # Library root with public API exports
├── circuit_breaker.rs      # Three-state circuit breaker (Closed/Open/Half-Open)
├── connection_pool.rs      # HTTP client connection pooling with mTLS support
├── consumer_index.rs       # Consumer lookup index for auth plugins
├── health_check.rs         # Active and passive backend health checking
├── load_balancer.rs        # Load balancing (RoundRobin, Weighted, LeastConn, ConsistentHash, Random)
├── plugin_cache.rs         # Plugin configuration cache with atomic updates
├── retry.rs                # Retry logic with backoff strategies
├── router_cache.rs         # Pre-sorted route table with bounded path cache
├── config/                 # Configuration management
│   ├── mod.rs             # Configuration module exports
│   ├── db_loader.rs       # Database configuration loading and migrations
│   ├── env_config.rs      # Environment variable configuration
│   ├── file_loader.rs     # YAML/JSON file configuration loading
│   ├── pool_config.rs     # Connection pool configuration
│   └── types.rs           # Core data structures (Proxy, Consumer, Plugin)
├── proxy/                 # Proxy request handling
│   ├── mod.rs             # ProxyState and main proxy logic
│   ├── body.rs            # ProxyBody sum type (Full/Stream) for response streaming
│   ├── client_ip.rs       # Trusted proxy / X-Forwarded-For client IP resolution
│   ├── handler.rs         # HTTP request/response processing
│   └── grpc_proxy.rs      # gRPC reverse proxy with HTTP/2 and trailer support
├── router_cache.rs        # Pre-sorted route table with bounded path cache
├── connection_pool.rs     # HTTP client connection pooling with mTLS support
├── load_balancer.rs       # Load balancing algorithms and upstream target selection
├── health_check.rs        # Active and passive health checking for upstream targets
├── tls/
│   └── mod.rs             # TLS configuration with advanced hardening
├── dns/                   # DNS resolution and caching
│   ├── mod.rs             # DNS module exports, DnsCacheResolver for HTTP clients
│   └── resolver.rs        # Async DNS resolver with caching
├── http3/                 # HTTP/3 (QUIC) support
│   ├── mod.rs
│   ├── client.rs
│   ├── server.rs
│   └── config.rs
├── admin/                 # Admin API for configuration management
│   ├── mod.rs             # Admin API routes and handlers
│   └── jwt_auth.rs        # JWT authentication for Admin API
├── plugins/               # Plugin system for extensibility
│   ├── mod.rs             # Plugin framework, registry, and priority constants
│   ├── access_control.rs  # Consumer-based authorization
│   ├── basic_auth.rs      # HTTP Basic auth with bcrypt
│   ├── body_validator.rs  # JSON/XML request body validation
│   ├── bot_detection.rs   # Bot detection and mitigation
│   ├── correlation_id.rs  # Correlation ID generation and propagation
│   ├── cors.rs            # Cross-Origin Resource Sharing
│   ├── hmac_auth.rs       # HMAC authentication
│   ├── http_logging.rs    # HTTP endpoint logging
│   ├── ip_restriction.rs  # IP-based access control
│   ├── jwt_auth.rs        # HS256 JWT authentication
│   ├── key_auth.rs        # API key authentication
│   ├── oauth2_auth.rs     # OAuth2 introspection/JWKS validation
│   ├── otel_tracing.rs    # OpenTelemetry distributed tracing
│   ├── prometheus_metrics.rs # Prometheus metrics export
│   ├── rate_limiting.rs   # In-memory rate limiting
│   ├── request_termination.rs # Early response / request termination
│   ├── request_transformer.rs # Header/query modification
│   ├── response_transformer.rs # Response header modification
│   ├── stdout_logging.rs  # JSON transaction logging
│   ├── transaction_debugger.rs # Verbose request/response debugging
│   └── utils/             # Plugin utilities
│       ├── mod.rs
│       └── http_client.rs
├── grpc/                  # gRPC CP/DP communication
│   ├── mod.rs
│   ├── cp_server.rs       # Control Plane gRPC server
│   └── dp_client.rs       # Data Plane gRPC client
└── modes/                 # Operating modes
    ├── mod.rs
    ├── control_plane.rs   # Control Plane mode
    ├── data_plane.rs      # Data Plane mode
    ├── database.rs        # Database mode
    └── file.rs            # File mode
```

### **Tests (`tests/`)**

```
tests/
├── README.md                           # Test suite documentation
├── config.yaml                         # Test configuration fixture
├── certs/                              # TLS certificates for testing
│
├── unit_tests.rs                       # Entry point: unit test crate
├── unit/                               # Unit tests by component
│   ├── plugins/                        # All 20 plugin tests
│   ├── config/                         # Configuration parsing tests
│   ├── admin/                          # Admin API tests
│   └── gateway_core/                   # Core data structure tests
│
├── integration_tests.rs                # Entry point: integration test crate
├── integration/                        # Integration tests
│
├── functional_tests.rs                 # Entry point: functional test crate
├── functional/                         # End-to-end functional tests
│
├── helpers/bin/                        # Standalone test server binaries
│
└── performance/                        # Performance/load testing (separate crate)
```

### **Documentation (`docs/`)**

```
docs/
├── admin_read_only_mode.md  # Admin API read-only mode
├── backend_mtls.md          # Backend mTLS configuration
├── ci_cd.md                 # CI/CD pipeline documentation
├── cors_plugin.md           # CORS plugin configuration
├── cp_dp_mode.md            # Control Plane / Data Plane architecture
├── dns_resolver.md          # DNS resolver configuration
├── docker.md                # Docker deployment guide
├── frontend_tls.md          # Frontend TLS/mTLS configuration
├── functional_testing.md    # CP/DP functional testing guide
├── functional_testing_database.md  # Database mode testing
├── functional_testing_file_mode.md # File mode testing
├── load_balancing.md        # Load balancing, health checks, retry, circuit breaker
├── plugin_execution_order.md # Plugin priority and execution order
├── response_body_streaming.md # Response body streaming vs buffering
└── size_limits.md           # Request/response size limits
```

### **Performance Testing (`tests/performance/`)**

```
tests/performance/
```

## 🧩 Core Components

### **1. Configuration System (`src/config/`)**

The configuration system provides flexible configuration management through multiple sources:

- **`env_config.rs`**: Environment variable parsing and validation
- **`pool_config.rs`**: Connection pool settings with global defaults and proxy overrides
- **`types.rs`**: Core data structures including `Proxy`, `Consumer`, and `Plugin` definitions

**Key Features**:
- Environment variable configuration for all settings
- YAML/JSON file configuration support
- Per-proxy configuration overrides
- Configuration validation and defaults

### **2. Proxy Engine (`src/proxy/` + `src/router_cache.rs` + `src/plugin_cache.rs` + `src/consumer_index.rs`)**

The proxy engine handles all request routing and processing with **consistent security for HTTP and WebSocket**:

**Key Features**:
- **Router cache** with pre-sorted route table and bounded path lookup cache with random-sample eviction (`src/router_cache.rs`)
- Longest prefix match routing with O(1) cache hits for repeated paths
- Route table rebuilt atomically via ArcSwap on config changes — never on the hot request path
- **Plugin cache** returns `Arc<Vec<...>>` for zero-allocation per-request plugin retrieval (`src/plugin_cache.rs`)
- **Consumer index** with separate per-credential-type HashMaps for allocation-free O(1) auth lookups (`src/consumer_index.rs`)
- **Load balancer cache** with pre-computed target keys and O(1) upstream index (`src/load_balancer.rs`)
- Protocol translation (HTTP ↔ WebSocket)
- HTTP/1.1 and HTTP/2 inbound support (auto-negotiated via ALPN on TLS connections)
- Request/response transformation
- **Unified plugin pipeline** for HTTP and WebSocket requests
- **Full authentication and authorization** for WebSocket connections
- **Rate limiting** applies to WebSocket connections
- **Complete logging** of WebSocket connections
- **TCP keepalive** on inbound connections (60s interval) for stale client detection
- **Configurable response body mode** — per-proxy `response_body_mode` (stream/buffer); plugins can force buffering via `requires_response_body_buffering()`

**Security Model**:
- **WebSocket requests** go through the same plugin pipeline as HTTP requests
- **Authentication plugins** (key_auth, jwt_auth, etc.) protect WebSocket endpoints
- **Authorization plugins** (access_control) enforce IP restrictions on WebSocket connections
- **Rate limiting plugins** prevent WebSocket connection abuse
- **Logging plugins** provide complete audit trail for WebSocket connections

### **3. Frontend TLS (`src/tls/mod.rs`)**

TLS configuration for client connections with optional mutual authentication:

**Key Features**:
- HTTP/HTTPS dual-mode operation
- **ALPN protocol advertisement** (`h2` and `http/1.1`) enabling HTTP/2 on TLS connections
- Server certificate presentation for HTTPS
- Optional client certificate verification for mTLS
- Global environment variable configuration
- Support for all operating modes

**TLS Modes**:
- **HTTP**: Plain text connections on dedicated port (default 8000)
- **HTTPS**: Encrypted connections with server authentication on dedicated port (default 8443)
- **mTLS**: Encrypted connections with mutual authentication on HTTPS port
- **No-Verify Mode**: Testing mode with disabled certificate verification

**Listener Architecture**:
- **Separate HTTP and HTTPS listeners** for clear protocol separation
- **HTTP listener**: Always enabled, handles plain text traffic
- **HTTPS listener**: Enabled only when TLS certificates are configured
- **No protocol conflicts**: Each listener handles its protocol exclusively
- **Standard port conventions**: HTTP (8000), HTTPS (8443), both configurable

### **3.1 Admin API Listeners (`src/admin/mod.rs`)**

Separate HTTP and HTTPS listeners for the Admin API with enhanced TLS support:

**Key Features**:
- **Separate Admin Listeners**: Independent from proxy listeners
- **Admin HTTP**: Always enabled on port 9000 (configurable)
- **Admin HTTPS**: Enabled when admin TLS certificates are configured on port 9443 (configurable)
- **Admin mTLS**: Client certificate verification for admin access
- **JWT Authentication**: Required on both HTTP and HTTPS endpoints
- **No-Verify Mode**: Testing mode for admin API TLS

**Admin Listener Architecture**:
- **Admin HTTP Listener**: `FERRUM_ADMIN_HTTP_PORT` (default 9000)
- **Admin HTTPS Listener**: `FERRUM_ADMIN_HTTPS_PORT` (default 9443)
- **Admin TLS Certificates**: `FERRUM_ADMIN_TLS_CERT_PATH`, `FERRUM_ADMIN_TLS_KEY_PATH`
- **Admin Client CA Bundle**: `FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH` for mTLS
- **Admin No-Verify**: `FERRUM_ADMIN_TLS_NO_VERIFY` for testing

**Operating Mode Support**:
- **Database Mode**: Full admin API with HTTP/HTTPS/mTLS (reads fall back to cached config if DB is offline)
- **Control Plane Mode**: Full admin API with HTTP/HTTPS/mTLS (reads fall back to cached config if DB is offline)
- **File Mode**: No admin API (proxy only)
- **Data Plane Mode**: Read-only admin API served from cached config (writes return 403)

### **3.2 HTTP/3 (QUIC) (`src/http3/`)**

Optional HTTP/3 listener using QUIC transport, enabled via `FERRUM_ENABLE_HTTP3=true`:

**Key Features**:
- QUIC-based transport with TLS 1.3 (mandatory per spec)
- Shares the HTTPS port with HTTP/1.1 and HTTP/2 listeners
- Configurable idle timeout and max concurrent streams
- **0-RTT early data is disabled** for security — 0-RTT is vulnerable to replay attacks on non-idempotent operations proxied through the gateway

### **4. Load Balancer & Health Checks (`src/load_balancer.rs`, `src/health_check.rs`)**

Distributes traffic across multiple backend targets within an upstream group:

**Key Features**:
- Five algorithms: round robin, weighted round robin (smooth WRR), least connections, consistent hashing (150 vnodes), random
- Atomic rebuild on config changes — no requests dropped during reconfiguration
- Active health checks (periodic HTTP probes) and passive health checks (response monitoring)
- Passive recovery timer (`healthy_after_seconds`) for automatic target restoration
- Connection errors always count as passive health check failures
- All-unhealthy fallback: routes to all targets rather than returning errors
- `TargetSelection` carries `is_fallback` flag for downstream observability
- Client-facing headers: `X-Gateway-Error` (connection_failure | backend_timeout | backend_error) and `X-Gateway-Upstream-Status: degraded`
- See [docs/load_balancing.md](docs/load_balancing.md) for full configuration reference

### **4.1 Connection Pool (`src/connection_pool.rs`)**

High-performance HTTP client connection pooling with backend mTLS support:

**Key Features**:
- Connection reuse and keep-alive with per-proxy pool keys
- Lock-free cleanup using `AtomicU64` epoch timestamps (avoids deadlock with DashMap)
- HTTP/2 negotiated via ALPN on HTTPS (no forced h2c cleartext mode)
- TCP keepalive only when `enable_http_keep_alive` is true
- Backend mTLS authentication with client certificates
- Custom CA bundle support for server certificate verification
- No-Verify mode for testing environments (`FERRUM_BACKEND_TLS_NO_VERIFY`)
- Per-proxy connection configuration overrides
- Transparent DNS cache integration via `DnsCacheResolver` — no DNS in the hot path
- Connection statistics and monitoring

### **4. Plugin System (`src/plugins/`)**

Extensible plugin architecture for authentication, authorization, and transformations:

**20 Plugins Implemented**:
- **Authentication**: `jwt_auth`, `key_auth`, `basic_auth`, `oauth2_auth`, `hmac_auth`
- **Authorization**: `access_control`, `ip_restriction`
- **Security**: `cors`, `bot_detection`
- **Rate Limiting**: `rate_limiting`
- **Transformation**: `request_transformer`, `response_transformer`, `request_termination`, `body_validator`
- **Observability**: `stdout_logging`, `http_logging`, `transaction_debugger`, `correlation_id`, `prometheus_metrics`, `otel_tracing`

**Plugin Lifecycle**:
1. **Request Phase**: Authentication → Authorization → Rate Limiting
2. **Response Phase**: Logging → Metrics
3. **Error Phase**: Error handling and logging

### **5. Admin API (`src/admin/`)**

RESTful API for dynamic configuration management:

**Endpoints**:
- `/proxies` - Proxy CRUD operations
- `/consumers` - Consumer management
- `/plugins` - Plugin configuration
- JWT-based authentication and authorization

### **6. Operating Modes (`src/modes/`)**

Four distinct operating modes for different deployment scenarios:

#### **Database Mode (`database.rs`)**
- Single gateway instance with database storage
- Periodic configuration polling
- Admin API included
- **Use Case**: Small to medium deployments

#### **File Mode (`file.rs`)**
- Configuration from local files
- SIGHUP-based reloading
- No Admin API
- **Use Case**: Development, immutable infrastructure

#### **Control Plane Mode (`control_plane.rs`)**
- Centralized configuration management
- Database integration
- gRPC configuration distribution
- No proxy traffic handling
- **Use Case**: Distributed deployments

#### **Data Plane Mode (`data_plane.rs`)**
- Proxy traffic only
- gRPC configuration from Control Plane
- Read-only Admin API served from cached config
- **Use Case**: Scalable traffic processing

### **6.1 Data Source Resiliency**

The gateway is designed to continue operating indefinitely when its data source becomes unavailable. Configuration is loaded into memory once and all request-path operations use the in-memory cache — no per-request database or file access.

#### **How It Works**

All modes store the active configuration in an `ArcSwap<GatewayConfig>` — a lock-free, atomically-swappable smart pointer. Every proxy request reads from this in-memory cache, never from the data source directly. Background tasks periodically attempt to refresh the config from the source, but failures only produce a log warning and never affect request handling.

#### **Failure Behavior by Mode**

| Mode | Data Source | On Source Failure |
|------|------------|-------------------|
| **File** | YAML/JSON file | Config loaded once at startup. File can be deleted/corrupted afterward with zero impact. SIGHUP reload gracefully falls back to previous config on parse errors. |
| **Database** | SQL database | Polling loop logs a warning and continues with cached config. Gateway serves traffic indefinitely with stale config until DB recovers. |
| **Control Plane** | SQL database | Polling loop logs a warning. Does not broadcast stale updates to Data Planes. DPs retain their last known config. Admin API reads fall back to the in-memory cached config. |
| **Data Plane** | Control Plane (gRPC) | Auto-reconnects to CP every 5 seconds. Continues serving traffic with cached config. Admin API reads served from cached config with `X-Data-Source: cached` header. |

#### **Admin API Resilience**

Admin API read endpoints (GET proxies, consumers, plugin configs) use a two-tier strategy:
1. **Primary**: Query the database for fresh data
2. **Fallback**: If the database is unavailable (or not configured, as in DP mode), serve from the in-memory cached config

Fallback responses include an `X-Data-Source: cached` header so callers can detect stale data. Write operations (POST/PUT/DELETE) require a live database and will return `503 Service Unavailable` if the database is offline — there is no way to safely write without a data store.

The `/health` endpoint reports `cached_config` status including availability, `loaded_at` timestamp, and proxy/consumer counts, providing operational visibility during outages.

### **7. DNS System (`src/dns/`)**

Async DNS resolution with caching designed to keep lookups off the hot request path:

**Key Features**:
- In-memory `DashMap` caching with configurable TTL
- **Startup warmup** — resolves all proxy backend, upstream target, and plugin endpoint hostnames (deduplicated) before accepting requests
- **Background refresh** — proactively re-resolves entries at 75% TTL before expiration
- **`DnsCacheResolver` / `DnsCacheResolver`** — custom `reqwest::dns::Resolve` implementations that route all HTTP client DNS lookups (proxy backends, health checks, and plugin outbound calls) through the cache, keeping DNS off the hot request path
- Static DNS overrides (global and per-proxy)
- Per-proxy DNS configuration and TTL overrides
- Graceful degradation on resolution failures

### **8. Load Balancer (`src/load_balancer.rs`)**

Five load balancing algorithms for distributing traffic across backend targets:

- **RoundRobin** (default) - Sequential distribution
- **WeightedRoundRobin** - Weight-based distribution
- **LeastConnections** - Routes to the target with fewest active connections
- **ConsistentHashing** - Hash-based routing with configurable hash_on field
- **Random** - Random target selection

Integrates with health checking to skip unhealthy targets.

### **9. Health Checker (`src/health_check.rs`)**

Active and passive backend health checking:

- **Active checks**: Periodic HTTP/HTTPS probes with configurable path, method, expected status, timeout, and interval
- **Passive checks**: Monitors HTTP status codes from proxied requests with windowed failure counting
- **Unhealthy target tracking**: DashMap-based, integrates with load balancer to skip failing backends

### **10. Circuit Breaker (`src/circuit_breaker.rs`)**

Three-state circuit breaker pattern (Closed/Open/Half-Open) to prevent cascading failures. Configurable failure and success thresholds, timeout for Open-to-Half-Open transitions, and max probe requests in Half-Open state.

### **11. Retry Logic (`src/retry.rs`)**

Configurable retry logic with backoff strategies:

- Distinguishes TCP/connection-level failures from HTTP status failures
- Fixed and exponential backoff strategies
- Configurable retryable methods and status codes

## Performance & Scalability

The gateway is designed to scale to **10,000+ proxy/consumer resources** and **30,000+ plugin configurations** with minimal per-request overhead. All hot-path data structures use lock-free reads and pre-computed indexes.

### **Per-Request Data Structure Complexity**

| Component | Lookup | Lock Type | Notes |
|-----------|--------|-----------|-------|
| Route matching | O(1) cache hit / O(routes) fallback | Lock-free ArcSwap | DashMap path cache with random-sample eviction |
| Plugin lookup | O(1) HashMap | Lock-free ArcSwap | Returns `Arc<Vec<...>>` — zero Vec allocation per request |
| Consumer auth | O(1) per credential type | Lock-free ArcSwap | Separate indexes per type (no format!() allocation) |
| Upstream lookup | O(1) HashMap | Lock-free ArcSwap | Pre-built index avoids linear scan |
| Load balancer | O(1) round-robin / O(log n) consistent hash | Lock-free ArcSwap | Pre-computed target keys avoid format!() per request |
| Circuit breaker | O(1) atomic loads | Lock-free DashMap | |
| Health check state | O(1) DashMap | Lock-free DashMap | |

### **Key Design Decisions for Scale**

- **ArcSwap everywhere**: Config updates are atomic pointer swaps. Readers never block, even during config reload with 10k+ resources.
- **Pre-computed indexes**: Plugin configs are indexed by `proxy_id` at build time (O(P+C) rebuild instead of O(P×C)). Consumer credentials are split into separate HashMaps per type. Load balancer target keys are pre-computed strings.
- **Zero per-request allocation in plugin lookup**: `PluginCache::get_plugins()` returns `Arc<Vec<Arc<dyn Plugin>>>` — a single Arc clone, not N Arc clones + Vec allocation.
- **Random-sample cache eviction**: RouterCache evicts ~25% of entries when full instead of clearing the entire cache, preventing thundering-herd O(routes) scans.
- **No locks on the hot path**: All request-path reads use `ArcSwap::load()` (lock-free) or `DashMap` (per-bucket sharded locks). No `Mutex` or `RwLock` in the request pipeline.

### **Config Rebuild Performance**

When configuration changes (database poll, SIGHUP, or gRPC push), all caches are rebuilt atomically off the hot path:

| Cache | Rebuild Complexity | Notes |
|-------|-------------------|-------|
| RouterCache | O(n log n) sort | Pre-sorted by listen_path length |
| PluginCache | O(P + C) | Plugin configs pre-indexed by proxy_id |
| ConsumerIndex | O(consumers × credentials) | ~3-5 index entries per consumer |
| LoadBalancerCache | O(upstreams × targets) | Pre-computes target keys and hash rings |

In-flight requests continue using the previous config snapshot via Arc reference counting — zero disruption during reload.

## 🔄 Request Flow

### **HTTP Request Processing**

```
1. Client Request (TCP keepalive set on accept)
   ↓
2. TLS Termination + ALPN negotiation (HTTP/1.1 or HTTP/2)
   ↓
3. Router Cache Lookup (O(1) cache hit or pre-sorted prefix scan)
   ↓
4. Plugin Pipeline (auth → authz → rate limit)
   ↓
5. Load Balancer Target Selection (if upstream configured)
   ↓
6. Connection Pool (get/create client per proxy key, DNS via cache)
   ↓
7. Backend Request (with mTLS if configured, retry on failure)
   ↓
8. Health Check Reporting (passive: record success/failure)
   ↓
9. Response Processing (stream or buffer based on response_body_mode)
   ↓
10. Plugin Response Pipeline
   ↓
11. Client Response
```

### **WebSocket Request Processing**

All WebSocket connections go through the full plugin authentication pipeline — there is no unauthenticated bypass path. The upgrade is performed only after all plugins (auth, authz, rate limiting, logging) have executed successfully.

```
1. WebSocket Upgrade Request
   ↓
2. Route Matching
   ↓
3. Full Plugin Pipeline (auth → authz → rate limit → logging)
   ↓
4. Connection Pool (with mTLS)
   ↓
5. Backend WebSocket Upgrade
   ↓
6. Bidirectional Proxying
```

## 🔧 Configuration Hierarchy

Configuration follows a clear priority order:

1. **Proxy-specific configuration** (highest priority)
2. **Global environment variables**
3. **Default values** (lowest priority)

Example for mTLS:
```yaml
# Proxy-specific (highest priority)
proxies:
  - id: "api"
    backend_tls_client_cert_path: "/path/to/proxy-cert.pem"
    backend_tls_client_key_path: "/path/to/proxy-key.pem"
```

```bash
# Global environment variables (fallback)
export FERRUM_BACKEND_TLS_CA_BUNDLE_PATH="/path/to/ca-bundle.pem"
export FERRUM_BACKEND_TLS_CLIENT_CERT_PATH="/path/to/global-cert.pem"
export FERRUM_BACKEND_TLS_CLIENT_KEY_PATH="/path/to/global-key.pem"
```

## 🧪 Testing Strategy

The project uses comprehensive testing at multiple levels:

### **Unit Tests**
- All tests located in `tests/` directory (no inline tests in `src/`)
- Test individual functions and modules
- Fast execution with minimal dependencies

### **Integration Tests**
- Located in `tests/` directory alongside unit tests
- Test component interactions
- Include end-to-end scenarios (e.g., router cache → URL mapping → backend URL)

### **Plugin Testing**
- `plugin_utils.rs` provides shared test utilities
- Each plugin has dedicated test files
- Test plugin lifecycle and configuration

### **Performance Testing**
- `tests/performance/` directory contains performance benchmarks
- Automated performance regression testing
- Load testing scenarios

## 🚀 Getting Started for New Developers

### **1. Development Setup**

```bash
# Clone and build
git clone https://github.com/your-org/ferrum-gateway.git
cd ferrum-gateway
cargo build

# Run tests
cargo test

# Start with example config
FERRUM_MODE=file \
FERRUM_FILE_CONFIG_PATH=tests/config.yaml \
cargo run
```

### **2. Understanding the Codebase**

1. **Start with `src/main.rs`** - Understand application startup
2. **Read `src/config/types.rs`** - Learn core data structures
3. **Study `src/proxy/mod.rs`** - Understand proxy state management
4. **Explore `src/plugins/mod.rs`** - Learn plugin system
5. **Review operating modes** - Choose a mode to understand deeply

### **3. Adding New Features**

#### **New Plugin**
1. Create plugin file in `src/plugins/`
2. Implement `Plugin` trait
3. Add to plugin registry in `src/plugins/mod.rs`
4. Add configuration to `src/config/types.rs`
5. Write tests in `tests/`

#### **New Configuration Option**
1. Add field to appropriate struct in `src/config/types.rs`
2. Add environment variable parsing in `src/config/env_config.rs`
3. Update documentation
4. Add tests

#### **New Admin API Endpoint**
1. Add handler in `src/admin/handlers/`
2. Register route in `src/admin/mod.rs`
3. Add authentication/authorization as needed
4. Write integration tests

### **4. Code Style Guidelines**

- Follow Rust idioms and `rustfmt` formatting
- Use `tracing` for structured logging
- Write comprehensive tests for new features
- Update documentation for API changes
- Use `anyhow` for error handling
- Prefer async/await for I/O operations

### **5. Common Patterns**

#### **Error Handling**
```rust
use anyhow::{Result, Context};

fn example_function() -> Result<String> {
    let value = some_operation()
        .context("Failed to perform operation")?;
    Ok(value)
}
```

#### **Logging**
```rust
use tracing::{info, warn, error, debug};

info!("Gateway starting up");
warn!("Configuration issue detected");
error!("Failed to process request: {}", error);
debug!("Processing request for path: {}", path);
```

#### **Configuration**
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MyConfig {
    #[serde(default)]
    pub my_field: String,
    #[serde(default = "default_value")]
    pub my_number: u32,
}
```

## 🔄 Development Workflow

### **1. Feature Development**
1. Create feature branch from `main`
2. Implement changes with tests
3. Run full test suite
4. Update documentation
5. Submit pull request

### **2. Testing**
```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run with output
cargo test -- --nocapture

# Run integration tests
cargo test --test '*'
```

### **3. Building**
```bash
# Development build
cargo build

# Release build
cargo build --release

# Run WebSocket test server
cargo test --test websocket_echo_server -- --nocapture
```

## 📚 Additional Resources

- **`IMPLEMENTATION_ANALYSIS.md`** - Detailed implementation status
- **`docs/`** - Feature-specific documentation (TLS, DNS, CORS, Docker, CI/CD, etc.)
- **`tests/README.md`** - Test suite documentation
- **`tests/performance/README.md`** - Performance testing guide
- **`comparison/README.md`** - API gateway comparison benchmarks

## 🤝 Contributing

We welcome contributions! Please:

1. Read this architecture guide first
2. Check existing issues and pull requests
3. Follow the code style guidelines
4. Write comprehensive tests
5. Update documentation
6. Ensure all tests pass before submitting

For questions or guidance, reach out through GitHub issues or discussions.
