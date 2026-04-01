# Ferrum Edge Architecture

This document provides a comprehensive overview of the Ferrum Edge codebase architecture to help new developers understand the project structure and contribute effectively.

## High-Level Architecture

Ferrum Edge is a high-performance edge proxy built in Rust that follows a modular, plugin-based architecture. It supports multiple operating modes and provides dynamic routing, authentication, authorization, and protocol translation capabilities.

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client Apps   │───▶│  Ferrum Edge │───▶│  Backend Services│
└─────────────────┘    └─────────────────┘    └─────────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │   Admin API     │
              │   (Management)  │
              └─────────────────┘
```

## Project Structure

### **Core Application (`src/`)**

```
src/
├── main.rs                    # Application entry point and CLI argument parsing
├── lib.rs                     # Library root with public API exports
├── circuit_breaker.rs         # Three-state circuit breaker (Closed/Open/Half-Open)
├── config_delta.rs            # Incremental config updates for CP/DP
├── connection_pool.rs         # HTTP client connection pooling with mTLS support
├── consumer_index.rs          # Consumer lookup index for auth plugins
├── health_check.rs            # Active and passive backend health checking
├── load_balancer.rs           # Load balancing (RoundRobin, Weighted, LeastConn, ConsistentHash, Random)
├── plugin_cache.rs            # Plugin configuration cache with atomic updates
├── retry.rs                   # Retry logic with backoff strategies
├── router_cache.rs            # Pre-sorted route table with bounded path cache
├── admin/                     # Admin API for configuration management
│   ├── mod.rs                 # Admin API routes and handlers
│   └── jwt_auth.rs            # JWT authentication for Admin API
├── config/                    # Configuration management
│   ├── mod.rs                 # Configuration module exports
│   ├── conf_file.rs           # File configuration helpers
│   ├── config_backup.rs       # Config backup support for startup failover
│   ├── config_migration.rs    # Config version migrations
│   ├── db_loader.rs           # Database configuration loading and polling
│   ├── env_config.rs          # Environment variable configuration
│   ├── file_loader.rs         # YAML/JSON file configuration loading
│   ├── pool_config.rs         # Connection pool configuration
│   ├── types.rs               # Core data structures (Proxy, Consumer, Plugin)
│   └── migrations/            # SQL schema migrations
│       ├── mod.rs             # Migration registry
│       └── v001_initial_schema.rs  # Initial database schema
├── dns/                       # DNS resolution and caching
│   ├── mod.rs                 # DNS module exports, DnsCacheResolver for HTTP clients
│   └── resolver.rs            # Async DNS resolver with caching
├── dtls/                      # DTLS support (frontend termination, backend origination)
│   └── mod.rs                 # DTLS certificate helpers
├── grpc/                      # gRPC CP/DP communication
│   ├── mod.rs
│   ├── cp_server.rs           # Control Plane gRPC server
│   └── dp_client.rs           # Data Plane gRPC client
├── http3/                     # HTTP/3 (QUIC) support
│   ├── mod.rs
│   ├── client.rs              # HTTP/3 client connections
│   ├── config.rs              # HTTP/3 configuration
│   └── server.rs              # HTTP/3 server listener
├── modes/                     # Operating modes
│   ├── mod.rs
│   ├── control_plane.rs       # Control Plane mode
│   ├── data_plane.rs          # Data Plane mode
│   ├── database.rs            # Database mode
│   ├── file.rs                # File mode
│   └── migrate.rs             # Database migration mode
├── plugins/                   # Plugin system (22 built-in plugins)
│   ├── mod.rs                 # Plugin framework, registry, and priority constants
│   ├── access_control.rs      # Consumer-based authorization
│   ├── basic_auth.rs          # HTTP Basic auth with bcrypt
│   ├── body_transform.rs      # Request/response body transformation
│   ├── body_validator.rs      # JSON/XML request body validation
│   ├── bot_detection.rs       # Bot detection and mitigation
│   ├── correlation_id.rs      # Correlation ID generation and propagation
│   ├── cors.rs                # Cross-Origin Resource Sharing
│   ├── graphql.rs             # GraphQL query validation and rate limiting
│   ├── hmac_auth.rs           # HMAC authentication
│   ├── http_logging.rs        # HTTP endpoint logging
│   ├── ip_restriction.rs      # IP-based access control
│   ├── jwks_auth.rs           # JWKS multi-provider JWT validation
│   ├── jwks_cache.rs          # Global shared JWKS key store cache
│   ├── jwks_store.rs          # JWKS key store with background refresh
│   ├── jwt_auth.rs            # HS256 JWT authentication
│   ├── key_auth.rs            # API key authentication
│   ├── mtls_auth.rs           # Mutual TLS client certificate authentication
│   ├── otel_tracing.rs        # OpenTelemetry distributed tracing
│   ├── prometheus_metrics.rs  # Prometheus metrics export
│   ├── rate_limiting.rs       # In-memory rate limiting
│   ├── request_termination.rs # Early response / request termination
│   ├── request_transformer.rs # Header/query modification
│   ├── response_caching.rs    # Response caching
│   ├── response_transformer.rs # Response header modification
│   ├── stdout_logging.rs      # JSON transaction logging
│   ├── transaction_debugger.rs # Verbose request/response debugging
│   └── utils/                 # Plugin utilities
│       ├── mod.rs
│       └── http_client.rs     # Shared HTTP client for plugin outbound calls
├── proxy/                     # Proxy request handling
│   ├── mod.rs                 # ProxyState, handle_proxy_request, URL building
│   ├── body.rs                # ProxyBody sum type (Full/Tracked) for response streaming
│   ├── client_ip.rs           # Trusted proxy / X-Forwarded-For client IP resolution
│   ├── grpc_proxy.rs          # gRPC reverse proxy with HTTP/2 and trailer support
│   ├── http2_pool.rs          # HTTP/2 connection pooling
│   ├── stream_listener.rs     # Stream listener lifecycle manager (reconcile on config reload)
│   ├── tcp_proxy.rs           # Raw TCP stream proxy with TLS termination/origination
│   └── udp_proxy.rs           # UDP datagram proxy with per-client session tracking, DTLS
├── secrets/                   # Secret management providers
│   ├── mod.rs                 # Secret resolution orchestration
│   ├── aws.rs                 # AWS Secrets Manager provider
│   ├── azure.rs               # Azure Key Vault provider
│   ├── env.rs                 # Environment variable secret provider
│   ├── file.rs                # File-based secret provider
│   ├── gcp.rs                 # GCP Secret Manager provider
│   └── vault.rs               # HashiCorp Vault provider
├── service_discovery/         # Dynamic upstream discovery
│   ├── mod.rs                 # Service discovery orchestrator
│   ├── consul.rs              # Consul provider
│   ├── dns_sd.rs              # DNS-SD provider
│   └── kubernetes.rs          # Kubernetes provider
└── tls/
    └── mod.rs                 # TLS configuration with advanced hardening
```

### **Tests (`tests/`)**

```
tests/
├── README.md                           # Test suite documentation
├── config.yaml                         # Test configuration fixture
├── certs/                              # TLS certificates for testing
├── fixtures/                           # RSA key fixtures for auth plugin tests
├── scripts/                            # Test setup scripts (e.g., DB TLS)
│
├── unit_tests.rs                       # Entry point: unit test crate
├── unit/                               # Unit tests by component
│   ├── plugins/                        # All 22 plugin tests
│   ├── config/                         # Configuration parsing tests
│   ├── admin/                          # Admin API tests
│   ├── gateway_core/                   # Core data structure tests
│   └── secrets/                        # Secret provider tests
│
├── integration_tests.rs                # Entry point: integration test crate
├── integration/                        # Integration tests (mTLS, connection pool, gRPC, HTTP/3, admin API)
│
├── functional_tests.rs                 # Entry point: functional test crate
├── functional/                         # End-to-end functional tests
│
├── helpers/bin/                        # Standalone test server binaries
│
└── performance/                        # Performance/load testing (separate crate)
    └── multi_protocol/                 # Multi-protocol benchmark suite
```

### **Documentation (`docs/`)**

```
docs/
├── admin_backup_restore.md     # Admin backup and restore API
├── admin_batch_api.md          # Admin batch operations API
├── admin_read_only_mode.md     # Admin API read-only mode
├── backend_mtls.md             # Backend mTLS configuration
├── ci_cd.md                    # CI/CD pipeline documentation
├── client_ip_resolution.md     # Client IP resolution and trusted proxies
├── cors_plugin.md              # CORS plugin configuration
├── cp_dp_mode.md               # Control Plane / Data Plane architecture
├── database_tls.md             # Database TLS configuration
├── dns_resolver.md             # DNS resolver configuration
├── docker.md                   # Docker deployment guide
├── error_classification.md     # Error classification and gateway headers
├── frontend_tls.md             # Frontend TLS/mTLS configuration
├── functional_testing.md       # CP/DP functional testing guide
├── functional_testing_auth_acl.md  # Auth/ACL functional testing
├── functional_testing_database.md  # Database mode testing
├── functional_testing_file_mode.md # File mode testing
├── infrastructure_sizing.md    # Infrastructure sizing guide
├── load_balancing.md           # Load balancing, health checks, retry, circuit breaker
├── migrations.md               # Database migration documentation
├── pingora_comparison.md       # Pingora comparison analysis
├── plugin_execution_order.md   # Plugin priority and execution order
├── response_body_streaming.md  # Response body streaming vs buffering
├── routing.md                  # Routing and path matching
├── size_limits.md              # Request/response size limits
└── tcp_udp_proxy.md            # TCP/UDP stream proxy documentation
```

## Core Components

### **1. Configuration System (`src/config/`)**

The configuration system provides flexible configuration management through multiple sources:

- **`env_config.rs`**: Environment variable parsing and validation
- **`pool_config.rs`**: Connection pool settings with global defaults and proxy overrides
- **`types.rs`**: Core data structures including `Proxy`, `Consumer`, and `Plugin` definitions
- **`conf_file.rs`**: File configuration helpers
- **`config_backup.rs`**: Config backup support for startup failover when the data source is unreachable
- **`config_migration.rs`**: Config version migrations for schema evolution
- **`db_loader.rs`**: Database configuration loading with incremental polling

**Key Features**:
- Environment variable configuration for all settings
- YAML/JSON file configuration support
- Per-proxy configuration overrides
- Configuration validation and defaults
- Config backup for startup failover (`FERRUM_DB_CONFIG_BACKUP_PATH`)

### **2. Proxy Engine (`src/proxy/` + `src/router_cache.rs` + `src/plugin_cache.rs` + `src/consumer_index.rs`)**

The proxy engine handles all request routing and processing with **consistent security for HTTP and WebSocket**:

**Key Features**:
- **Router cache** with pre-sorted route table and bounded path lookup cache with random-sample eviction (`src/router_cache.rs`)
- Longest prefix match routing with O(1) cache hits for repeated paths
- Route table rebuilt atomically via ArcSwap on config changes — never on the hot request path
- **Plugin cache** returns `Arc<Vec<...>>` for zero-allocation per-request plugin retrieval; pre-computes response body buffering requirements per proxy to avoid per-request iteration (`src/plugin_cache.rs`)
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
- **TCP/UDP stream proxying** with TLS termination/origination and DTLS support (`src/proxy/tcp_proxy.rs`, `src/proxy/udp_proxy.rs`)
- **Stream listener lifecycle management** — reconciles TCP/UDP listeners on config reload (`src/proxy/stream_listener.rs`)
- **HTTP/2 connection pooling** for dedicated HTTP/2 backend connections (`src/proxy/http2_pool.rs`)

**Security Model**:
- **WebSocket requests** go through the same plugin pipeline as HTTP requests
- **Authentication plugins** (key_auth, jwt_auth, mtls_auth, etc.) protect WebSocket endpoints
- **Authorization plugins** (`access_control`) enforce consumer authorization on WebSocket connections
- **Pre-auth IP plugins** (`ip_restriction`) enforce IP/CIDR restrictions on WebSocket connections
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
- **File Mode**: Read-only admin API served from cached config
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
- No-Verify mode for testing environments (`FERRUM_TLS_NO_VERIFY`)
- Per-proxy connection configuration overrides
- Transparent DNS cache integration via `DnsCacheResolver` — no DNS in the hot path
- Connection statistics and monitoring

### **5. Plugin System (`src/plugins/`)**

Extensible plugin architecture for authentication, authorization, and transformations:

**22 Plugins Registered**:
- **Authentication**: `jwks_auth`, `jwt_auth`, `key_auth`, `basic_auth`, `hmac_auth`, `mtls_auth`
- **Authorization**: `access_control`, `ip_restriction`
- **Security**: `cors`, `bot_detection`
- **Rate Limiting**: `rate_limiting`
- **Transformation**: `request_transformer`, `response_transformer`, `request_termination`, `body_validator`, `graphql`
- **Caching**: `response_caching`
- **Observability**: `stdout_logging`, `http_logging`, `transaction_debugger`, `correlation_id`, `prometheus_metrics`, `otel_tracing`

**Plugin Lifecycle**:
1. **Request Phase**: Authentication → Authorization → Rate Limiting
2. **Response Phase**: Logging → Metrics
3. **Error Phase**: Error handling and logging

### **6. Admin API (`src/admin/`)**

RESTful API for dynamic configuration management:

**Endpoints**:
- `/proxies` - Proxy CRUD operations
- `/consumers` - Consumer management
- `/plugins` - Plugin configuration
- `/upstreams` - Upstream CRUD operations
- `/health` - Health check endpoint
- `/backup` and `/restore` - Configuration backup/restore
- JWT-based authentication and authorization

### **7. Operating Modes (`src/modes/`)**

Five operating modes for different deployment scenarios:

#### **Database Mode (`database.rs`)**
- Single gateway instance with database storage
- Periodic configuration polling with incremental updates
- Full admin API included
- **Use Case**: Small to medium deployments

#### **File Mode (`file.rs`)**
- Configuration from local YAML/JSON files
- SIGHUP-based reloading (Unix only)
- Read-only admin API
- **Use Case**: Development, immutable infrastructure

#### **Control Plane Mode (`control_plane.rs`)**
- Centralized configuration management
- Database integration with incremental polling
- gRPC configuration distribution to Data Planes
- No proxy traffic handling
- **Use Case**: Distributed deployments

#### **Data Plane Mode (`data_plane.rs`)**
- Proxy traffic only
- gRPC configuration from Control Plane
- Read-only admin API served from cached config
- **Use Case**: Scalable traffic processing

#### **Migrate Mode (`migrate.rs`)**
- Runs database schema migrations then exits
- **Use Case**: CI/CD deployment pipelines

### **7.1 Data Source Resiliency**

The gateway is designed to continue operating indefinitely when its data source becomes unavailable. Configuration is loaded into memory once and all request-path operations use the in-memory cache — no per-request database or file access.

#### **How It Works**

All modes store the active configuration in an `ArcSwap<GatewayConfig>` — a lock-free, atomically-swappable smart pointer. Every proxy request reads from this in-memory cache, never from the data source directly. Background tasks periodically attempt to refresh the config from the source, but failures only produce a log warning and never affect request handling.

#### **Failure Behavior by Mode**

| Mode | Data Source | On Source Failure |
|------|------------|-------------------|
| **File** | YAML/JSON file | Config loaded once at startup. File can be deleted/corrupted afterward with zero impact. SIGHUP reload gracefully falls back to previous config on parse errors. |
| **Database** | SQL database | Polling loop logs a warning and continues with cached config. Gateway serves traffic indefinitely with stale config until DB recovers. If `FERRUM_DB_FAILOVER_URLS` is configured, failover URLs are tried in order before marking the DB as unavailable. If `FERRUM_DB_READ_REPLICA_URL` is configured, polling reads are offloaded to the replica (falls back to primary if replica is unreachable). |
| **Control Plane** | SQL database | Polling loop logs a warning. Does not broadcast stale updates to Data Planes. DPs retain their last known config. Admin API reads fall back to the in-memory cached config. |
| **Data Plane** | Control Plane (gRPC) | Auto-reconnects to CP every 5 seconds. Continues serving traffic with cached config. Admin API reads served from cached config with `X-Data-Source: cached` header. |

#### **Admin API Resilience**

Admin API read endpoints (GET proxies, consumers, plugin configs) use a two-tier strategy:
1. **Primary**: Query the database for fresh data
2. **Fallback**: If the database is unavailable (or not configured, as in DP mode), serve from the in-memory cached config

Fallback responses include an `X-Data-Source: cached` header so callers can detect stale data. Write operations (POST/PUT/DELETE) require a live database and will return `503 Service Unavailable` if the database is offline — there is no way to safely write without a data store.

The `/health` endpoint reports `cached_config` status including availability, `loaded_at` timestamp, and proxy/consumer counts, providing operational visibility during outages.

### **8. DNS System (`src/dns/`)**

Async DNS resolution with caching designed to keep lookups off the hot request path:

**Key Features**:
- In-memory `DashMap` caching with configurable TTL
- **Startup warmup** — resolves all proxy backend, upstream target, and plugin endpoint hostnames (deduplicated) before accepting requests
- **Background refresh** — proactively re-resolves entries at 75% TTL before expiration
- **`DnsCacheResolver`** — custom `reqwest::dns::Resolve` implementation that routes all HTTP client DNS lookups (proxy backends, health checks, and plugin outbound calls) through the cache, keeping DNS off the hot request path
- Static DNS overrides (global and per-proxy)
- Per-proxy DNS configuration and TTL overrides
- Graceful degradation on resolution failures

### **9. Service Discovery (`src/service_discovery/`)**

Dynamic upstream target discovery from external registries:

- **DNS-SD** (`dns_sd.rs`) — SRV record-based discovery
- **Kubernetes** (`kubernetes.rs`) — Kubernetes API-based endpoint discovery
- **Consul** (`consul.rs`) — Consul service catalog discovery

Discovered targets are merged with static upstream targets and fed into the load balancer.

### **10. Secrets Management (`src/secrets/`)**

Pluggable secret resolution for configuration values:

- **Environment variables** (`env.rs`) — resolve secrets from environment
- **File** (`file.rs`) — resolve secrets from files on disk
- **AWS Secrets Manager** (`aws.rs`) — resolve secrets from AWS
- **Azure Key Vault** (`azure.rs`) — resolve secrets from Azure
- **GCP Secret Manager** (`gcp.rs`) — resolve secrets from GCP
- **HashiCorp Vault** (`vault.rs`) — resolve secrets from Vault

### **11. Circuit Breaker (`src/circuit_breaker.rs`)**

Three-state circuit breaker pattern (Closed/Open/Half-Open) to prevent cascading failures. Configurable failure and success thresholds, timeout for Open-to-Half-Open transitions, and max probe requests in Half-Open state.

### **12. Retry Logic (`src/retry.rs`)**

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
| Plugin lookup | O(1) HashMap | Lock-free ArcSwap | Returns `Arc<Vec<...>>` — zero Vec allocation per request; buffering flag pre-computed |
| Consumer auth | O(1) per credential type | Lock-free ArcSwap | Separate indexes per type (no format!() allocation) |
| Upstream lookup | O(1) HashMap | Lock-free ArcSwap | Pre-built index avoids linear scan |
| Load balancer | O(1) round-robin / O(log n) consistent hash | Lock-free ArcSwap | Pre-computed target keys avoid format!() per request |
| Circuit breaker | O(1) atomic loads | Lock-free DashMap | |
| Health check state | O(1) DashMap | Lock-free DashMap | |

### **Key Design Decisions for Scale**

- **ArcSwap everywhere**: Config updates are atomic pointer swaps. Readers never block, even during config reload with 10k+ resources.
- **Pre-computed indexes**: Plugin configs are indexed by `proxy_id` at build time (O(P+C) rebuild instead of O(P×C)). Consumer credentials are split into separate HashMaps per type. Load balancer target keys are pre-computed strings.
- **Zero per-request allocation in plugin lookup**: `PluginCache::get_plugins()` returns `Arc<Vec<Arc<dyn Plugin>>>` — a single Arc clone, not N Arc clones + Vec allocation. Response body buffering requirements and Alt-Svc headers are pre-computed at config load time to eliminate per-request `format!()` and `.any()` iterator overhead.
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

## Request Flow

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

## Configuration Hierarchy

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
export FERRUM_TLS_CA_BUNDLE_PATH="/path/to/ca-bundle.pem"
export FERRUM_BACKEND_TLS_CLIENT_CERT_PATH="/path/to/global-cert.pem"
export FERRUM_BACKEND_TLS_CLIENT_KEY_PATH="/path/to/global-key.pem"
```

## Testing Strategy

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
- `tests/performance/` directory contains wrk-based performance benchmarks
- `tests/performance/multi_protocol/` contains multi-protocol benchmark suite (HTTP/1.1, HTTP/2, HTTP/3, gRPC, TCP, UDP, WebSocket)
- Automated performance regression testing in CI
- Baseline comparison with `compare_baselines.py`

## Getting Started for New Developers

### **1. Development Setup**

```bash
# Clone and build
git clone https://github.com/QuickLaunchWeb/ferrum-edge.git
cd ferrum-edge
cargo build

# Run tests
cargo test --all-features

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
3. Add a priority constant in `src/plugins/mod.rs`
4. Override `supported_protocols()` to declare protocol support
5. Register in the plugin registry (`create_plugin()` match arm in `mod.rs`)
6. Add unit tests in `tests/unit/plugins/`
7. Update `FEATURES.md`, `README.md`, and `docs/plugin_execution_order.md`

#### **New Configuration Option**
1. Add field to appropriate struct in `src/config/types.rs` with `#[serde(default)]`
2. Add environment variable parsing in `src/config/env_config.rs`
3. If database-stored: update migration in `src/config/migrations/` and `db_loader.rs`
4. Update `openapi.yaml` if the Admin API exposes it
5. Add tests

#### **New Admin API Endpoint**
1. Add handler in `src/admin/mod.rs`
2. Register route in admin router
3. Add authentication/authorization as needed
4. Write integration tests

### **4. Code Style Guidelines**

- Follow Rust idioms and `rustfmt` formatting
- Use `tracing` for structured logging
- Write comprehensive tests for new features
- Update documentation for API changes
- Use `anyhow` for error handling
- Prefer async/await for I/O operations
- No `.unwrap()` or `.expect()` in production code

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

## Development Workflow

### **1. Feature Development**
1. Create feature branch from `main`
2. Implement changes with tests
3. Run full test suite
4. Update documentation
5. Submit pull request

### **2. Testing**
```bash
# Unit tests
cargo test --test unit_tests --all-features

# Integration tests
cargo test --test integration_tests --all-features

# Functional / E2E tests (requires binary build)
cargo build --bin ferrum-edge
cargo test --test functional_tests --all-features -- --ignored

# All tests
cargo test --all-features
```

### **3. Building**
```bash
# Development build
cargo build

# Release build
cargo build --release
```

## Additional Resources

- **`docs/`** - Feature-specific documentation (TLS, DNS, CORS, Docker, CI/CD, etc.)
- **`tests/README.md`** - Test suite documentation
- **`tests/performance/README.md`** - Performance testing guide
- **`comparison/README.md`** - API gateway comparison benchmarks
