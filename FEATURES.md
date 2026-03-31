# Features — Ferrum Edge

A comprehensive feature list for Ferrum Edge.

## Protocol Support

- **HTTP/1.1** with keep-alive connection pooling
- **HTTP/2** via ALPN negotiation on TLS connections
- **HTTP/3** (QUIC) on the same port as HTTPS with streaming responses (backpressure-aware adaptive coalescing), configurable idle timeout, max streams, QUIC flow-control windows, and per-backend connection pooling
- **WebSocket** (`ws`/`wss`) with transparent upgrade handling
- **gRPC** (`grpc`/`grpcs`) with HTTP/2 trailer support and full plugin compatibility
- **TCP** stream proxying with TLS termination, origination, and configurable idle timeout
- **UDP** datagram proxying with DTLS support (frontend termination + backend origination)

## Operating Modes

- **Database** — single-instance with PostgreSQL, MySQL, or SQLite backend
- **File** — single-instance with YAML/JSON config, SIGHUP reload (Unix only; restart required on other platforms)
- **Control Plane (CP)** — centralized config authority, gRPC distribution to DPs
- **Data Plane (DP)** — horizontally scalable traffic processing nodes

## Routing

- Longest prefix match on `listen_path` with unique path enforcement
- Host-based routing with exact and wildcard prefix support (`*.example.com`)
- Pre-sorted route table with bounded O(1) path cache, rebuilt atomically on config changes
- Configurable path stripping and backend path prefixing
- Per-proxy HTTP method filtering (`allowed_methods`) with 405 Method Not Allowed responses

## Load Balancing

- Six algorithms: round robin, weighted round robin, least connections, least latency, consistent hashing (IP/header/cookie sticky sessions), random
- Active health checks (HTTP, TCP SYN, UDP probes) with configurable thresholds
- Passive health monitoring with automatic failover
- Circuit breaker (Closed/Open/Half-Open) preventing cascading failures
- Retry logic with fixed and exponential backoff strategies for HTTP/1.1, HTTP/2, HTTP/3, gRPC, and WebSocket — see [docs/retry.md](docs/retry.md)

## Service Discovery

Ferrum supports dynamic upstream target discovery through three providers, configured via the `service_discovery` block on an upstream.

### Providers

- **DNS-SD** — discovers targets via DNS SRV record lookups. Suitable for environments using mDNS or service-aware DNS infrastructure. Configurable service name and poll interval.
- **Kubernetes** — queries the Kubernetes API for endpoint addresses backing a named Service. Supports namespace scoping and named port selection. Requires in-cluster credentials or a configured kubeconfig.
- **Consul** — queries a Consul agent or server for healthy service instances. Supports datacenter selection and ACL token authentication.

### Behavior

- **Background polling** — each provider polls on a configurable interval (`poll_interval_seconds`), updating the upstream's target list without blocking request traffic.
- **Static + dynamic target merging** — statically defined `targets` on an upstream are preserved and merged with dynamically discovered targets. This allows fallback entries that are always present.
- **Resilience** — if a provider becomes unreachable (DNS timeout, Kubernetes API error, Consul agent down), the upstream retains its last-known target list and continues routing normally. A warning is logged on each failed poll. Normal updates resume automatically when the provider recovers.
- **Per-target path override** — each upstream target may specify an optional `path` field that overrides the proxy's `backend_path` when that target is selected by the load balancer, enabling different backend path prefixes per target.

## Plugin System

- 33 built-in plugins with lifecycle hooks (request received, authenticate, authorize, before proxy, after proxy, on response body, on WebSocket frame, log)
- Priority-ordered execution with protocol-aware filtering (HTTP, gRPC, WebSocket, TCP, UDP)
- Global and per-proxy scoping with same-type override semantics
- Multi-authentication mode with first-match consumer identification

### Authentication Plugins

- **mTLS** — client certificate identity matching with per-proxy CA filtering
- **JWT** (HS256) — bearer token with configurable claim field
- **API Key** — header or query parameter lookup
- **Basic Auth** — bcrypt or HMAC-SHA256 password verification
- **HMAC** — request signature verification
- **JWKS Auth** — multi-provider JWKS JWT validation with claim-based authorization

### Authorization & Security Plugins

- **Access Control** — IP/CIDR and consumer-based allow/deny lists
- **IP Restriction** — standalone IP/CIDR filtering
- **Rate Limiting** — per-IP or per-consumer with configurable windows and optional header exposure; supports centralized Redis-backed mode (`sync_mode: "redis"`) for coordinated rate limiting across multiple data plane instances. Compatible with any RESP-protocol server (Redis, Valkey, DragonflyDB, KeyDB, Garnet). TLS uses gateway-level `FERRUM_TLS_CA_BUNDLE_PATH` and `FERRUM_TLS_NO_VERIFY`
- **Request Size Limiting** — per-proxy request body size limits (lower than global default), Content-Length fast path + buffered body check
- **Response Size Limiting** — per-proxy response body size limits (lower than global default), Content-Length fast path + optional buffered body check
- **Bot Detection** — User-Agent pattern blocking with allow-list support
- **CORS** — preflight handling with origin, method, and header validation
- **Body Validator** — JSON Schema and XML validation
- **GraphQL** — query depth/complexity limiting, alias limiting, introspection control, per-operation rate limiting
- **gRPC Method Router** — per-method access control (allow/deny lists) and per-method rate limiting with metadata enrichment
- **gRPC Deadline** — `grpc-timeout` enforcement, default injection, max capping, and gateway processing time subtraction

### AI / LLM Plugins

- **AI Token Metrics** — extract token usage (prompt, completion, total) from LLM responses (OpenAI, Anthropic, Google, Cohere, Mistral, Bedrock) into transaction metadata for downstream observability
- **AI Request Guard** — validate and constrain AI requests: model allow/block lists, max_tokens enforcement (reject or clamp), message count limits, prompt length limits, temperature range, system prompt blocking
- **AI Rate Limiter** — token-aware rate limiting per consumer or IP with sliding window, auto-detecting provider format from responses; supports centralized Redis-backed mode for cross-instance token budget coordination. Compatible with any RESP-protocol server (Redis, Valkey, DragonflyDB, KeyDB, Garnet). TLS uses gateway-level settings
- **AI Prompt Shield** — PII detection and redaction in prompts with built-in patterns (SSN, credit card, email, phone, API keys, AWS keys, IBAN) and custom regex support

### WebSocket Plugins

- **WebSocket Message Size Limiting** — enforces maximum frame sizes on WebSocket connections, closing with code 1009 (Message Too Big) on violation
- **WebSocket Rate Limiting** — per-connection frame rate limiting using token bucket algorithm, closing with code 1008 (Policy Violation) on excess; supports centralized Redis-backed mode for cross-instance frame rate coordination. Compatible with any RESP-protocol server (Redis, Valkey, DragonflyDB, KeyDB, Garnet). TLS uses gateway-level settings
- **WebSocket Frame Logging** — logs frame metadata (direction, type, size, connection ID) without transforming frames

### Transform Plugins

- **Request Transformer** — add, remove, or update headers and query parameters
- **Response Transformer** — modify response headers
- **Request Termination** — return static responses without proxying

### Observability Plugins

- **Stdout Logging** — JSON transaction summaries
- **HTTP Logging** — batched delivery to external endpoints with retry
- **Transaction Debugger** — verbose request/response logging with header redaction
- **Correlation ID** — UUID generation and propagation
- **Prometheus Metrics** — exposition format endpoint
- **OpenTelemetry Tracing** — W3C Trace Context propagation + OTLP/HTTP span export with batching, custom headers, rich semantic attributes, and propagation-only mode

## Connection Pooling

- Lock-free connection reuse with per-proxy pool keys
- Global defaults with per-proxy overrides (max idle, idle timeout, keep-alive, HTTP/2)
- HTTP/2 multiplexing via ALPN negotiation
- TCP and HTTP/2 keep-alive with configurable intervals

## High-Concurrency & Runtime Tuning

- **jemalloc** memory allocator (Linux/macOS) for reduced fragmentation at scale
- **SO_REUSEPORT** for kernel-level connection distribution across CPU cores
- Configurable TCP listen backlog (default 2048) for burst absorption
- Connection limit semaphore (default 100k) with graceful queuing under overload
- Server-side HTTP/2 `max_concurrent_streams` (default 1000) to bound per-connection resource usage
- Configurable tokio worker and blocking thread counts with auto-detection

## TLS & Security

- Frontend TLS termination on proxy and admin listeners
- Frontend mTLS with client certificate verification
- Backend mTLS with per-proxy certificate configuration
- CP/DP gRPC channel TLS and mTLS (one-way TLS or mutual certificate verification)
- DTLS frontend termination and backend origination (ECDSA P-256 / Ed25519)
- Configurable cipher suites, key exchange groups, and protocol versions
- Database TLS/SSL with PostgreSQL and MySQL support

## DNS Caching

- In-memory async cache with startup warmup (backends, upstreams, plugin endpoints)
- Background refresh at 75% TTL with stale-while-revalidate
- Per-proxy TTL overrides and static hostname overrides
- Shared resolver for all outbound HTTP clients including plugins

## Configuration & Admin

- Admin REST API with JWT authentication and read-only mode
- Full CRUD for proxies, consumers, plugin configs, and upstreams
- Credential type whitelist enforcement on consumer credential endpoints
- Config version validation on restore endpoint
- Database error masking in API responses (internal details logged, not exposed)
- Batch operations and full config backup/restore
- Zero-downtime config reload via DB polling, SIGHUP, or CP push
- Atomic config swap via ArcSwap (no partial config visible to requests)
- Incremental database polling with indexed `updated_at` queries and full config validation

## Resilience

- In-memory config cache survives source outages (DB, file, gRPC)
- Startup failover with externally provisioned backup config (`FERRUM_DB_CONFIG_BACKUP_PATH`)
- Multi-URL database failover (`FERRUM_DB_FAILOVER_URLS`) with automatic ordered connection failover
- Read replica support (`FERRUM_DB_READ_REPLICA_URL`) for offloading config polling reads from the primary database
- Graceful shutdown with active request draining (SIGTERM/SIGINT)
- Client observability headers (`X-Gateway-Error`, `X-Gateway-Upstream-Status`)

## Secrets Management

Any `FERRUM_*` environment variable can be loaded from an external secret source by setting a suffixed variant. Only variables with the `FERRUM_` prefix are scanned — non-Ferrum env vars are never modified. Each variable supports exactly one source — if both the base variable and a suffixed variant are set, startup fails with a conflict error. After resolution, the suffixed source variables (e.g. `FERRUM_X_FILE`) are removed from the environment to avoid leaking reference paths to child processes.

**Always available (no extra dependencies):**
- **Environment variable** — `FERRUM_X=value` (direct value)
- **File** — `FERRUM_X_FILE=/run/secrets/x` (Docker secrets, K8s volume mounts, Vault Agent file injection)

**Optional backends (Cargo feature flags, zero impact on default binary size):**
- **HashiCorp Vault** — `FERRUM_X_VAULT=secret/data/gw#key` (feature: `secrets-vault`)
- **AWS Secrets Manager** — `FERRUM_X_AWS=arn:aws:secretsmanager:...` (feature: `secrets-aws`)
- **GCP Secret Manager** — `FERRUM_X_GCP=projects/P/secrets/S/versions/V` (feature: `secrets-gcp`)
- **Azure Key Vault** — `FERRUM_X_AZURE=https://vault.vault.azure.net/secrets/name` (feature: `secrets-azure`)

Works for all config keys — JWT secrets, DB URLs, TLS cert paths, port numbers, or any other `FERRUM_*` variable.

### Backend Authentication

Each cloud backend uses its SDK's standard credential chain. The required environment variables (or equivalent credentials) must be configured **before** the gateway starts.

**File** — no additional auth required. The gateway process must have filesystem read access to the referenced path.

**HashiCorp Vault** (`secrets-vault`):

| Variable | Required | Description |
|----------|----------|-------------|
| `VAULT_ADDR` | Yes | Vault server URL (e.g. `https://vault.example.com:8200`) |
| `VAULT_TOKEN` | Yes | Authentication token with read access to the referenced secret paths |

Uses KV v2 engine. The `_VAULT` reference format is `<mount>/data/<path>#<json_key>` (e.g. `secret/data/ferrum#admin_jwt`). The `#<json_key>` suffix is required if the Vault secret contains multiple keys; if omitted, the secret must contain exactly one key or startup fails with an error.

**AWS Secrets Manager** (`secrets-aws`):

Uses the standard AWS credential chain resolved by `aws-config`. Any of the following approaches work:

| Variable | Description |
|----------|-------------|
| `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` | Static IAM credentials |
| `AWS_SESSION_TOKEN` | (Optional) Session token for temporary credentials |
| `AWS_PROFILE` | Named profile from `~/.aws/credentials` |
| `AWS_REGION` or `AWS_DEFAULT_REGION` | Region where the secret is stored |
| *(none)* | EC2 instance profile, ECS task role, or EKS IRSA are used automatically |

The IAM principal must have `secretsmanager:GetSecretValue` permission on the referenced secret. The `_AWS` reference format is `<secret-name-or-arn>[#<json_key>]`.

**GCP Secret Manager** (`secrets-gcp`):

Uses Application Default Credentials (ADC). Any of the following approaches work:

| Variable | Description |
|----------|-------------|
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to a service account JSON key file |
| *(none)* | GCE metadata service (Compute Engine, GKE, Cloud Run) is used automatically |
| *(none)* | `gcloud auth application-default login` for local development |

The service account or principal must have the `secretmanager.versions.access` IAM permission on the referenced secret. The `_GCP` reference format is `projects/<project>/secrets/<secret>/versions/<version>`.

**Azure Key Vault** (`secrets-azure`):

Uses service principal authentication via `ClientSecretCredential`.

| Variable | Required | Description |
|----------|----------|-------------|
| `AZURE_TENANT_ID` | Yes | Azure AD tenant (directory) ID |
| `AZURE_CLIENT_ID` | Yes | Application (client) ID of the service principal |
| `AZURE_CLIENT_SECRET` | Yes | Client secret for the service principal |

The service principal must have the **Key Vault Secrets User** role (or equivalent `get` secret permission) on the referenced vault. The `_AZURE` reference format is `https://<vault-name>.vault.azure.net/secrets/<secret-name>`.

### Usage Examples

**File (Docker secrets / K8s volume mounts):**

```bash
# Read the JWT secret from a Docker secret or K8s mounted file
export FERRUM_ADMIN_JWT_SECRET_FILE=/run/secrets/jwt_secret

# Read the database URL from a file
export FERRUM_DB_URL_FILE=/run/secrets/db_url
```

**HashiCorp Vault:**

```bash
# Vault connection
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_TOKEN=hvs.EXAMPLE_TOKEN

# Read the JWT secret from Vault KV v2 (mount "secret", path "ferrum", key "admin_jwt")
export FERRUM_ADMIN_JWT_SECRET_VAULT=secret/data/ferrum#admin_jwt

# Read the database URL from Vault
export FERRUM_DB_URL_VAULT=secret/data/ferrum#db_url

# Build with Vault support
cargo build --release --features secrets-vault
```

**AWS Secrets Manager:**

```bash
# AWS credentials (or use instance profile / ECS task role / IRSA)
export AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...

# Read a plain-text secret by name
export FERRUM_ADMIN_JWT_SECRET_AWS=ferrum/jwt-secret

# Read a specific key from a JSON secret
export FERRUM_DB_URL_AWS=ferrum/database#connection_string

# Read by ARN
export FERRUM_DB_URL_AWS=arn:aws:secretsmanager:us-east-1:123456789012:secret:ferrum/database#connection_string

# Build with AWS support
cargo build --release --features secrets-aws
```

**GCP Secret Manager:**

```bash
# GCP credentials (or use GCE metadata / Workload Identity)
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

# Read a secret (always specify the full resource name with version)
export FERRUM_ADMIN_JWT_SECRET_GCP=projects/my-project/secrets/ferrum-jwt/versions/latest
export FERRUM_DB_URL_GCP=projects/my-project/secrets/ferrum-db-url/versions/1

# Build with GCP support
cargo build --release --features secrets-gcp
```

**Azure Key Vault:**

```bash
# Azure service principal credentials
export AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export AZURE_CLIENT_SECRET=...

# Read secrets by vault URL
export FERRUM_ADMIN_JWT_SECRET_AZURE=https://my-vault.vault.azure.net/secrets/ferrum-jwt
export FERRUM_DB_URL_AZURE=https://my-vault.vault.azure.net/secrets/ferrum-db-url

# Build with Azure support
cargo build --release --features secrets-azure
```

**Multiple features can be enabled together:**

```bash
cargo build --release --features secrets-vault,secrets-aws
```

### TLS and Trust

**Cloud backends (AWS, GCP, Azure)** use **rustls** (pure-Rust TLS) with the compile-time Mozilla CA bundle (`webpki-roots`) and the OS certificate store (`rustls-native-certs`). No OpenSSL or system-specific TLS libraries are required. These SDKs connect to public cloud API endpoints whose certificates are already trusted by the Mozilla CA bundle — no additional TLS configuration is needed.

**HashiCorp Vault** also uses rustls, but since Vault is often deployed on-premises with a private CA, the gateway respects `FERRUM_TLS_CA_BUNDLE_PATH`. If this variable points to a PEM-encoded CA bundle, the Vault client will trust certificates signed by those CAs in addition to the default trust store. This is the same CA bundle variable used by the gateway's backend proxy connections.

### Timeouts and Resilience

Each individual cloud backend fetch (Vault, AWS, GCP, Azure) has a **30-second timeout**. If a secret provider is unreachable or slow, the gateway fails startup with a clear timeout error rather than hanging indefinitely. File-based secrets have no timeout since they are local filesystem reads.

## Known Protocol Gaps

The following are known limitations tracked for future improvement:

| Gap | Protocol | Reason | Workaround |
|-----|----------|--------|------------|
| No HTTP/2 WebSocket (RFC 8441) | WebSocket | hyper's server does not implement the Extended CONNECT method (RFC 8441) for HTTP/2 WebSocket upgrades. Client-side support exists in hyper 1.x but server-side requires low-level h2 crate work to handle `:protocol = "websocket"` pseudo-headers and `SETTINGS_ENABLE_CONNECT_PROTOCOL`. Axum added server-side support in 0.8.0 but Ferrum Edge uses hyper directly. | Clients must use HTTP/1.1 Upgrade or TLS-negotiated connections for WebSocket |
| No DTLS 1.3 | UDP | DTLS 1.3 (RFC 9147, published April 2022) has no production-ready Rust implementation. The `webrtc-dtls` crate only supports DTLS 1.2 (RFC 6347). `rusty-dtls` exists but is early-stage (PSK-only handshakes). FFI to OpenSSL 3.2+ or WolfSSL would break the pure-Rust design. QUIC (already supported via quinn) provides TLS 1.3 over UDP but is not a transparent DTLS replacement. | Use TLS 1.3 over TCP, or use QUIC-based proxying for modern UDP security |

## Deployment

- Single binary, mode selected via environment variable
- Docker multi-stage build with health check endpoint
- Docker Compose profiles for SQLite, PostgreSQL, and CP/DP topologies
- CI pipeline: unit tests, functional tests, lint, performance regression
