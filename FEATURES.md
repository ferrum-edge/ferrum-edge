# Features — Ferrum Edge

A comprehensive feature list for Ferrum Edge.

## Protocol Support

- **HTTP/1.1** with keep-alive connection pooling
- **HTTP/2** via ALPN negotiation on TLS connections
- **HTTP/3** (QUIC) on the same port as HTTPS with streaming responses (backpressure-aware adaptive coalescing), configurable idle timeout, max streams, QUIC flow-control windows, and per-backend connection pooling
- **WebSocket** (`ws`/`wss`) with transparent upgrade handling (HTTP/1.1 Upgrade and HTTP/2 Extended CONNECT per RFC 8441)
- **gRPC** (`grpc`/`grpcs`) with HTTP/2 trailer support and full plugin compatibility
- **TCP** stream proxying with TLS termination, origination, passthrough, and configurable idle timeout
- **UDP** datagram proxying with DTLS support (frontend termination, backend origination, passthrough)
- **TLS/DTLS passthrough** — forward encrypted bytes without termination, with SNI extraction for logging

## Operating Modes

- **Database** — single-instance with PostgreSQL, MySQL, SQLite, or MongoDB backend
- **File** — single-instance with YAML/JSON config, SIGHUP reload (Unix only; restart required on other platforms)
- **Control Plane (CP)** — centralized config authority, gRPC distribution to DPs
- **Data Plane (DP)** — horizontally scalable traffic processing nodes

## Routing

- Longest prefix match on `listen_path` with unique path enforcement
- Host-based routing with exact and wildcard prefix support (`*.example.com`)
- Pre-sorted route table with bounded O(1) path cache, rebuilt atomically on config changes
- Configurable path stripping and backend path prefixing
- Per-proxy HTTP method filtering (`allowed_methods`) with 405 Method Not Allowed responses
- Per-proxy WebSocket Origin validation (`allowed_ws_origins`) for CSWSH protection (RFC 6455 §10.2)

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

- 52 built-in plugins with lifecycle hooks (request received, authenticate, authorize, before proxy, after proxy, on final request/response body, on response body, on WebSocket frame, on UDP datagram, log)
- Priority-ordered execution with protocol-aware filtering (HTTP, gRPC, WebSocket, TCP, UDP)
- Multiple instances of the same plugin type per proxy (e.g., two `http_logging` for Splunk and Datadog) with optional `priority_override` for execution order control
- Global and per-proxy scoping — proxy-scoped plugins replace global plugins of the same name
- Multi-authentication mode with first-match consumer identification
- Multi-credential rotation — consumers can have multiple active credentials of the same type (e.g., two API keys, two JWT secrets) for zero-downtime key rotation, configurable via `FERRUM_MAX_CREDENTIALS_PER_TYPE`
- Custom plugin database migrations — plugins declare migrations via `plugin_migrations()`, auto-discovered at build time, tracked separately in `_ferrum_plugin_migrations` with per-plugin version scoping. Supports cross-database SQL (PostgreSQL/MySQL/SQLite overrides). MongoDB uses idempotent index creation instead of SQL migrations

### Authentication Plugins

- **mTLS** — client certificate identity matching with per-proxy CA filtering
- **JWT** (HS256) — bearer token with configurable claim field
- **API Key** — header or query parameter lookup
- **Basic Auth** — bcrypt or HMAC-SHA256 password verification
- **HMAC** — request signature verification
- **JWKS Auth** — multi-provider JWKS JWT validation with claim-based authorization
- **LDAP Auth** — LDAP directory authentication via direct bind or search-then-bind with optional AD group filtering
- **SOAP WS-Security** — WS-Security header validation with UsernameToken (PasswordText/PasswordDigest), X.509 signature verification, SAML assertion validation, timestamp freshness, and nonce replay protection

### Authorization & Security Plugins

- **Access Control** — consumer-based and group-based allow/deny lists (consumers declare `acl_groups` membership; plugins match via `allowed_groups` / `disallowed_groups`)
- **IP Restriction** — standalone IP/CIDR filtering
- **TCP Connection Throttle** — caps active TCP connections per Consumer or client IP
- **Rate Limiting** — per-IP or per-consumer with configurable windows and optional header exposure; supports centralized Redis-backed mode (`sync_mode: "redis"`) for coordinated rate limiting across multiple data plane instances. Compatible with any RESP-protocol server (Redis, Valkey, DragonflyDB, KeyDB, Garnet). TLS uses gateway-level `FERRUM_TLS_CA_BUNDLE_PATH` and `FERRUM_TLS_NO_VERIFY`
- **Request Size Limiting** — per-proxy request body size limits (lower than global default), Content-Length fast path + buffered body check
- **Response Size Limiting** — per-proxy response body size limits (lower than global default), Content-Length fast path + optional buffered body check
- **Bot Detection** — User-Agent pattern blocking with allow-list support
- **CORS** — preflight handling with origin, method, and header validation
- **Body Validator** — JSON Schema, XML, and gRPC protobuf validation
- **GraphQL** — query depth/complexity limiting, alias limiting, introspection control, per-operation rate limiting
- **gRPC-Web** — bidirectional protocol translation between gRPC-Web (browser) and native gRPC (HTTP/2), supporting binary and base64 text encoding modes with trailer frame embedding
- **gRPC Method Router** — per-method access control (allow/deny lists) and per-method rate limiting with metadata enrichment
- **gRPC Deadline** — `grpc-timeout` enforcement, default injection, max capping, and gateway processing time subtraction

### AI / LLM Plugins

- **AI Federation** — universal AI gateway that routes requests to any of 11 supported providers (OpenAI, Anthropic, Google Gemini/Vertex, Azure OpenAI, AWS Bedrock, Mistral, Cohere, xAI, DeepSeek, Meta Llama, Hugging Face). Clients send OpenAI Chat Completions format; the plugin translates to native provider format, handles authentication (API key, OAuth2, AWS SigV4), and normalizes responses back to OpenAI format. Supports model-based routing with glob patterns, provider-level model mapping, priority-ordered fallback on configurable status codes and network errors, per-provider connect/read timeouts, and custom base URLs for self-hosted endpoints. Writes token metadata for downstream rate limiting and logging
- **AI Token Metrics** — extract token usage (prompt, completion, total) from LLM responses (OpenAI, Anthropic, Google, Cohere, Mistral, Bedrock) into transaction metadata for downstream observability
- **AI Request Guard** — validate and constrain AI requests: model allow/block lists, max_tokens enforcement (reject or clamp), message count limits, prompt length limits, temperature range, system prompt blocking
- **AI Rate Limiter** — token-aware rate limiting per consumer or IP with sliding window, auto-detecting provider format from responses; supports centralized Redis-backed mode for cross-instance token budget coordination. Compatible with any RESP-protocol server (Redis, Valkey, DragonflyDB, KeyDB, Garnet). TLS uses gateway-level settings
- **AI Prompt Shield** — PII detection and redaction in prompts with built-in patterns (SSN, credit card, email, phone, API keys, AWS keys, IBAN) and custom regex support

### WebSocket Plugins

- **WebSocket Message Size Limiting** — enforces maximum frame sizes on WebSocket connections, closing with code 1009 (Message Too Big) on violation
- **WebSocket Rate Limiting** — per-connection frame rate limiting using token bucket algorithm, closing with code 1008 (Policy Violation) on excess; supports centralized Redis-backed mode for cross-instance frame rate coordination. Compatible with any RESP-protocol server (Redis, Valkey, DragonflyDB, KeyDB, Garnet). TLS uses gateway-level settings
- **WebSocket Frame Logging** — logs frame metadata (direction, type, size, connection ID) without transforming frames

### UDP Plugins

- **UDP Rate Limiting** — per-client-IP datagram and byte rate limiting for UDP proxies; supports centralized Redis-backed mode. Compatible with any RESP-protocol server (Redis, Valkey, DragonflyDB, KeyDB, Garnet)

### Serverless Function Plugin

- **Serverless Function** — invoke AWS Lambda, Azure Functions, or Google Cloud Functions as middleware. Pre-proxy mode enriches requests with function-computed headers; terminate mode returns function responses directly. Supports SigV4 signing for AWS, function key auth for Azure, and bearer token auth for GCP. Cloud credentials fall back to standard environment variables (`AWS_ACCESS_KEY_ID`, `AZURE_FUNCTIONS_KEY`, etc.) when not set in plugin config.

### Response Mock Plugin

- **Response Mock** — returns configurable mock responses without proxying to the backend. Mock rule paths are relative to the proxy's `listen_path`, so rules are scoped to the proxy they're configured on. Supports matching by HTTP method and path pattern (exact or regex with `~` prefix), configurable status codes, headers, body, and optional latency simulation via `delay_ms`. When `passthrough_on_no_match` is true, unmatched requests continue to the real backend. Useful for early API testing, contract testing, and local development

### Spec Expose Plugin

- **Spec Expose** — exposes API specification documents (OpenAPI, Swagger, WSDL, WADL) on a `/specz` sub-path of each proxy's listen path. Fetches the spec from a configured upstream URL and returns it to the caller with the upstream's `Content-Type` preserved. The `/specz` endpoint is unauthenticated — the plugin short-circuits before authentication runs, so consumers can discover API contracts without credentials. Supports per-plugin TLS verification skip for internal endpoints with self-signed certificates. Only works with prefix-based `listen_path` proxies. Inspired by [kong-spec-expose](https://github.com/Optum/kong-spec-expose)

### SSE Plugin

- **SSE** — Server-Sent Events stream handler. Validates inbound SSE client criteria (GET method, `Accept: text/event-stream`), shapes requests for backends (strips `Accept-Encoding`, forwards `Last-Event-ID`), and ensures proper streaming response headers (`Cache-Control: no-cache`, `Connection: keep-alive`, `X-Accel-Buffering: no`). Optionally forces `text/event-stream` content type and wraps non-SSE responses into SSE event framing

### Transform Plugins

- **Request Transformer** — add, remove, or update headers and query parameters
- **Response Transformer** — modify response headers
- **Compression** — on-the-fly response compression (gzip, brotli) with Accept-Encoding negotiation, content-type filtering, minimum body size threshold, and optional request decompression with zip bomb protection
- **Response Caching** — cache backend responses with TTL, cache key rules, and conditional caching
- **Request Termination** — return static responses without proxying

### Observability Plugins

- **Stdout Logging** — JSON transaction summaries
- **HTTP Logging** — batched delivery to external endpoints with retry and custom headers (Datadog, Splunk, New Relic, Sumo Logic, Axiom, Logtail, Elastic, Azure Monitor, and more)
- **Loki Logging** — batched delivery to Grafana Loki with label-based stream grouping, gzip compression, and multi-tenant support
- **UDP Logging** — batched delivery to external UDP/DTLS endpoints with optional DTLS encryption and client certificate support
- **Transaction Debugger** — verbose request/response diagnostics via `tracing::debug` with header redaction (development only)
- **Correlation ID** — UUID generation and propagation
- **Prometheus Metrics** — exposition format endpoint
- **OpenTelemetry Tracing** — W3C Trace Context propagation + OTLP/HTTP span export with batching, custom headers, rich semantic attributes, and propagation-only mode

## Connection Pooling

- Lock-free connection reuse with per-proxy pool keys (thread-local key buffers for zero-allocation cache hits)
- **Arc-wrapped upstream targets** — load balancer selections are cheap pointer bumps, not struct clones
- Global defaults with per-proxy overrides (max idle, idle timeout, keep-alive, HTTP/2)
- HTTP/2 multiplexing via ALPN negotiation
- TCP and HTTP/2 keep-alive with configurable intervals
- **Startup pool warmup** — pre-establishes backend connections (reqwest, gRPC, HTTP/2, HTTP/3) after DNS warmup to eliminate first-request cold-start latency (configurable via `FERRUM_POOL_WARMUP_ENABLED`)

## Adaptive Buffer Sizing

- **Per-proxy adaptive copy buffers** — tracks bytes transferred per connection (EWMA) and selects optimal `copy_bidirectional` buffer sizes for TCP proxy and WebSocket tunnel connections. Small-message protocols get 8 KiB buffers (saves memory at scale), bulk transfers get 256 KiB buffers (reduces syscall overhead). Inspired by Envoy's watermark-based memory class bucketing.
- **Per-proxy adaptive UDP batch limits** — tracks datagrams per recv wakeup cycle (EWMA) and selects per-proxy batch drain limits. Quiet proxies yield faster to the event loop (64 dgrams), burst proxies drain more per cycle (6000 dgrams).
- Four buffer size tiers (8 KiB, 32 KiB, 64 KiB, 256 KiB) and four batch limit tiers (64, 256, 2000, 6000)
- Lock-free hot path: DashMap read + AtomicU64 load + three comparisons per lookup
- Configurable EWMA alpha, min/max buffer bounds, and defaults via `FERRUM_ADAPTIVE_BUFFER_*` env vars
- Enabled by default; disable with `FERRUM_ADAPTIVE_BUFFER_ENABLED=false` / `FERRUM_ADAPTIVE_BATCH_LIMIT_ENABLED=false`

## High-Concurrency & Runtime Tuning

- **jemalloc** memory allocator (Linux/macOS) for reduced fragmentation at scale
- **Multi-listener SO_REUSEPORT** — N parallel accept loops per proxy port (auto-detects CPU cores via `FERRUM_ACCEPT_THREADS`), giving the kernel separate accept queues to eliminate single-socket lock bottleneck at high connection rates
- Configurable TCP listen backlog (default 2048) for burst absorption
- Connection limit semaphore (default 100k) with graceful queuing under overload
- Server-side HTTP/2 `max_concurrent_streams` (default 1000) to bound per-connection resource usage
- Configurable tokio worker and blocking thread counts with auto-detection

## TLS & Security

- Plaintext listener disable — set port to `0` to prevent HTTP proxy, admin HTTP, or gRPC listeners from binding (TLS-only operation)
- Frontend TLS termination on proxy and admin listeners
- Frontend mTLS with client certificate verification
- Backend mTLS with per-proxy certificate configuration
- CP/DP gRPC channel TLS and mTLS (one-way TLS or mutual certificate verification)
- DTLS 1.2/1.3 frontend termination and backend origination (ECDSA P-256/P-384)
- Configurable cipher suites, key exchange groups, and protocol versions
- Database TLS/SSL with PostgreSQL, MySQL, and MongoDB support (mTLS client cert auth for all three)
- Protocol-level request validation (anti-smuggling, desync prevention):
  - HTTP/1.x: Content-Length + Transfer-Encoding conflict rejection
  - All versions: Multiple Content-Length with mismatched values rejection
  - HTTP/1.0: Transfer-Encoding rejection (RFC 9112 §6.2 — no chunked in 1.0)
  - All versions: Content-Length non-numeric value rejection (RFC 9110 §8.6)
  - HTTP/1.x: Multiple Host header rejection
  - HTTP/2: TE header restricted to "trailers" only
  - All versions: TRACE method blocked (anti-XST)
  - gRPC: POST method enforcement
  - WebSocket: Sec-WebSocket-Key format validation (base64 16-byte nonce)
  - WebSocket: Per-proxy Origin validation (`allowed_ws_origins`) for CSWSH protection
- Admin API security headers (X-Content-Type-Options, Cache-Control, X-Frame-Options)
- HTTP/1.1 header read timeout for slowloris protection (`FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS`)
- Hop-by-hop header stripping per RFC 9110 §7.6.1 (including Proxy-Authenticate)
- Backend IP allowlist policy (`FERRUM_BACKEND_ALLOW_IPS`) for SSRF protection with three-layer enforcement (config-time, DNS-resolution-time, connection-time)
- UDP response amplification protection (`udp_max_response_amplification_factor` per-proxy) with symmetric `on_udp_datagram` plugin hooks (client→backend and backend→client)
- Per-IP concurrent request limiting (`FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP`) with RAII Drop guard for leak-free tracking across 30+ return paths
- Admin API IP allowlist (`FERRUM_ADMIN_ALLOWED_CIDRS`) — TCP-level rejection before TLS handshake or request processing
- Opt-in Via header (RFC 9110 §7.6.3) on request and response paths (`FERRUM_ADD_VIA_HEADER`)
- Opt-in Forwarded header (RFC 7239) alongside X-Forwarded-* (`FERRUM_ADD_FORWARDED_HEADER`)
- Certificate Revocation List (CRL) checking across all TLS/DTLS surfaces (`FERRUM_TLS_CRL_FILE_PATH`)

## DNS Caching

- In-memory async cache with startup warmup (backends, upstreams, plugin endpoints)
- Background refresh at 75% TTL with stale-while-revalidate
- Per-proxy TTL overrides and static hostname overrides
- Shared resolver for all outbound HTTP clients including plugins

## CLI

- Four subcommands: `run` (foreground gateway), `validate` (config check), `reload` (SIGHUP), `version`
- Smart path defaults — `ferrum-edge run` works zero-config when `./ferrum.conf` and `./resources.yaml` exist
- Mode inference — `--spec` auto-sets file mode when no mode is configured
- Full backwards compatibility — no-args invocation uses legacy env-var-only startup
- Configuration precedence: CLI flag > env var > conf file > smart defaults > hardcoded defaults
- See [docs/cli.md](docs/cli.md) for the full reference

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
- Multi-URL database failover (`FERRUM_DB_FAILOVER_URLS`) with automatic ordered connection failover. MongoDB replica sets handle failover natively via the connection string
- Read replica support — SQL: `FERRUM_DB_READ_REPLICA_URL` offloads config polling reads. MongoDB: `readPreference=secondaryPreferred` in connection string (driver routes reads to secondaries automatically)
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

## Deployment

- Single binary, mode selected via environment variable
- Docker multi-stage build with distroless runtime (zero OS-level CVEs, ~30MB image)
- Docker Compose profiles for SQLite, PostgreSQL, and CP/DP topologies
- CI pipeline: unit tests, functional tests, lint, performance regression
