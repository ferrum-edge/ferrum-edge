# Features — Ferrum Gateway

A comprehensive feature list for Ferrum Gateway.

## Protocol Support

- **HTTP/1.1** with keep-alive connection pooling
- **HTTP/2** via ALPN negotiation on TLS connections
- **HTTP/3** (QUIC) on the same port as HTTPS with configurable idle timeout, max streams, QUIC flow-control windows, and per-backend connection pooling
- **WebSocket** (`ws`/`wss`) with transparent upgrade handling
- **gRPC** (`grpc`/`grpcs`) with HTTP/2 trailer support and full plugin compatibility
- **TCP** stream proxying with TLS termination and origination
- **UDP** datagram proxying with DTLS support (frontend termination + backend origination)

## Operating Modes

- **Database** — single-instance with PostgreSQL, MySQL, or SQLite backend
- **File** — single-instance with YAML/JSON config, SIGHUP reload
- **Control Plane (CP)** — centralized config authority, gRPC distribution to DPs
- **Data Plane (DP)** — horizontally scalable traffic processing nodes

## Routing

- Longest prefix match on `listen_path` with unique path enforcement
- Host-based routing with exact and wildcard prefix support (`*.example.com`)
- Pre-sorted route table with bounded O(1) path cache, rebuilt atomically on config changes
- Configurable path stripping and backend path prefixing

## Load Balancing

- Five algorithms: round robin, weighted round robin, least connections, consistent hashing, random
- Active health checks (HTTP, TCP SYN, UDP probes) with configurable thresholds
- Passive health monitoring with automatic failover
- Circuit breaker (Closed/Open/Half-Open) preventing cascading failures
- Retry logic with fixed and exponential backoff strategies

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

## Plugin System

- 21 built-in plugins with lifecycle hooks (request received, authenticate, authorize, before proxy, after proxy, log)
- Priority-ordered execution with protocol-aware filtering (HTTP, gRPC, WebSocket, TCP, UDP)
- Global and per-proxy scoping with same-type override semantics
- Multi-authentication mode with first-match consumer identification

### Authentication Plugins

- **JWT** (HS256) — bearer token with configurable claim field
- **API Key** — header or query parameter lookup
- **Basic Auth** — bcrypt or HMAC-SHA256 password verification
- **HMAC** — request signature verification
- **OAuth2** — introspection and JWKS validation modes

### Authorization & Security Plugins

- **Access Control** — IP/CIDR and consumer-based allow/deny lists
- **IP Restriction** — standalone IP/CIDR filtering
- **Rate Limiting** — per-IP or per-consumer with configurable windows and optional header exposure
- **Bot Detection** — User-Agent pattern blocking with allow-list support
- **CORS** — preflight handling with origin, method, and header validation
- **Body Validator** — JSON Schema and XML validation
- **GraphQL** — query depth/complexity limiting, alias limiting, introspection control, per-operation rate limiting

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
- **OpenTelemetry Tracing** — OTLP integration

## Connection Pooling

- Lock-free connection reuse with per-proxy pool keys
- Global defaults with per-proxy overrides (max idle, idle timeout, keep-alive, HTTP/2)
- HTTP/2 multiplexing via ALPN negotiation
- TCP and HTTP/2 keep-alive with configurable intervals

## TLS & Security

- Frontend TLS termination on proxy and admin listeners
- Frontend mTLS with client certificate verification
- Backend mTLS with per-proxy certificate configuration
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
- Batch operations and full config backup/restore
- Zero-downtime config reload via DB polling, SIGHUP, or CP push
- Atomic config swap via ArcSwap (no partial config visible to requests)
- Incremental database polling with indexed `updated_at` queries

## Resilience

- In-memory config cache survives source outages (DB, file, gRPC)
- Startup failover with externally provisioned backup config (`FERRUM_DB_CONFIG_BACKUP_PATH`)
- Graceful shutdown with active request draining (SIGTERM/SIGINT)
- Client observability headers (`X-Gateway-Error`, `X-Gateway-Upstream-Status`)

## Secrets Management

**Any** environment variable can be loaded from an external secret source by setting a suffixed variant. Each variable supports exactly one source — if both the base variable and a suffixed variant are set, startup fails with a conflict error.

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

Uses KV v2 engine. The `_VAULT` reference format is `<mount>/data/<path>#<json_key>` (e.g. `secret/data/ferrum#admin_jwt`).

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

## Deployment

- Single binary, mode selected via environment variable
- Docker multi-stage build with health check endpoint
- Docker Compose profiles for SQLite, PostgreSQL, and CP/DP topologies
- CI pipeline: unit tests, functional tests, lint, performance regression
